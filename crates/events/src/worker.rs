//! Scan scheduling, bounded outbox insertion and webhook delivery workers.
use crate::{EVENT, Events, audit, date, webhook};
use mail_bridge_core::{Error, Result, safe};
use mail_bridge_store::{events::PendingEvent, hash, now};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

impl Events {
    pub async fn scan_once(&self, id: &str) -> Result<()> {
        let Some(sub) = self.get(id)? else {
            return Ok(());
        };
        if sub.expires <= now()
            || !self.auth.event_grant_active(&sub.owner)?
            || !self.source.available(&sub.filters.account_id)?
        {
            self.remove(id)?;
            return Ok(());
        }
        if sub.paused {
            return Ok(());
        }
        let scan = tokio::time::timeout(
            Duration::from_secs(20),
            self.source.scan(&sub.filters, sub.validity, sub.uid),
        )
        .await
        .map_err(|_| Error("Event upstream timeout"))??;
        let mut messages = scan.messages;
        messages.retain(|message| message.uid > sub.uid);
        messages.sort_unstable_by_key(|message| message.uid);
        messages.dedup_by_key(|message| message.uid);
        let messages = messages.into_iter().map(|message| {
            let uid = message.uid;
            let stable = hash(serde_json::to_vec(&json!([sub.filters, scan.validity, uid])).map_err(safe)?);
            let event = format!("evt_{stable}");
            let body = serde_json::to_vec(&json!({"eventId":event,"name":EVENT,"timestamp":date(now()),"data":{"account_id":sub.filters.account_id,"mailbox":sub.filters.mailbox,"message_id":format!("imap_{stable}"),"uidvalidity":scan.validity,"uid":uid,"subject":message.subject,"from":message.from,"date":message.date},"cursor":null})).map_err(safe)?;
            Ok(PendingEvent {uid,id:event,body})
        }).collect::<Result<Vec<_>>>()?;
        if self.db.enqueue_scan(
            id,
            (sub.validity, sub.uid),
            (scan.validity, scan.next_uid),
            scan.scanned_to,
            &messages,
        )? {
            audit("scan", "queued", "new_uid");
        }
        Ok(())
    }
    pub async fn deliver_once(&self, id: &str) -> Result<bool> {
        let Some(sub) = self.get(id)? else {
            return Ok(false);
        };
        if sub.expires <= now() || !self.auth.event_grant_active(&sub.owner)? {
            self.remove(id)?;
            return Ok(false);
        }
        if sub.paused {
            return Ok(false);
        }
        let Some(item) = self.db.due_event(id)? else {
            return Ok(false);
        };
        let mail_bridge_store::events::OutboxItem {
            event,
            body,
            attempts,
        } = item;
        let headers = webhook::headers(
            &sub.secret,
            sub.previous.as_deref().filter(|_| sub.rotate_until > now()),
            &event,
            id,
            &body,
        )?;
        let reply = self.transport.post(&sub.url, headers, body).await;
        // Unsubscribe/revocation can cancel this future; never schedule new work
        // for a subscription removed while the request was in flight.
        if self.get(id)?.is_none() {
            return Ok(false);
        }
        let (accepted, retry, reason) = match reply {
            Ok(reply) if (200..300).contains(&reply.status) => (true, false, ""),
            Ok(reply) if reply.status == 410 => {
                self.remove(id)?;
                audit("deliver", "removed", "http_410");
                return Ok(false);
            }
            Ok(reply) if reply.status == 413 => (false, false, "http_4xx"),
            Ok(reply) if reply.status == 429 || reply.status >= 500 => (false, true, "http_5xx"),
            Ok(_) => (false, false, "http_4xx"),
            Err(error) => (false, true, error.0),
        };
        let failure = if accepted {
            None
        } else {
            let count = if retry { attempts + 1 } else { 5 };
            let backoff = [1, 4, 16, 60, 300][attempts.min(4) as usize];
            Some((count, now() + backoff, reason))
        };
        self.db.finish_delivery(id, &event, failure)?;
        audit(
            "deliver",
            if accepted {
                "accepted"
            } else if failure.is_some_and(|f| f.0 >= 5) {
                "paused"
            } else {
                "retry"
            },
            if accepted { "http_2xx" } else { reason },
        );
        Ok(true)
    }
    pub fn start(self: Arc<Self>, shutdown: CancellationToken) {
        tokio::spawn(async move {
            loop {
                let subscriptions = self.active().unwrap_or_default();
                for sub in subscriptions {
                    let eligible = if sub.expires <= now() {
                        Ok(false)
                    } else {
                        self.auth.event_grant_active(&sub.owner).and_then(|active| {
                            if active {
                                self.source.available(&sub.filters.account_id)
                            } else {
                                Ok(false)
                            }
                        })
                    };
                    let eligible = match eligible {
                        Ok(eligible) => eligible,
                        Err(_) => {
                            audit("watch", "retry", "availability_lookup_failed");
                            continue;
                        }
                    };
                    if !eligible {
                        let _ = self.remove(&sub.id);
                        continue;
                    }
                    let mut workers = self.workers.lock().expect("worker lock");
                    if sub.paused {
                        if let Some(cancel) = workers.remove(&sub.id) {
                            cancel.cancel();
                        }
                        continue;
                    }
                    if workers.contains_key(&sub.id) {
                        continue;
                    }
                    let cancel = shutdown.child_token();
                    workers.insert(sub.id.clone(), cancel.clone());
                    let delivery = self.clone();
                    let deliver_id = sub.id.clone();
                    let delivery_cancel = cancel.clone();
                    tokio::spawn(async move {
                        loop {
                            let work = async {
                                if delivery.get(&deliver_id)?.is_none_or(|s| s.paused) {
                                    return Ok(false);
                                }
                                delivery.deliver_once(&deliver_id).await?;
                                Ok::<_, Error>(true)
                            };
                            let keep = tokio::select! {_=delivery_cancel.cancelled()=>break,result=work=>result.unwrap_or(true)};
                            if !keep {
                                break;
                            }
                            tokio::select! {_=delivery_cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
                        }
                    });
                    let service = self.clone();
                    tokio::spawn(async move {
                        let mut backoff = 1;
                        loop {
                            let work = async {
                                service.scan_once(&sub.id).await?;
                                let current =
                                    service.get(&sub.id)?.ok_or(Error("Subscription ended"))?;
                                if current.paused {
                                    return Err(Error("Subscription paused"));
                                }
                                tokio::time::timeout(
                                    Duration::from_secs(40),
                                    service.source.wait(&current.filters),
                                )
                                .await
                                .map_err(|_| Error("Event wait timeout"))?
                            };
                            let result =
                                tokio::select! {_ = cancel.cancelled()=>break,result=work=>result};
                            if result.is_err() {
                                if service.get(&sub.id).ok().flatten().is_none() {
                                    break;
                                }
                                tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(backoff))=>{}};
                                backoff = (backoff * 2).min(60);
                            } else {
                                backoff = 1;
                                tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
                            }
                        }
                    });
                }
                tokio::select! {_=shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
            }
            if let Ok(mut workers) = self.workers.lock() {
                for (_, cancel) in workers.drain() {
                    cancel.cancel();
                }
            }
        });
    }
}
