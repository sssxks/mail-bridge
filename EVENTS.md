# MCP Events / message.created (0.3)

## Coremail compatibility and operational diagnostics

Some servers (confirmed on the ZJU account during live read-only diagnosis)
omit UIDNEXT from both EXAMINE and STATUS. Event baseline and catch-up now fall
back to one bounded `FETCH * (UID)` on a nonempty mailbox; an empty mailbox starts
at zero. No historical SEARCH, message body fetch or read-flag mutation is needed
to establish that watermark. UIDVALIDITY is still required and checked.

Distinct callbacks on the same host are paced by the existing two-second
verification rate limit, rather than rejected. Signed verification, TLS/DNS
checks, owner isolation, bounded queues and the two-subscription limit remain.
Failed baselines create no subscription or outbox entries; a short-lived callback
proof may remain and is safely reused on retry. Existing OAuth grants stay valid.

The systemd journal now receives `mail_event` records with only UTC timestamp and
static action/status/reason categories for verification, subscription outcomes,
queued events and delivery results. No headers, keys, tokens, callback URLs,
recipients or message content are logged. Baseline errors return a categorized
`data.reason`. These diagnostics support real platform acceptance testing; mocks
and catalog discovery alone do not prove delivery to a dot.

Contract verified against https://developers.openai.com/plugins/build/mcp-events
and its linked experimental MCP Events draft on 2026-10-18. This is an
implementation of OpenAI's webhook subset, not a claim of live platform approval.
OpenAI documents CallbackEndpointError=-32015; the linked draft uses -32027.
This adapter follows OpenAI's -32015 with a categorized data.reason.

Events are enabled by default. Set MAIL_BRIDGE_EVENTS_ENABLED=false and restart
to disable them. Clients use mail:read for discovery and subscriptions;
mail:send is independent and unnecessary for observing mail. An explicit
subscription with a verified platform-provided webhook URL and whsec_ secret
starts mailbox watching. Enabling the feature alone creates no subscriptions.

The same authenticated POST /mcp implements:
- server/discover: capabilities.events={}, supportedVersions=[2026-07-28].
- events/list: message.created with required account_id and mailbox filters.
- events/subscribe: name, arguments, delivery={mode:webhook,url,secret},
  cursor:null, optional ttlMs/maxAgeMs. maxAgeMs cannot enable historical replay.
- events/unsubscribe: original name, arguments, delivery={mode:webhook,url}.

MCP 2026-07-28 requests require Mcp-Method, MCP-Protocol-Version and valid inline
params._meta io.modelcontextprotocol/protocolVersion and clientCapabilities.
The official rmcp SDK validates these; its extension callback handles event
methods. A small discovery adapter supplies the events capability absent from
the SDK's typed capabilities. Legacy 2025 tool clients are retained.
Missing mail:read scope returns HTTP403 + WWW-Authenticate insufficient_scope.

Subscription identity is a deterministic hash of authenticated OAuth client
principal, canonical URL, event name and typed canonical filter arguments.
Reordered argument keys cannot duplicate it. Each principal has isolated
subscriptions; this is a single mailbox-owner connector, not a multi-tenant SaaS.
Default TTL1h, granted range60s-24h, finite even when no expiration is requested.
Reauthorization uses the same principal; expiry/revocation stops workers.
Clients renew using events/subscribe before refreshBefore. Expiry stops the
subscription without emitting a webhook; this service never invokes a model
for renewal. Whether renewal uses a model depends on the client implementation.

Before acceptance, HTTPS-only callback verification posts a fresh signed
verification challenge; only 2xx plus constant-time matching JSON echo succeeds.
Successful proof is cached by principal+URL for5min; same-host verification
attempts are limited to one per2s. Neither proof errors nor logs reveal the URL
or secret. Destinations must use port443, have no userinfo/fragment and resolve
exclusively to global unicast addresses. Every request resolves again, validates
all results, pins those addresses while retaining original Host/SNI, verifies
TLS, disables environment proxies, redirects and connection reuse. DNS timeout5s,
connect5s/request10s, response8KiB. Private, link-local, multicast, mappedIPv6 and
reserved addresses are rejected. No localhost exception exists in production.

The source uses EXAMINE, UID SEARCH and batched BODY.PEEK[HEADER] fetches.
Each scan fetches at most 128 headers, each capped at 8 KiB, without fetching
bodies or changing read flags. IDLE is
preferred with a30s wait/reconnect; absent IDLE, internal bounded30s checking is
used. This fallback is internal ingestion, not a polling event delivery API.
There are no IMAP listeners without accepted subscriptions. At most2 subscriptions
share the process; each has one watcher connection plus the ordinary mail gate.
Reconnect failures back off1-60s, independently of outbound delivery retries.

Initial baseline is current UIDNEXT-1: old mail is not emitted. UIDVALIDITY and
private UID cursor are persistent. New UIDs enter SQLite outbox atomically with
the watermark; restart resumes pending events and catches up missing UID ranges
(up to1024 UID numbers per pass). Full queue stops cursor advancement, allowing
later catch-up. Stable event/message IDs include account_id, mailbox, UIDVALIDITY
and UID; identical UID numbers from different accounts cannot collide.
External cursor is always null: no historical protocol replay is promised.
If UIDVALIDITY changes, begin from the new current UIDNEXT and mark truncated
for refresh; unsupported gap/terminated controls are not delivered.

Each JSON webhook contains eventId,name,timestamp,data,cursor:null. data contains
account_id,mailbox,message_id,uidvalidity,uid plus subject,from,date. Subject
is MIME-decoded text or null; from is an array of {name,address} with nullable
fields; date is the RFC3339 Date header or null. Missing/unparseable headers
use null or an empty sender array. Header parsing is bounded; subjects/names
are capped at 1000 characters, addresses at 254, and senders at 20.
No body or attachment is pushed. The three new fields are optional in the
catalog for pre-upgrade queued events; newly queued events include all three.
Summary values persist with the event, so retries preserve the exact payload.
Headers: webhook-id=eventId, Unix webhook-timestamp, webhook-signature=v1,base64
HMAC-SHA256(decoded whsec_ key, id+'.'+timestamp+'.'+exact body),
X-MCP-Subscription-Id. Keys decode to24-64bytes. Rotation signs new+previous key
for5min. Retries retain body and event ID, generate fresh timestamp/signature.

2xx acknowledges and deletes the outbox item. Network/429/5xx retry at most5 total
attempts with1/4/16/60s delays; no automatic HTTP client retry. 410 removes the
subscription; 413 and other permanent status failures do not retry. Exhaustion
or permanent failure drops that item, marks truncated and pauses the subscription
until a successful explicit refresh. Remaining queue is bounded/preserved.
Delivery is at-least-once: receivers must deduplicate by eventId, including the
crash window after receiver acceptance but before the durable acknowledgment.

Unsubscribe is idempotent, waits for pending creation/refresh, removes queued
events and cancels watcher/delivery futures. Principal mismatch cannot delete
another principal's subscription. Expiration, OAuth grant revocation or absent
account credential cancels it. Feature OFF starts no worker even with saved
rows; persisted grants expire normally. To erase secrets use full revocation.
Protect state/backups with0700/0600; signing secrets are private database values,
never source/environment templates. Do not upload the state DB to Library.

Local proof: fake IMAP source and receiver validate signed challenges, exact
signed wire bytes, retry stability, restarts, isolation, UIDVALIDITY resets,
key rotation, queue/retry limits, expiry, revocation, unsubscribe, SSRF input
checks and SDK2026 HTTP lifecycle. The Debian12 binary also passes a local HTTP
smoke with missing mailbox credentials. Actual QQ/ZJU IDLE compatibility, real
TLS webhook acceptance, platform catalog display and end-to-end chat wake-up
still require later user-approved credentials/deployment/platform testing.
No SSE event transport, desktop hooks or live-platform success is claimed.
