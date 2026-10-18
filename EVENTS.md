# MCP Events / message.created (0.3)

Contract verified against https://developers.openai.com/plugins/build/mcp-events
and its linked experimental MCP Events draft on 2026-10-18. This is an
implementation of OpenAI's webhook subset, not a claim of live platform approval.
OpenAI documents CallbackEndpointError=-32015; the linked draft uses -32027.
This adapter follows OpenAI's -32015 with a categorized data.reason.

Default OFF. After a separately approved deployment, enable
MAIL_BRIDGE_EVENTS_ENABLED=true and restart. Re-scan the private plugin, grant
mail:read AND mail:events, then ask the platform to subscribe. No real persistent
access or callback is created by the build/test process. The platform must
supply its own destination URL and whsec_ secret; do not invent real ones in chat.
mail:send is independent and unnecessary for observing mail.

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
Missing subscribe scope returns HTTP403 + WWW-Authenticate insufficient_scope.

Subscription identity is a deterministic hash of authenticated OAuth client
principal, canonical URL, event name and typed canonical filter arguments.
Reordered argument keys cannot duplicate it. Each principal has isolated
subscriptions; this is a single mailbox-owner connector, not a multi-tenant SaaS.
Default TTL1h, granted range60s-24h, finite even when no expiration is requested.
Reauthorization uses the same principal; expiry/revocation stops workers.

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

The source uses EXAMINE and UID SEARCH only, never bodies or read flags. IDLE is
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
only account_id,mailbox,message_id,uidvalidity,uid. No subject, sender, body or
attachment is pushed; read content later through an explicit authenticated tool.
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
