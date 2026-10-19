use mail_bridge_auth::Auth;
use mail_bridge_mail::service::MailService;
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};

/// HTTP request extension containing a parsed compact mail-permission set.
#[derive(Clone)]
pub struct Scopes(pub mail_bridge_core::scope::Scopes);
/// HTTP request extension containing the authenticated OAuth client identity.
#[derive(Clone)]
pub struct Principal(pub Box<str>);
/// MCP adapter dependency product `Setup × Mail × Auth × OptionalEvents`.
/// Only construction assembles dependencies; requests cannot replace the services.
#[derive(Clone)]
pub struct Mcp {
    /// Shared private account-setup invitation service.
    setup: Arc<crate::account_setup::AccountSetup>,
    /// Mail service used by HTTP and MCP adapters.
    mail: Arc<MailService>,
    /// Authorization service used to resolve current grants.
    auth: Arc<Auth>,
    /// Optional event service; absence disables event discovery and operations.
    events: Option<Arc<mail_bridge_events::Events>>,
}
impl Mcp {
    /// Assemble immutable adapter dependencies before exposing the handler.
    pub(crate) fn new(
        setup: Arc<crate::account_setup::AccountSetup>,
        mail: Arc<MailService>,
        auth: Arc<Auth>,
        events: Option<Arc<mail_bridge_events::Events>>,
    ) -> Self {
        Self {
            setup,
            mail,
            auth,
            events,
        }
    }
}
/// Fixed tool catalog, initialized once and shared for the process lifetime.
/// Listing clones the catalog; lookup scans eight entries and clones only the match.
pub static TOOLS: LazyLock<[Tool; 8]> = LazyLock::new(|| {
    let string = json!({"type":"string","minLength":1});
    let uid = json!({"type":"integer","minimum":1,"maximum":4294967295u64});
    let page = json!({"folder":{"type":"string","minLength":1,"maxLength":512},"limit":{"type":"integer","minimum":1,"maximum":20},"before_uid":uid,"uidvalidity":uid});
    let draft = json!({"to":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string","maxLength":254}},"subject":{"type":"string","minLength":1,"maxLength":500},"body":{"type":"string","minLength":1,"maxLength":20000}});
    let mut search = page.clone();
    search["field"] = json!({"type":"string","enum":["SUBJECT","FROM","TO","TEXT"]});
    search["query"] = json!({"type":"string","minLength":1,"maxLength":256});
    let mut send = draft.clone();
    send["request_id"] = json!({"type":"string","pattern":"^[A-Za-z0-9_-]{16,80}$"});
    let definitions = [
        (
            "begin_account_setup",
            "Create a private mailbox setup link valid for 10 minutes.",
            json!({}),
            vec![],
        ),
        (
            "list_accounts",
            "List accounts, sender addresses, credential status and SMTP availability.",
            json!({}),
            vec![],
        ),
        (
            "list_folders",
            "List mailbox folders.",
            json!({"offset":{"type":"integer","minimum":0,"maximum":10000},"limit":{"type":"integer","minimum":1,"maximum":100}}),
            vec![],
        ),
        (
            "list_messages",
            "List newest messages first. Pass uidvalidity and next_before_uid as before_uid for the next page, including after empty pages.",
            page,
            vec![],
        ),
        (
            "search_messages",
            "Search provider-indexed messages by field. Empty results may be incomplete; inspect search_warning and preserve pagination. Domain-shaped FROM/TO queries use broader candidates verified against decoded headers.",
            search,
            vec!["field", "query"],
        ),
        (
            "read_message",
            "Read a message without marking it as read.",
            json!({"folder":string,"uid":uid,"uidvalidity":uid}),
            vec!["uid", "uidvalidity"],
        ),
        (
            "prepare_draft",
            "Preview sender, recipients, subject and body without saving or sending.",
            draft,
            vec!["to", "subject", "body"],
        ),
        (
            "send_email",
            "Send a plain-text email. Reuse request_id for the same message to prevent duplicate sends.",
            send,
            vec!["to", "subject", "body", "request_id"],
        ),
    ];
    definitions.map(|(name,description,mut properties,mut required)|{
        if !matches!(name, "list_accounts" | "begin_account_setup") {
            properties["account_id"]=json!({"type":"string","pattern":"^[a-z0-9_-]{1,32}$"});
            required.push("account_id");
        }
        let write=name=="send_email";
        let creates_setup=name=="begin_account_setup";
        let value=json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":!write&&!creates_setup,"destructiveHint":write,"idempotentHint":!write&&!creates_setup,"openWorldHint":true},"_meta":{"securitySchemes":[{"type":"oauth2","scopes":[if write{"mail:send"}else{"mail:read"}]}]}});
        serde_json::from_value(value).expect("static tool definition")
    })
});
impl ServerHandler for Mcp {
    /// Adapt authenticated event discovery and subscription operations to MCP errors.
    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CustomResult, ErrorData> {
        let Some(events) = &self.events else {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "Events are disabled",
                None,
            ));
        };
        if context
            .protocol_version()
            .is_none_or(|v| v.as_str() != "2026-07-28")
        {
            return Err(ErrorData::new(
                ErrorCode(-32026),
                "Events require MCP 2026-07-28",
                None,
            ));
        }
        let parts = context.extensions.get::<axum::http::request::Parts>();
        let scopes = parts
            .and_then(|p| p.extensions.get::<Scopes>())
            .map(|s| &s.0);
        let owner = parts
            .and_then(|p| p.extensions.get::<Principal>())
            .ok_or_else(|| {
                ErrorData::new(ErrorCode(-32024), "Authenticated principal required", None)
            })?;
        let permitted = scopes.is_some_and(|s| s.contains(mail_bridge_core::scope::Scope::Read));
        if !permitted {
            return Err(ErrorData::new(
                ErrorCode(-32024),
                "Authorize mail:read before subscribing",
                Some(json!({"scope":"mail:read"})),
            ));
        }
        let value = match request.method.as_str() {
            "events/list" => {
                let p = request.params.unwrap_or(json!({}));
                if !p.is_object()
                    || p.as_object()
                        .is_some_and(|v| v.keys().any(|k| k != "_meta" && k != "cursor"))
                    || p.get("cursor").is_some_and(|v| !v.is_null())
                {
                    return Err(ErrorData::invalid_params(
                        "No event catalog cursor is available",
                        None,
                    ));
                }
                events.catalog()
            }
            "events/subscribe" | "events/unsubscribe" => {
                let mut p = request.params.unwrap_or(json!({}));
                if let Some(object) = p.as_object_mut() {
                    object.remove("_meta");
                }
                let params: mail_bridge_events::subscription::Subscribe = serde_json::from_value(p)
                    .map_err(|_| {
                        ErrorData::invalid_params("Invalid event subscription arguments", None)
                    })?;
                if request.method == "events/subscribe" {
                    let result = events.subscribe(&owner.0, params).await;
                    match &result {
                        Ok(_) => mail_bridge_events::audit("subscribe", "accepted", "ok"),
                        Err(error) => mail_bridge_events::audit(
                            "subscribe",
                            "failed",
                            error.reason.unwrap_or(match error.code {
                                -32602 => "invalid_arguments",
                                -32024 => "access_denied",
                                -32025 => "resource_limit",
                                _ => "internal_error",
                            }),
                        ),
                    }
                    result.map_err(event_rpc)?
                } else {
                    let result = events.unsubscribe(&owner.0, params).await;
                    mail_bridge_events::audit(
                        "unsubscribe",
                        if result.is_ok() { "accepted" } else { "failed" },
                        "request_completed",
                    );
                    result.map_err(event_rpc)?
                }
            }
            _ => {
                return Err(ErrorData::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    "Unknown event method",
                    None,
                ));
            }
        };
        Ok(CustomResult::new(value))
    }
    /// Advertise the MCP tool capability.
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
    /// Return the fixed tool catalog.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(TOOLS.to_vec()))
    }
    /// Find one named entry in the fixed eight-tool catalog.
    fn get_tool(&self, name: &str) -> Option<Tool> {
        TOOLS.iter().find(|tool| tool.name == name).cloned()
    }
    /// Check the required permission and dispatch account setup or a parsed mail operation.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResponse, ErrorData> {
        let scope = if request.name == "send_email" {
            "mail:send"
        } else {
            "mail:read"
        };
        let allowed = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<Scopes>())
            .is_some_and(|scopes| {
                scopes.0.contains(if scope == "mail:send" {
                    mail_bridge_core::scope::Scope::Send
                } else {
                    mail_bridge_core::scope::Scope::Read
                })
            });
        if !allowed {
            let mut result = CallToolResult::error(vec![ContentBlock::text(
                "Authorize the required mail scope.",
            )]);
            result.meta = Some(
                serde_json::from_value(
                    json!({"mcp/www_authenticate":[self.auth.challenge(scope)]}),
                )
                .expect("static metadata"),
            );
            return Ok(result.into());
        }
        let args = Value::Object(request.arguments.unwrap_or_default());
        let outcome = if request.name == "begin_account_setup" {
            let client = context
                .extensions
                .get::<axum::http::request::Parts>()
                .and_then(|p| p.extensions.get::<Principal>());
            match client {
                Some(client) if args.as_object().is_some_and(|v| v.is_empty()) => {
                    self.setup.begin(&client.0, self.auth.base())
                }
                _ => Err(mail_bridge_core::Error::Rejected(
                    "Invalid setup arguments or missing authenticated connection",
                )),
            }
        } else {
            self.mail.dispatch(&request.name, args).await
        };
        let result = match outcome {
            Ok(value) => CallToolResult::success(vec![ContentBlock::text(value.to_string())]),
            Err(error) => CallToolResult::error(vec![ContentBlock::text(error.message())]),
        };
        Ok(result.into())
    }
}

/// Translate the event error category into its MCP wire representation.
fn event_rpc(error: mail_bridge_events::subscription::EventError) -> ErrorData {
    ErrorData::new(
        ErrorCode(error.code),
        error.message,
        error.reason.map(|reason| json!({"reason":reason})),
    )
}
