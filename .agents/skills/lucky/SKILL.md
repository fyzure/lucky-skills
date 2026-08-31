---
name: lucky
description: Manage and troubleshoot authorized Lucky v3 instances through this repository's safe OpenToken client. Use for Lucky status/modules, Web Service and reverse-proxy rules, DDNS, certificates, Docker, cloudflared, FRP, STUN, or a specific Lucky configuration change. 用于查询或修改 Lucky 管理后台/OpenToken API；默认只读，写操作仅在用户明确要求时执行，并遵循客户端风险分级与确认机制。
---

# Lucky management workflow

Use the repository's guarded OpenToken tooling instead of ad-hoc authenticated `curl` commands.

## Locate the client

1. Prefer the current repository root when it contains both `tools/lucky_credentials.py` and `tools/lucky_api.py`.
2. Otherwise, locate the full `lucky-skills` checkout/plugin that contains those files. Do not assume a standalone copied `SKILL.md` includes the client.
3. Run Lucky commands from that root so the endpoint catalog and helper modules resolve correctly.

## Authenticate safely

- Treat OpenToken as an administrator secret. Never print it, place it in command-line arguments, commit it, or expose the safe-entry path unnecessarily.
- Check credentials without revealing them:

```bash
python3 tools/lucky_credentials.py doctor
```

- If credentials are missing, use the interactive installer described in `docs/credentials.md`:

```bash
python3 tools/lucky_credentials.py install
```

- Prefer direct in-process credential loading so the OpenToken never has to be copied into a child-process environment:

```bash
python3 tools/lucky_api.py status
```

- The CLI uses environment credentials only when both `LUCKY_BASE_URL` and `LUCKY_OPEN_TOKEN` are non-empty. If both are empty/unset, it reads the platform/configured default credential path from `lucky_credentials.py`; if only one is non-empty, it fails closed to avoid targeting the wrong Lucky instance. `--credentials-file PATH` explicitly overrides this selection. The older `lucky_credentials.py run -- ...` wrapper remains available for compatibility.

## Start read-only

For inspection or troubleshooting, establish a baseline before proposing changes:

```bash
python3 tools/lucky_api.py status
python3 tools/lucky_api.py info
python3 tools/lucky_api.py modules
```

Search the catalog before using an arbitrary endpoint:

```bash
python3 tools/lucky_api.py catalog --search webservice
python3 tools/lucky_api.py catalog --search ddns
```

Then call cataloged read-only routes with `call`. Prefer narrow responses and the smallest endpoint that answers the question. The default catalog merges the frontend snapshot with `evidence/lucky-v3-runtime-verification.json` only when both the Lucky version and the exact static-snapshot SHA-256 match; treat `runtime-verified` method and risk overrides as stronger operational evidence than generic HTTP-method heuristics, and use `schema_evidence` to judge whether body fields came from frontend construction, model pass-through, or authorized read-only shape checks. A route absent from the merged catalog remains unknown and must not be called with credentials just to discover its behavior.

## Apply changes conservatively

- Only mutate Lucky when the user explicitly asks for the configuration change.
- Trust the repository's merged route risk classification, not HTTP method alone. Runtime verification has confirmed dangerous GET endpoints such as configuration backup/download actions, so never reinterpret a `dangerous` or `mutating` runtime override as read-only merely because the method is GET.
- Read the current object first and preserve the identifiers/fields required for rollback.
- Make the smallest targeted change. Do not replace unrelated rules or settings.
- The client rejects writes by default. For a confirmed write, use both `--allow-write` and the exact confirmation string required by `--confirm`, for example:

```bash
python3 tools/lucky_api.py call /api/example \
  --method PUT --json-file /path/to/reviewed-payload.json \
  --allow-write --confirm 'PUT /api/example'
```

- Verify the resulting object/state immediately after the write. If the change is reversible and verification fails, restore the captured baseline when safe to do so.
- Never perform dangerous actions such as deleting data, clearing sessions/statistics, terminal/file operations, container destruction, or broad rule replacement against existing business resources unless that exact destructive outcome was requested. A schema-specific exception is allowed only when the instance owner explicitly authorizes a bounded write probe: use newly created disposable resources with a unique test prefix, capture and verify the business-resource baseline before and after, minimize calls, clean up immediately, and route global/destructive operations such as prune to a mock or otherwise isolated backend rather than the production backend.
- When improving UNKNOWN coverage, first distinguish literal-prefix extraction artifacts from real handlers. If method discovery is necessary and the target Lucky version has already been calibrated to authenticate before protected handlers, prefer unauthenticated method probes that stop at the login check. A non-404 result proves route/method existence only; it does not prove request-body schema or safe business behavior. Do not establish WebSocket/SFTP sessions or authenticate mutating probes merely to improve coverage unless the explicit, isolated schema-probe exception above applies.

## Web Service / reverse proxy work

For domain migration or reverse-proxy changes, inspect `/api/webservice/rules` (or the narrow rule-detail endpoint) first. Preserve the existing rule key, listener/TLS settings, proxy target, authentication, security groups, WAF, and unrelated domains. When adding a new hostname for a migration, prefer temporarily keeping both old and new hostnames until end-to-end validation succeeds.

Lucky 3.0.0 reverse-proxy subrules are saved as part of the **complete parent WebService object**. The current frontend reads `/api/webservice/rule/{RuleKey}`, edits `DefaultProxy` or `ProxyList`, and PUTs the preserved parent object back; a new/copied subrule has an empty/unset `Key` until Lucky assigns one. Re-read immediately before a write and preserve unknown fields. For disposable probes, clean up by removing only your uniquely TEST-prefixed subrules from the latest parent object instead of restoring a stale snapshot.

`NginxConf` is a runtime-verified mini-nginx configuration field for `reverseproxy`; it is not an opaque string and not full Nginx. Lucky 3.0.0 currently supports `proxy_set_header`, `proxy_hide_header`, `add_header`, `proxy_redirect`, `location`, and Lucky's `path` shorthand. This means arbitrary reviewed request headers such as `X-Workspace-Id` or `X-Forwarded-Prefix` can be set directly with `proxy_set_header`; an empty quoted value removes a request header. `location`/`path` matching uses the request path after a `Domains` frontend prefix is removed, while a path already present in `Locations` is prepended to the remaining path and the query is preserved. See `docs/webservice-reverse-proxy.md` for the verified variables, Host behavior, response-header semantics, `AutoProxyLocation`, and exact path model.

Treat `NginxConf` as powerful configuration: never interpolate untrusted end-user strings into directives. For owner-authorized runtime validation, `tools/lucky_web_reverseproxy_probe.py` batches unique TEST subrules into one setup PUT and removes only those TEST subrules in cleanup, with bounded 429 backoff.

For Lucky v3 Web-service redirects, the redirect status is stored at `DefaultProxy.OtherParams.RedirectType` (and equivalently on redirect subrules). Lucky 3.0.0 has been API-verified to accept `"308"`; a rule with `WebServiceType: "redirect"`, `Locations: ["https://{host}{path}{args}"]`, and `RedirectType: "308"` returned HTTP 308 for both GET and POST. Create a new listener with `POST /api/webservice/rules`; update an existing listener by GETting its full object and PUTting the preserved object to `/api/webservice/rule/{RuleKey}`.

Lucky 3.0.0 also has runtime-verified WebService SNI routing. The current frontend exposes the exact service type value `WebServiceType: "SNIRouting"`; for an SNI subrule, `Domains` contains the SNI hostname and `Locations` contains the raw TCP target in `host:port` form. SNI routing requires the parent WebService rule to have TLS enabled, but Lucky does **not** terminate TLS for the matching SNI stream: it forwards the ClientHello/TLS connection to the target. Therefore the target service must present a certificate valid for that hostname. `OtherParams.ProxyProtocolV2` may be kept `false` unless the target explicitly accepts Proxy Protocol v2. Lucky 3.0.0 currently limits SNI routing subrules to six per WebService rule. After a write, verify both the returned rule object and an external TLS/application request; `ret: 0` alone is not sufficient.

## SSL certificate mapping

Lucky 3.0.0 certificate objects support `MappingToPath`, `MappingPath`, and `MappingChangeScript`. When mapping is enabled, Lucky writes certificate material into the configured writable directory using the certificate `Remark` as the filename prefix; the observed files include `<Remark>.key` and `<Remark>.pem` (plus certificate/issuer files). This is suitable for a local TLS service behind SNI routing because Lucky will refresh the mapped files when the managed certificate changes.

Treat mapped private keys as secrets. The observed default mapping created the private key with mode `0644`, so explicitly reduce it to `0600` and, when appropriate, use `MappingChangeScript` to re-apply the permission after future certificate updates and/or reload the consuming service. Keep mapping paths inside an intentionally writable Lucky mount; do not expose mapped certificate directories through file-serving rules. Never print `CertBase64`, `KeyBase64`, ACME credentials, or the raw response from `GET /api/ssl/{key}` into chat/logs; use the client's redacted output or write sensitive responses to a root-only temporary file and delete it immediately after constructing a reviewed update payload.

## Report results

Summarize what was read or changed, identify any remaining non-Lucky dependency (DNS, CDN, origin application, firewall, certificate issuance), and avoid reproducing secrets returned by Lucky responses.
