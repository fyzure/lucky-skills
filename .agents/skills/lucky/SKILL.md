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

## DDNS behavior

Lucky 3.0.0 Cloudflare DDNS has a `behavior-runtime` probe at `tools/lucky_ddns_probe.py`. The verified write lifecycle is create with `POST /api/ddns`, update with `PUT /api/ddns?key=<TaskKey>`, toggle with `/api/ddns/enable`, synchronize with `/api/ddns/manualSync/{TaskKey}`, and delete with `DELETE /api/ddns?key=<TaskKey>`. For an IPv4-driven A record, `SyncRecordData.ipv4Address` must be non-empty; `{ipv4Addr}` is the observed substitution template that resolves to the task's current IPv4 query result. A literal IPv4 string is instead treated as a fixed desired record value.

The probe clones an existing Cloudflare provider configuration only in memory, creates a uniquely prefixed TEST task and TEST DNS record, serves the IPv4 source and webhook receiver on loopback, independently verifies Cloudflare record changes, and cleans both sides. Never print the cloned provider Secret or preserve the raw task detail in evidence. Use `--confirm PROBE-AND-CLEAN-DDNS` only with the instance owner's explicit approval and a valid `CLOUDFLARE_API_TOKEN` for the selected test zone.

For Lucky v3 Web-service redirects, the redirect status is stored at `DefaultProxy.OtherParams.RedirectType` (and equivalently on redirect subrules). Lucky 3.0.0 has been API-verified to accept `"308"`; a rule with `WebServiceType: "redirect"`, `Locations: ["https://{host}{path}{args}"]`, and `RedirectType: "308"` returned HTTP 308 for both GET and POST. Create a new listener with `POST /api/webservice/rules`; update an existing listener by GETting its full object and PUTting the preserved object to `/api/webservice/rule/{RuleKey}`.

Lucky 3.0.0 also has runtime-verified WebService SNI routing. The current frontend exposes the exact service type value `WebServiceType: "SNIRouting"`; for an SNI subrule, `Domains` contains the SNI hostname and `Locations` contains the raw TCP target in `host:port` form. SNI routing requires the parent WebService rule to have TLS enabled, but Lucky does **not** terminate TLS for the matching SNI stream: it forwards the ClientHello/TLS connection to the target. Therefore the target service must present a certificate valid for that hostname. `OtherParams.ProxyProtocolV2` may be kept `false` unless the target explicitly accepts Proxy Protocol v2. Lucky 3.0.0 currently limits SNI routing subrules to six per WebService rule. After a write, verify both the returned rule object and an external TLS/application request; `ret: 0` alone is not sufficient.

## SSL certificate mapping

Lucky 3.0.0 certificate objects support `MappingToPath`, `MappingPath`, and `MappingChangeScript`. When mapping is enabled, Lucky writes certificate material into the configured writable directory using the certificate `Remark` as the filename prefix; the observed files include `<Remark>.key` and `<Remark>.pem` (plus certificate/issuer files). This is suitable for a local TLS service behind SNI routing because Lucky will refresh the mapped files when the managed certificate changes.

Treat mapped private keys as secrets. The observed default mapping created the private key with mode `0644`, so explicitly reduce it to `0600` and, when appropriate, use `MappingChangeScript` to re-apply the permission after future certificate updates and/or reload the consuming service. Keep mapping paths inside an intentionally writable Lucky mount; do not expose mapped certificate directories through file-serving rules. Never print `CertBase64`, `KeyBase64`, ACME credentials, or the raw response from `GET /api/ssl/{key}` into chat/logs; use the client's redacted output or write sensitive responses to a root-only temporary file and delete it immediately after constructing a reviewed update payload.

For owner-authorized ACME validation, `tools/lucky_ssl_acme_probe.py` creates one unique TEST certificate, performs real issuance, verifies metadata plus Lucky-visible mapped `.key/.crt/.pem` files, exercises only TEST-object update/toggle/flush/manualsync paths, and cleans the certificate and mapping directory. If Lucky is containerized, `MappingPath` is interpreted in Lucky's filesystem namespace; do not assume container `/tmp` equals host `/tmp`. Current 3.0.0 behavior also showed that turning mapping on only after certificate material already exists does not immediately backfill old material.

`tools/lucky_ssl_sync_probe.py` verifies the `linuxssh` sync-client configuration and entitlement boundary without bypassing it. On the current runtime, `/api/info` reports `u=0`; although a TEST linuxssh client receives a Key and a TEST certificate with `AllSyncClient=true` is created successfully, `manualsync` returns `PermissionDeniedCannotUseSyncFunction` before SSH transfer. Treat actual sync-client file delivery as **not verified** unless a legitimately entitled Lucky instance allows the transfer stage.

## WebTerminal behavior

WebTerminal is a high-risk capability. Runtime probes are allowed only against localhost and uniquely prefixed TEST connections/sessions/paths. `tools/lucky_webterminal_probe.py` verifies a real temporary-ticket WebSocket local shell: `connecting/connected` JSON events, raw terminal input/output, JSON resize frames, session list/detail/stats/remark, detach and attach, then explicit close. The shared stdlib WebSocket helper preserves a valid first frame that arrives in the same TCP read as the HTTP 101 response.

`tools/lucky_webterminal_sftp_probe.py` uses an ephemeral localhost-only SSH key and the existing local sshd to verify Lucky's first-use `SSHHostKeyUntrusted` confirmation flow, persisted host-key trust, a second successful connection test, real SSH terminal I/O, and SFTP list/mkdir/touch/write/read/rename/copy/chmod/remove plus tar.gz compress/preview/decompress under a unique `/tmp/TEST-*` tree. Do not install remote utilities just to make a probe pass; archive behavior depends on tools already available on the SSH target.

Two Lucky 3.0.0 upload routes are currently verified **failures**, not supported-success claims: browser-equivalent multipart `POST /api/webterminal/sftp/{SessionId}/upload` reproducibly returns `ret=5 SSH_FX_FAILURE`, while `upload-streaming` reproducibly returns closed-pipe/BrokenPipe behavior. Preserve these as runtime defects until a later Lucky version is re-verified.

## StorageManagement local behavior

Lucky 3.0.0 local StorageManagement has a bounded runtime probe at `tools/lucky_storage_probe.py`. The verified registry lifecycle is `GET /api/storagemanagement/list`, POST/PUT/DELETE on `/api/storagemanagement/list`, the mutating GET `/api/storagemanagement/enable`, and read-only `litelist`. A newly POSTed local item was normalized to `Enable=true` even when the candidate explicitly requested `Enable=false`; if a disabled initial state is required, explicitly disable the generated item after creation. Disabled items are absent from `litelist` and reappear after enable.

The storage probe uses only a unique Lucky-visible `/tmp/TEST-*` directory created through `local-path-browser`, keeps `SystemMount.Enable=false`, and removes the TEST item/path before checking list/litelist baselines. `Writable` is also behavior-verified through the loopback-only WebDAV probe described below; `SystemMount` remains unverified until a separate safely unmounted TEST mount is practiced.

## WebDAV + Storage permission behavior

`tools/lucky_webdav_probe.py` is the preferred file-service consumer probe because Lucky 3.0.0 WebDAV supports an explicit `ListenIP`. It refuses to run unless the current WebDAV service is stopped and has no configured users, then binds a random high port on `127.0.0.1`, disables TLS and firewall automation, and creates one disposable Basic-auth principal. Two unique local StorageManagement TEST items are exposed as `store` mounts: one writable and one read-only. Runtime verification covers OPTIONS/PROPFIND, writable PUT/GET/DELETE, read-only PUT rejection, service status/logs and full cleanup.

Before restoring the baseline WebDAV configuration, the probe re-reads the live configuration and verifies its unique TEST username plus listener address/port. Refuse restoration if those ownership markers no longer match; never overwrite a concurrent operator change with a stale snapshot. Passwords and test file bodies must never appear in evidence.

FTP is not equivalent from a safety perspective. The current FTP configuration exposes `Network`, control `Port` and passive port range but no loopback `ListenIP`. Do not start a temporary FTP listener on a production host merely for coverage and do not modify the host firewall to manufacture isolation. Practice real FTP login/transfer only in a network namespace or dedicated isolated instance.

## Rclone local sync behavior

`tools/lucky_rclone_sync_probe.py` verifies Rclone's execution engine without remotes or credentials. It creates unique Lucky-visible source/destination `/tmp/TEST-*` trees and one TEST task with `SourceType=local`, `DestType=local`, `SyncMode=sync` and `CreateEmptyDirs=true`. A real run must reach success and propagate a source-only empty directory. The same task is then PUT-updated to `DryRun=true`; a second source-only directory must remain absent from the destination after another successful run.

The compact `/api/rclone/sync/list` response intentionally omits many execution options. Use `GET /api/rclone/sync/{Key}` when validating `DryRun`, `CreateEmptyDirs`, filters, bandwidth or other detailed task fields. Do not add cloud remotes, schedules, bisync or system mounts to this probe solely for coverage.

## Docker Compose behavior

Use `tools/lucky_docker_compose_probe.py` for bounded Compose lifecycle verification. It requires an empty Docker-task baseline, reuses a pre-existing image, creates only unique `/tmp/TEST-*` projects, sets `network_mode: none`, publishes no ports, declares no volumes, and never requests image pull/build or Docker prune. One fresh project verifies synchronous `up → down`; a second project follows the current Lucky 3.0.0 UI flow through `up-async`, task polling, `ps/config/logs`, `stop-async`, synchronous start/restart and `down-async`.

Do not treat synchronous `/api/docker/compose/up` as an idempotent re-up operation: runtime verification shows that an already existing project name returns a project-name-already-exists business error. Also distinguish Docker task cancellation from completed-history cleanup. `DELETE /api/docker/tasks/{id}` cancels an active task and cannot remove a completed task. The global `DELETE /api/docker/tasks` may clear completed history only when the pre-probe task baseline is empty and the current task-ID set exactly equals the IDs issued to the probe. Otherwise refuse the clear and preserve operator tasks.

## Cron shell behavior

`tools/lucky_cron_probe.py` verifies Cron execution without touching business tasks or external services. It requires clean TEST-prefixed ownership, creates one disposable group plus two TEST tasks, and writes only inside one Lucky-visible `/tmp/TEST-*` directory. The verified shell subtask shape is `{Type:"shell_option", Options:{shell_content:<script>}, Remark:<label>}`. `Type=8` is used for manual-only tasks, while `Type=4` with a numeric-seconds string in `TypeParams` is the current every-N-seconds schedule model.

For a whole-task manual run, `GET /api/cron/dojobs?key=<CronKey>` is mutating despite using GET. For a selected subtask, `POST /api/cron/jobs/trigger` accepts `{cronKey,jobIndex}`. The bounded runtime probe verified a manual marker, then PUT-updated the same task to `Type=4` / `TypeParams="2"` and observed the scheduler create a second marker automatically. A separate `exit 7` shell subtask was dispatched through the single-job trigger and produced a Cron failure/error log entry. Disable scheduled TEST tasks before deletion and remove only uniquely prefixed TEST tasks/groups/paths; never use this probe to call the network, toggle production services, or execute arbitrary host paths.

## Report results

Summarize what was read or changed, identify any remaining non-Lucky dependency (DNS, CDN, origin application, firewall, certificate issuance), and avoid reproducing secrets returned by Lucky responses.
