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

Then call cataloged read-only routes with `call`. Prefer narrow responses and the smallest endpoint that answers the question. The default catalog merges the frontend snapshot with `evidence/lucky-v3-runtime-verification.json` only when both the Lucky version and the exact static-snapshot SHA-256 match; treat `runtime-verified` method and risk overrides as stronger operational evidence than generic HTTP-method heuristics, and use `schema_evidence` to judge whether body fields came from frontend construction, model pass-through, or authorized read-only shape checks. The current Lucky 3.0.0 merged baseline contains 597 routes, all `runtime-verified`, with zero `frontend-call` and zero `unknown`; two additional frontend calls are retained only as `runtime-rejected` false positives because private-DinD runtime probes with owned containers still returned HTTP 404. A route absent from the merged catalog remains unknown and must not be called with credentials just to discover its behavior.

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
- Never perform dangerous actions such as deleting data, clearing sessions/statistics, terminal/file operations, container destruction, or broad rule replacement against existing business resources unless that exact destructive outcome was requested. A schema-specific exception is allowed only when the instance owner explicitly authorizes a bounded write probe: use newly created disposable resources with a unique test prefix, capture and verify the business-resource baseline before and after, minimize calls, clean up immediately, and route global/destructive regression such as prune to GitHub-hosted disposable Lucky, private DinD, or another owned synthetic fixture rather than any production backend.
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

## Core admin behavior (CI-only)

Never behavior-test global admin credentials, global 2FA, configuration restore, program reboot/update, certificate destruction or Docker prune on production merely for coverage. `tools/lucky_core_admin_ci_probe.py` is the verified path for the account/reboot subset: it refuses non-GitHub-Actions execution, starts a fresh pinned Lucky 3.0.0 container published only on runner loopback, and performs all Lucky operations through HTTP APIs.

The verified password flow is `PUT /api/password/verify` with the current password, followed by a full-object `PUT /api/baseconfigure` carrying the new `AdminPassword` and `OldPassword`. Authentication-policy writes invalidate the current admin token. On the disposable instance the old password was rejected after save and the generated strong password successfully established a new token. Global 2FA uses `PUT /api/2fa/setting` with `{TwoFAEnable,TwoFAKey,TwoFACode}`. The CI probe generates a 16-character Base32 key and six-digit RFC 6238 SHA-1 TOTP entirely in runner memory; enable makes password-only login fail, key replacement makes the previous key fail and the new key succeed, and disable with the current code restores password-only login. Re-authenticate after every password/2FA policy transition before protected readback.

`GET /api/reboot_program` is also behavior-verified only on that disposable instance. Docker `restart=always` is used solely as the CI supervisor: the Lucky process PID changed, the login challenge recovered, and the changed password still logged in after restart. Never persist passwords, RSA login plaintext, TOTP secrets/codes or admin tokens in logs/evidence. Remaining certificate-destruction flows must follow the same disposable-CI rule.

Global configuration restore is separately behavior-verified by `tools/lucky_config_restore_ci_probe.py`, again only on fresh GitHub-hosted Lucky. The verified flow is: write a disposable marker profile A -> authenticated `GET /api/configure` export -> change to profile B -> multipart `POST /api/configure` with field `file` -> read the opaque `restoreConfigureKey` -> `GET /api/restoreconfigureconfirm?key=<opaque>` -> wait for login challenge -> re-authenticate -> verify profile A returned. Treat the exported archive as secret-bearing material: keep it only in runner memory/root-owned temporary storage, never print its body/path, never persist the restore key, and never use production configuration import/export for coverage.

Self-update behavior is verified only by `tools/lucky_update_ci_probe.py` on fresh GitHub-hosted Lucky. An official Linux x86_64 release archive is staged through `/api/update`, and the returned `Name/ARCH/OS/Version/GoVersion/Date/MD5` metadata is submitted unchanged to `PUT /api/update/comfire`. The verified 3.0.0 -> 2.27.2 downgrade accepted both steps with `ret=0` but then stopped serving HTTP for at least 45 seconds while Docker still reported the container running with RestartCount=0 and ExitCode=0. Treat this as a dangerous non-serving downgrade failure semantic, not a successful update. Never exercise self-update against production merely for coverage.

Certificate destructive behavior is verified only by `tools/lucky_ssl_destructive_ci_probe.py` on fresh GitHub-hosted Lucky. The probe generates its own self-signed TEST certificate/key and imports it with the runtime-verified direct-material source `AddFrom=file`. `PUT /api/ssl/flush?key=<owned>` returns `ret=1` with `UnsupportedRefreshType file`; no ACME run starts and the certificate fingerprint does not change. `DELETE /api/ssl?key=<owned>` then removes the TEST item and restores the empty SSL baseline. Do not reinterpret the flush result as successful renewal, and never use production certificates for destructive coverage.

Real Docker prune is behavior-verified only by `tools/lucky_docker_prune_ci_probe.py`. That probe gives Lucky **only** a private Docker-in-Docker Unix socket carried in an owned named volume; the runner/production Docker socket is never mounted into Lucky. With `{all:true,volumes:true}`, Lucky 3.0.0 actually removed the owned stopped container, unused TEST network, anonymous volume and dangling image while preserving a running protected container plus its network/volume/image. A tagged-but-unused TEST image remained and BuildKit cache did not shrink, so do **not** interpret Lucky's `all=true` as Docker CLI `image prune -a`. Production Docker prune remains forbidden for coverage.

## StorageManagement local behavior

Lucky 3.0.0 local StorageManagement has a bounded runtime probe at `tools/lucky_storage_probe.py`. The verified registry lifecycle is `GET /api/storagemanagement/list`, POST/PUT/DELETE on `/api/storagemanagement/list`, the mutating GET `/api/storagemanagement/enable`, and read-only `litelist`. A newly POSTed local item was normalized to `Enable=true` even when the candidate explicitly requested `Enable=false`; if a disabled initial state is required, explicitly disable the generated item after creation. Disabled items are absent from `litelist` and reappear after enable.

The local-storage probe uses only a unique Lucky-visible `/tmp/TEST-*` directory created through `local-path-browser`, keeps `SystemMount.Enable=false`, and removes the TEST item/path before checking list/litelist baselines. `Writable` is also behavior-verified through the loopback-only WebDAV probe described below. StorageManagement's own `SystemMount` is **platform-boundary verified for this repository's Linux x86_64 target**: the served Lucky 3.0.0 frontend renders those controls only for `Type != local` when `os == windows` and links to WinFsp; its save validator does not independently validate SystemMount. `tools/lucky_storage_mount_ci_probe.py` runs a fresh pinned Linux Lucky in GitHub Actions with `SYS_ADMIN` + `/dev/fuse` only as a diagnostic control, then forces one owned local SystemMount request. Lucky returns `ret=4` with `mountpoint format error` before creating the storage item, and the probe restores storage/litelist/Cron/path baselines. Treat this as a Linux non-applicability/platform boundary, **not** as successful Windows SystemMount behavior. A true StorageManagement mount claim requires a controlled Windows Lucky + WinFsp environment and a non-local storage type. Rclone SystemMount is a separate Linux-capable feature with its own FUSE behavior probe.

## WebDAV + Storage permission behavior

`tools/lucky_webdav_probe.py` is the preferred file-service consumer probe because Lucky 3.0.0 WebDAV supports an explicit `ListenIP`. It refuses to run unless the current WebDAV service is stopped and has no configured users, then binds a random high port on `127.0.0.1`, disables TLS and firewall automation, and creates one disposable Basic-auth principal. Two unique local StorageManagement TEST items are exposed as `store` mounts: one writable and one read-only. Runtime verification covers OPTIONS/PROPFIND, writable PUT/GET/DELETE, read-only PUT rejection, service status/logs and full cleanup.

Before restoring the baseline WebDAV configuration, the probe re-reads the live configuration and verifies its unique TEST username plus listener address/port. Refuse restoration if those ownership markers no longer match; never overwrite a concurrent operator change with a stale snapshot. Passwords and test file bodies must never appear in evidence.

FTP is not equivalent from a safety perspective. The current FTP configuration exposes `Network`, control `Port` and passive port range but no loopback `ListenIP`. Do not start a temporary FTP listener on a production host merely for coverage and do not modify the host firewall to manufacture isolation. Practice real FTP login/transfer only in a network namespace or dedicated isolated instance.

For the verified isolated path, use `tools/lucky_ftp_ci_probe.py`. It refuses to run outside GitHub Actions and starts a fresh pinned Lucky 3.0.0 container. Lucky configuration is still changed only through its HTTP API; Docker is used solely as the outer network boundary, publishing the admin listener, FTP control port and every passive-data port only on runner `127.0.0.1`. Keep `AutoFireWall=false`, `DisableActiveMode=true` and use a ten-port passive range because current Lucky rejects `PassivePortEnd - PassivePortStart < 9`. The probe creates one random TEST principal with one writable local mount, requires wrong-password rejection, then completes passive LIST, STOR, RETR and DELE with exact backing-file verification. With a single local mount, that mount is the FTP root itself; `DisplayName` is not an extra directory layer. Restore the exact stopped/empty FTP baseline through the API under the ownership guard, then remove the disposable instance. Never transplant this probe onto the production host just to increase coverage.

For NAT-PMP mapping behavior, use `tools/lucky_natpmp_ci_probe.py` rather than manufacturing NAT on the production RS host. It is GitHub-Actions-only and places pinned Lucky 3.0.0 on a Docker `--internal` LAN while a separate veth-backed network namespace acts as a synthetic WAN. Owned stdlib fixtures provide the STUN Binding server, NAT-PMP UDP/5351 gateway and UDP echo target. Lucky configuration still changes only through HTTP APIs: the disposable udp4 rule uses `NatPMP=true`, `UPnP=false` and `AutoOptionsFirewall=false`. Require a real NAT-PMP UDP add whose internal port equals Lucky `ListenPort`, then require a random marker from the WAN namespace to traverse the assigned external-port mapping relay -> Lucky -> echo target -> Lucky -> relay and return byte-for-byte. Repeated add/renew for the same internal mapping must retain the assigned external port. Disabling/deleting the rule must produce a lifetime=0 NAT-PMP delete and remove the relay before the STUN rule/module baselines are restored. The probe uses no Internet route, public STUN service, real router, iptables or production firewall. UPnP is verified separately; never merge the two protocol claims.

For UPnP IGD mapping behavior, use `tools/lucky_upnp_ci_probe.py`. It keeps the same Docker `--internal` Lucky LAN plus isolated veth/network-namespace WAN, but replaces NAT-PMP with a bridge-scoped stdlib IGD v1 fixture. The disposable Lucky rule must use `UPnP=true`, `NatPMP=false` and `AutoOptionsFirewall=false`. Require Lucky to issue SSDP discovery, fetch the owned device description, call `GetExternalIPAddress`, and call `AddPortMapping` with protocol UDP, `NewInternalClient` equal to the disposable Lucky IP and `NewInternalPort` equal to rule `ListenPort`. The fake IGD creates only that owned userspace UDP mapping relay; require a random WAN marker to traverse mapping -> Lucky -> echo target -> Lucky -> mapping byte-for-byte. Disabling/deleting the rule must lead to `DeletePortMapping`, relay removal and full rule/module baseline restoration. In the verified Lucky 3.0.0 run, the separately configured owned STUN Binding responder received no request on this UPnP path; treat that as a runtime observation, not a general guarantee that UPnP always bypasses STUN. Never target a production IGD/router for coverage.

For Wake-on-LAN behavior coverage, use `tools/lucky_wol_ci_probe.py` rather than a real LAN host. The probe is GitHub-Actions-only and starts pinned Lucky 3.0.0 on a uniquely named Docker `--internal` bridge with **no published admin port**. Through Lucky's API it verifies the fresh WOL Server/Client are disabled, temporarily enables only the Server, and creates one owned device with a locally administered random MAC, the internal bridge broadcast address and one reserved ProbeTarget IP. Before the powered fixture exists, Lucky must converge to `State=Unreachable` / `ReachabilityState=Unreachable`. After `GET /api/wol/device/wakeup?key=<owned key>`, a raw AF_PACKET capture bound only to that TEST bridge must observe the exact standard 102-byte magic payload; only then does the CI harness start a virtual endpoint at the configured TEST IP/MAC. Lucky must subsequently converge to `State=Reachable` / `ReachabilityState=Reachable`, with the TEST IP present in `ReachableTargetList`. Current Lucky 3.0.0 emits the wake datagram on **UDP/9** even when the device `Port` field is set to another random value. `GET /api/wol/device/shutdown` has separate unauthenticated cloud evidence proving its METHOD+path reaches Lucky's authentication gate; do not enter the real shutdown handler merely for coverage. Delete the TEST device, restore Server/Client to their exact disabled baseline, and remove both disposable containers plus the bridge.

## SMB2 loopback guest behavior

Use `tools/lucky_smb_probe.py` only from a stopped SMB baseline with no configured `Users` or `PublicMountList`. The probe creates one unique Lucky-visible `/tmp/TEST-*` local root and exposes exactly one writable public local share. The temporary server must use `ListenIP=127.0.0.1`, `ListenNetwork=tcp4`, a random high port, `AutoFirewall=false`, `GuestEnable=true`, and WSDD/mDNS/NBNS all disabled. The runtime-verified public mount model is `Type / Param / DisplayName / Writable / DisableChangeWriteTable`; do not infer or document credential-bearing SMB user fields from this guest-only probe.

The verified client path is dependency-free SMB2 rather than the host curl SMB implementation. Offer only SMB 2.0.2/2.1 during NEGOTIATE; current Lucky 3.0.0 LiteSMB selects dialect `0x0210`. With the isolated guest service, raw NTLMSSP Type 1 SESSION_SETUP succeeds and returns SessionFlags containing `SMB2_SESSION_FLAG_IS_GUEST`. Require a real TREE_CONNECT to `DisplayName`, CREATE with delete-on-close, WRITE and exact READ of an in-memory random marker, then CLOSE/TREE_DISCONNECT/LOGOFF. Cross-check the backing file through Lucky local-path-browser while it is open and require it to disappear after CLOSE. The host curl build may advertise `smb/smbs`, but it sent SMB1 and LiteSMB rejected it as `client does not support SMB2`; do not install `smbclient` or Python SMB packages merely to make this probe work. Restore the exact original stopped configuration only while listener/share ownership markers still match, then remove the TEST tree.

## DLNA isolated HTTP/UPnP behavior

Use `tools/lucky_dlna_probe.py` only from a stopped DLNA baseline with an empty MountList. Do not force loopback: current Lucky 3.0.0 rejects `lo` because its DLNA implementation requires an interface that is UP, MULTICAST and has MTU > 0. The probe may select only a Docker-style `br-*` interface with a private IPv4 address, UP+MULTICAST flags and **zero attached veths**. It must never select a physical/LAN, Tailscale, WireGuard or populated Docker interface, and it must not modify firewall or network configuration.

The verified behavior is HTTP/UPnP control-plane behavior on that empty host-local bridge: one unique `/tmp/TEST-*` local mount, a random high HTTP port, `/rootDesc.xml`, ContentDirectory advertisement and a SOAP `Browse(ObjectID=0, BrowseDirectChildren)` that exposes the TEST child directory. Host-side SSDP M-SEARCH on the empty Linux bridge returned no response in the verified run; record that as an observation rather than treating it as a DLNA failure or claiming discovery success. Also do not assume `FriendlyName` changes the rootDesc friendly name merely because configure readback preserved it. Restore the original stopped configuration only while listener/interface/mount ownership markers still match, then delete the TEST tree.

## FRP STCP visitor behavior

Use `tools/lucky_frp_visitor_probe.py` for visitor behavior instead of exposing a public frps. The verified topology is entirely loopback: one TEST frps on `127.0.0.1`, one provider frpc with an STCP proxy backed by a process-local echo server, and a separate visitor frpc with an STCP visitor bound only to a random `127.0.0.1` port. FRP auth tokens and STCP `secretKey` values must be generated in memory and never printed or persisted in evidence.

For the current VisitorForm, `serverName` identifies the provider STCP proxy and the visitor shares its `secretKey`; `bindAddr/bindPort` are the local consumer endpoint. Require a real byte-for-byte roundtrip through the visitor. A PUT update through `{oldName,newVisitor}` has also been verified with both `transport.useEncryption` and `transport.useCompression` enabled, followed by a second exact roundtrip. Do not use `visitorStatuses` as the sole success signal: current Lucky 3.0.0 returned an empty visitorStatuses array while the STCP data plane was working. Explicitly delete visitor and provider proxy before deleting the three TEST FRP instances, then verify the complete instance-key baseline.

## FileBrowser local behavior

`tools/lucky_filebrowser_probe.py` verifies FileBrowser only from a stopped/disabled baseline. It creates a fresh TEST database, cache and writable local mount under one unique Lucky-visible `/tmp/TEST-*` tree, then starts HTTP on a random `127.0.0.1` tcp4 port with TLS, AutoFirewall and exec disabled. Never point this probe at an existing FileBrowser database. `/api/third/filebrowser/resetadmin` METHOD+path existence is already runtime-verified by an unauthenticated cloud probe that stops at Lucky's authentication gate; do not execute the real reset handler merely for coverage.

A fresh disposable database accepts FileBrowser's documented reset-default account/password `666/666`; this fact applies to the fresh TEST database only and is not a reason to reset or assume credentials on an existing database. The JWT returned by `/api/login` stays in process memory and is sent only as `X-Auth`. With exactly one local mount, `/api/resources/` maps directly to that backing directory. Runtime verification covers raw upload, exact content readback, PATCH rename and DELETE; current FileBrowser returns HTTP 204 for a successful delete. Before restoring the baseline configuration, require the live DB path, listener port and mount Param to still match this probe's unique TEST ownership markers, then verify the original stopped status/configuration and remove the TEST tree.

## Rclone local sync behavior

`tools/lucky_rclone_sync_probe.py` verifies Rclone's execution engine without remotes or credentials. It creates unique Lucky-visible source/destination `/tmp/TEST-*` trees and one TEST task with `SourceType=local`, `DestType=local`, `SyncMode=sync` and `CreateEmptyDirs=true`. A short-lived manual-only Cron helper creates one random marker file inside the owned source tree; a real run must reach success, propagate a source-only empty directory and copy that file. The same helper is then PUT-updated to compare the source/destination contents and creates an owned verification marker only when they match, after which the helper task/group is deleted. The Rclone task is then PUT-updated to `DryRun=true`; a second source-only directory and the post-sync verification marker must remain absent from the destination after another successful run.

The current Lucky 3.0.0 UI exposes `sync` and `bisync`, not a separate `copy` SyncMode; treat “actual copy” here as a real file copy performed by `SyncMode=sync`, not as an undocumented mode value. The compact `/api/rclone/sync/list` response intentionally omits many execution options. Use `GET /api/rclone/sync/{Key}` when validating `DryRun`, `CreateEmptyDirs`, filters, bandwidth or other detailed task fields. Do not add cloud remotes, schedules, bisync or system mounts to this probe solely for coverage. The Cron helper must remain manual-only, path-confined to the owned TEST trees, and fully removed with its group before baseline verification.

Use `tools/lucky_rclone_stop_probe.py` for running-task stop verification. It deliberately uses only a 1 MiB local TEST file with `Transfers=1`, `Checkers=1` and `BandwidthLimit=32K` so running is observable without a large workload; call stop immediately after observing `State.Status=running`. On the current Lucky 3.0.0 runtime, stop returns `ret=0` and the task leaves running, but the next State.Status is `success` with no LastError even when the throttled destination file does not exist. Do not interpret that post-stop `success` as proof of a complete transfer. The stop probe must restore both Rclone and Cron helper task/group baselines and delete both TEST trees.

Treat Rclone SystemMount as deployment-capability-sensitive. `tools/lucky_rclone_mount_ci_probe.py` is the verified behavior path: it refuses non-GitHub-Actions execution, starts pinned Lucky 3.0.0 in a disposable container with only the FUSE requirements (`SYS_ADMIN`, `/dev/fuse`, unconfined AppArmor), and keeps every Lucky remote/global/Cron/path mutation on HTTP APIs. For a `Type=local` remote, the mounted source path belongs in `SystemMount.Root`; top-level remote `Root` and StorageManagement-style `Params.LocalPath` do not substitute for it in this flow. Require source-to-mount marker visibility, mount-to-source write-through, disable-triggered unmount, remote deletion and full remote/sync/Cron/group/global/path baseline restoration. The production Lucky container remains deliberately without `SYS_ADMIN` or `/dev/fuse`; never add those privileges merely for coverage.

## Docker Compose behavior

Use `tools/lucky_docker_compose_probe.py` for bounded Compose lifecycle verification. It requires an empty Docker-task baseline, reuses a pre-existing image, creates only unique `/tmp/TEST-*` projects, sets `network_mode: none`, publishes no ports, declares no volumes, and never requests image pull/build or Docker prune. One fresh project verifies synchronous `up → down`; a second project follows the current Lucky 3.0.0 UI flow through `up-async`, task polling, `ps/config/logs`, `stop-async`, synchronous start/restart and `down-async`.

Do not treat synchronous `/api/docker/compose/up` as an idempotent re-up operation: runtime verification shows that an already existing project name returns a project-name-already-exists business error. Also distinguish Docker task cancellation from completed-history cleanup. `DELETE /api/docker/tasks/{id}` cancels an active task and cannot remove a completed task. The global `DELETE /api/docker/tasks` may clear completed history only when the pre-probe task baseline is empty and the current task-ID set exactly equals the IDs issued to the probe. Otherwise refuse the clear and preserve operator tasks.

## Docker image import/load behavior

Use `tools/lucky_docker_image_import_probe.py` for image import/load verification without pulling or building anything. It creates only a tiny raw rootfs tar inside a unique Lucky-visible `/tmp/TEST-*` directory, imports exactly one disposable image, applies a unique TEST tag, exports that owned image through `save.withoutcompression`, deletes it, then loads the saved Docker tar and requires the same image identity/tag to return. Cleanup must restore both the image inventory and helper Cron/path baselines; never retag or delete a pre-existing business image.

The current Lucky 3.0.0 image-import UI first multipart-POSTs one `file` to `/api/docker/images/upload-temp`, then POSTs `{path,cleanup:true}` to `/api/docker/images/load`. Runtime verification reached `upload-temp`, but this instance returns `Temp operation path not configured`; do not change global Docker `temp_operation_path` solely for coverage. The probe therefore records that precondition and uses its already-owned Lucky `/tmp` tar to verify `load`. Do not run local Docker image build/build-from-zip/build-from-git against the production daemon for coverage; use the GitHub-hosted disposable Lucky + isolated Docker harnesses already defined by this repository.

## Docker image build behavior

Do not run Docker image build handlers against the RS production daemon for coverage. `tools/lucky_docker_build_ci_probe.py` is the verified build harness and deliberately refuses to run unless `GITHUB_ACTIONS=true` with `RUNNER_TEMP` present. It pins the exact verified Lucky 3.0.0 image digest, publishes the fresh Lucky admin port only on runner loopback, connects only to the GitHub-hosted runner's ephemeral Docker socket, enables a random disposable OpenToken in process memory and removes all post-baseline image identities before exit.

The three build semantics are now runtime-backed. `/api/docker/images/build` takes `{dockerfile:<Dockerfile text>}` rather than a host context directory. `/api/docker/images/build-from-zip` takes `{zip_path:<Lucky-visible zip>}` and was verified with a two-file `FROM scratch` context. `/api/docker/images/build-from-git` takes `{git_url:<string>}`; CI replaces git inside the disposable Lucky container with a read-only fake clone helper that copies an owned fixture, so Lucky still executes its clone-to-build path without contacting an external Git server. ZIP and Git successful responses are exactly `{ret: integer, output: string}`. Verify newly built images by unique owned label plus marker-file content, never by merely trusting `ret=0`, and require the runner image baseline to be restored.

## Security Group + WebAuth behavior

Use `tools/lucky_security_group_probe.py` only with uniquely prefixed disposable principals/subrules and a loopback marker origin. The verified flow creates one TEST group, an in-group local user, a no-group local user, and disabled third-party/OAuth mappings without real provider tokens. BasicAuth must reject missing/wrong credentials and accept the in-group local user. WebAuth must expose the challenge/RSA login flow, accept the in-group local user into a session that reaches upstream, reject the no-group user, and generate a runtime security-group grant.

The current WebAuth login application requests `challengeId/nonce/publicKey`, encrypts plaintext `{account,password,twoFA,challengeId,nonce}` in RSA chunks of at most 120 UTF-8 bytes, joins ciphertext chunks with `.`, and POSTs `{challengeId,cipherText}`. Treat `GrantKey` as the runtime grant identifier; do not claim explicit grant deletion unless it is separately re-verified, because the earlier full E2E run discovered that using generic `Key` was wrong. For BasicAuth/WebAuth with `AuthSource=securityGroup`, current frontend behavior sets `SecurityGroupAccessMode=disabled`; `strict/append` is a separate authorization-composition mode. Cleanup must remove only TEST principals/subrules and verify the pre-existing WebService subrule set remains object-for-object unchanged.

## Third-party OAuth / OIDC isolated E2E

Treat third-party-user authorization and OAuth administrator login as separate flows. The current frontend adds/synchronizes a provider user through `GET /api/oauth/tmpcode?type=<provider>`, browser authorization, `GET /api/oauth/status`, then `GET /api/oauth/userinfo`. OAuth administrator login separately obtains `/api/login/challenge`, RSA-encrypts `{type,token,twoFA,challengeId,nonce}` in the same 120-byte chunking scheme, and POSTs only `{challengeId,cipherText}` to `/api/oauth/login`. Do not substitute tmpCode, callback code, third-party user Key or an access token for one another without runtime evidence.

Use `tools/lucky_oauth_ci_probe.py` for full third-party OIDC regression. It must remain GitHub-Actions-only and use a fresh pinned Lucky 3.0.0 container, Docker `--internal`, an owned OIDC provider/client, and a disposable Lucky WebService `oauth` rule as the relay. All Lucky changes must go through HTTP APIs. The verified management flow is tmpCode/authUrl -> authorization -> relay callback -> token/userinfo -> status(auth=true) -> Lucky userinfo -> save mapping -> disable/re-enable -> reauthorize/update. Before backend login, explicitly allow the saved third-party user Key with `ThirdAuthLoginUserList`; do not depend on ambiguous allow-all semantics.

For backend login, use a fresh authorization ticket and follow the frontend exactly: wait for `status.auth=true`, obtain `/api/login/challenge`, RSA-encrypt `{type,token,twoFA,challengeId,nonce}` in <=120-byte UTF-8 chunks, and POST `{challengeId,cipherText}` to `/api/oauth/login`. Lucky 3.0.0's frontend interceptor appends its `_` anti-replay timestamp/checksum query to both challenge and login; the verified CI path required reproducing that behavior and returned `ret=0` with a non-empty login token. Never persist tmpCode, callback code, access/refresh token, login token, client secret, disposable admin password or SafeURL. OpenToken-only `/api/oauth/tmpcode?type=oidc` may still return `ret=2`; do not infer that full OAuth E2E is unavailable from that narrower context. Do not use Playwright/Chromium, real identity providers, production OAuth clients or forged sessions.

## Cron shell behavior

`tools/lucky_cron_probe.py` verifies Cron execution without touching business tasks or external services. It requires clean TEST-prefixed ownership, creates one disposable group plus two TEST tasks, and writes only inside one Lucky-visible `/tmp/TEST-*` directory. The verified shell subtask shape is `{Type:"shell_option", Options:{shell_content:<script>}, Remark:<label>}`. `Type=8` is used for manual-only tasks, while `Type=4` with a numeric-seconds string in `TypeParams` is the current every-N-seconds schedule model.

For a whole-task manual run, `GET /api/cron/dojobs?key=<CronKey>` is mutating despite using GET. For a selected subtask, `POST /api/cron/jobs/trigger` accepts `{cronKey,jobIndex}`. The bounded runtime probe verified a manual marker, then PUT-updated the same task to `Type=4` / `TypeParams="2"` and observed the scheduler create a second marker automatically. A separate `exit 7` shell subtask was dispatched through the single-job trigger and produced a Cron failure/error log entry. Disable scheduled TEST tasks before deletion and remove only uniquely prefixed TEST tasks/groups/paths; never use this probe to call the network, toggle production services, or execute arbitrary host paths.

## Report results

Summarize what was read or changed, identify any remaining non-Lucky dependency (DNS, CDN, origin application, firewall, certificate issuance), and avoid reproducing secrets returned by Lucky responses.
