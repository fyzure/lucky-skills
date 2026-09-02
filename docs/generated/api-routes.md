---
pageClass: api-routes-page
---

# API 路由参考

> 目标版本：Lucky 3.0.0。共收录 599 个“路径 + 方法”记录。
> 此表由前端构建产物静态证据与可选的版本绑定运行时验证合并生成，不代表上游承诺的稳定公共 API；`UNKNOWN` 表示仍只有路径字面量证据。
> 当前证据等级：`runtime-verified` 499 条，`frontend-call` 100 条，其他 0 条。
> `runtime-verified` 表示目标版本上的路由/方法或受控运行时行为已有证据；它不等于“完整成功业务 E2E”，具体执行深度仍应结合该路由的 schema/runtime evidence 判断。

## `2fa`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `PUT` | `/api/2fa/setting` | `mutating` | — | `TwoFAEnable`, `TwoFAKey`, `TwoFACode` | `json` | `runtime-verified` |

## `about-content`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/about-content` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/about-content` | `mutating` | — | `version`, `display`, `cards` | `json` | `runtime-verified` |

## `baseconfigure`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/baseconfigure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/baseconfigure` | `mutating` | — | `AdminAccount`, `AdminPassword`, `AdminWebListenHttpsPort`, `AdminWebListenIP`, `AdminWebListenPort`, `AdminWebListenTLS`, `AllowAllThirdAuthUsers`, `AllowInternetaccess`, `AutoOptionsFirewall`, `BackendServerListBackup`, `BackgroundBlur`, `BackgroundColor`, `BackgroundImage`, `CatchPanic`, `ConfVer`, `CustomDNSA`, `CustomDNSB`, `CustomDNSC`, `CustomDNSD`, `CustomDNSList`, `DeviceID`, `DisableAllowAllOrigins`, `DisableModules`, `DisableNTPSync`, `DisableNTPSyncLog`, `EnableCustomBackgroundColor`, `EnableCustomBackgroundImage`, `EnableOpenToken`, `EnableStatusHistory`, `EnableThirdAuthLogin`, `FirewallInitDelay`, `ForceHTTPS`, `FrontendDisableAutoExpandLeftMenu`, `FrontendLanguage`, `FrontendTheme`, `GCPercent`, `GOMAXPROCS`, `GlobalDisableFirewallOpt`, `GlobalNoLimitCIDRs`, `HttpClientTimeout`, `IgnoreAuthInfoCheck`, `IgnoreSafeURLCheck`, `InsecureSkipVerify`, `Keys`, `LogMaxSize`, `MaxConsecutiveLoginFailures`, `OldPassword`, `OpenToken`, `OpenTokenConfirmed`, `OriginsList`, `ProxyProtocolTrustedCIDRs`, `RestartAfterPanic`, `SafeURL`, `SetGCPercent`, `StatNetInterfaceList`, `StatusHistoryRetentionDays`, `StatusHistorySampleIntervalSeconds`, `ThirdAuthLoginSkipTwoFA`, `ThirdAuthLoginUserList`, `TimeZone`, `TokenExpirationHour`, `TwoFADigits`, `TwoFAEnable`, `TwoFAKey`, `hiddenModules` | `json` | `runtime-verified` |

## `cloudflared`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/cloudflared/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/cloudflared/list` | `mutating` | — | `Key`, `Remark`, `Enable`, `Type`, `Params` | `json` | `runtime-verified` |
| `PUT` | `/api/cloudflared/list` | `mutating` | — | `Key`, `Remark`, `Enable`, `Type`, `Params` | `json` | `runtime-verified` |
| `DELETE` | `/api/cloudflared/list/{param}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/cloudflared/list/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/cloudflared/list/{param}/{param2}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/cloudflared/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `PUT` | `/api/cloudflared/orderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/cloudflared/{param}/cname/check` | `read-only` | `hostname` | — | `json` | `frontend-call` |
| `POST` | `/api/cloudflared/{param}/cname/create` | `mutating` | — | `hostname`, `proxied` | `json` | `runtime-verified` |
| `DELETE` | `/api/cloudflared/{param}/cname/delete` | `dangerous` | `hostname` | — | `json` | `frontend-call` |
| `DELETE` | `/api/cloudflared/{param}/ingress` | `mutating` | `hostname`, `path` | — | `json` | `frontend-call` |
| `GET` | `/api/cloudflared/{param}/ingress` | `read-only` | — | — | `json` | `frontend-call` |
| `POST` | `/api/cloudflared/{param}/ingress` | `mutating` | — | `hostname`, `path`, `service`, `originRequest` | `json` | `runtime-verified` |
| `PUT` | `/api/cloudflared/{param}/ingress` | `mutating` | — | `oldHostname`, `oldPath`, `newRule` | `json` | `runtime-verified` |
| `GET` | `/api/cloudflared/{param}/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/cloudflared/{param}/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |

## `configure`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/configure` | `dangerous` | — | — | `blob` | `runtime-verified` |
| `POST` | `/api/configure` | `dangerous` | — | — | `json` | `runtime-verified` |

## `coraza`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/coraza/OWASPCoreRuleset` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/coraza/instancelist` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/coraza/instanceorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/coraza/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/coraza/list` | `mutating` | — | `Key`, `Name`, `Enable`, `InboundScoreThreshold`, `OutboundScoreThreshold`, `CorazaWAFConfigList`, `RuleExclusions` | `json` | `runtime-verified` |
| `PUT` | `/api/coraza/list` | `mutating` | — | `Key`, `Name`, `Enable`, `InboundScoreThreshold`, `OutboundScoreThreshold`, `CorazaWAFConfigList`, `RuleExclusions` | `json` | `runtime-verified` |
| `DELETE` | `/api/coraza/list/{param}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/coraza/list/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/coraza/list/{param}/{param2}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/coraza/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |

## `cron`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/cron/dojobs` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/cron/enable` | `mutating` | `enable`, `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/cron/expressioncheck` | `read-only` | `expression` | — | `json` | `runtime-verified` |
| `DELETE` | `/api/cron/groups` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/cron/groups` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/cron/groups` | `mutating` | — | `Name` | `json` | `runtime-verified` |
| `PUT` | `/api/cron/groups` | `mutating` | — | `Key`, `Name` | `json` | `runtime-verified` |
| `PUT` | `/api/cron/groups/collapsed` | `mutating` | — | `collapsed`, `key` | `json` | `runtime-verified` |
| `GET` | `/api/cron/groups/collapsed/states` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/cron/groups/orderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/cron/groups/taskcount` | `read-only` | `groupKey` | — | `json` | `runtime-verified` |
| `POST` | `/api/cron/jobs/trigger` | `mutating` | — | `cronKey`, `jobIndex` | `json` | `runtime-verified` |
| `GET` | `/api/cron/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/cron/list` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/cron/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/cron/list` | `mutating` | — | `Key`, `Name`, `Enable`, `OtherKey`, `Type`, `TypeParams`, `GroupKey`, `ExecSecond`, `ExecMinute`, `ExecHour`, `Jobs`, `Parallel`, `IOT_DianDeng_Enable`, `IOT_DianDeng_AUTHKEY`, `IOT_DianDeng_InsecureSkipVerify`, `IOT_DianDengVoiceAssistantTriggerCondition`, `IOT_DianDengBindComponentEnable`, `IOT_DianDengBindComponentTriggerCondition`, `IOT_DianDengBindComponent`, `IOT_DianDengBindComponentState`, `IOT_DianDengBindComponentType`, `IOT_Bemfa_Enable`, `IOT_Bemfa_SecretKey`, `IOT_Bemfa_Topic`, `IOT_BemfaVoiceAssistantTriggerCondition`, `IOT_Bemfa_InsecureSkipVerify` | `json` | `runtime-verified` |
| `PUT` | `/api/cron/list` | `mutating` | — | `Key`, `Name`, `Enable`, `OtherKey`, `Type`, `TypeParams`, `GroupKey`, `ExecSecond`, `ExecMinute`, `ExecHour`, `Jobs`, `Parallel`, `IOT_DianDeng_Enable`, `IOT_DianDeng_AUTHKEY`, `IOT_DianDeng_InsecureSkipVerify`, `IOT_DianDengVoiceAssistantTriggerCondition`, `IOT_DianDengBindComponentEnable`, `IOT_DianDengBindComponentTriggerCondition`, `IOT_DianDengBindComponent`, `IOT_DianDengBindComponentState`, `IOT_DianDengBindComponentType`, `IOT_Bemfa_Enable`, `IOT_Bemfa_SecretKey`, `IOT_Bemfa_Topic`, `IOT_BemfaVoiceAssistantTriggerCondition`, `IOT_Bemfa_InsecureSkipVerify` | `json` | `runtime-verified` |
| `GET` | `/api/cron/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `PUT` | `/api/cron/taskgrouporderupdate` | `mutating` | — | `tasksMap`, `orderList` | `json` | `runtime-verified` |

## `ddns`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `DELETE` | `/api/ddns` | `mutating` | `key` | — | `json` | `frontend-call` |
| `POST` | `/api/ddns` | `mutating` | — | `DNS`, `DUID`, `DebugMode`, `DiaglogShowMode`, `Domains`, `Enable`, `Expanded`, `FirstCheckDelay`, `GetIPCommand`, `GetType`, `GlobalWebhook`, `HttpClientTimeout`, `IPReg`, `IPSectionExpanded`, `IngoreWebhookVariablesNotFound`, `IngoreWebhookVariablesNotFoundList`, `InsecureSkipVerify`, `Intervals`, `NetInterface`, `Records`, `RetryCount`, `RetryInterval`, `TTL`, `TaskKey`, `TaskName`, `TaskType`, `URL`, `V4GetIPScript`, `V4NetInterface`, `V4NetInterfaceIPReg`, `V4QueryIPEnable`, `V4QueryIPType`, `V4QueryUrl`, `V6DUID`, `V6GetIPScript`, `V6NetInterface`, `V6NetInterfaceIPReg`, `V6QueryIPEnable`, `V6QueryIPType`, `V6QueryUrl`, `WebHookTimeout`, `WebhookDisableCallbackSuccessContentCheck`, `WebhookEnable`, `WebhookHeaders`, `WebhookInsecureSkipVerify`, `WebhookLocalAddr`, `WebhookMethod`, `WebhookNetworkType`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyPassword`, `WebhookProxyUser`, `WebhookRequestBody`, `WebhookSuccessContent`, `WebhookURL` | `json` | `runtime-verified` |
| `PUT` | `/api/ddns` | `mutating` | `key` | `DNS`, `DUID`, `DebugMode`, `DiaglogShowMode`, `Domains`, `Enable`, `Expanded`, `FirstCheckDelay`, `GetIPCommand`, `GetType`, `GlobalWebhook`, `HttpClientTimeout`, `IPReg`, `IPSectionExpanded`, `IngoreWebhookVariablesNotFound`, `IngoreWebhookVariablesNotFoundList`, `InsecureSkipVerify`, `Intervals`, `NetInterface`, `Records`, `RetryCount`, `RetryInterval`, `TTL`, `TaskKey`, `TaskName`, `TaskType`, `URL`, `V4GetIPScript`, `V4NetInterface`, `V4NetInterfaceIPReg`, `V4QueryIPEnable`, `V4QueryIPType`, `V4QueryUrl`, `V6DUID`, `V6GetIPScript`, `V6NetInterface`, `V6NetInterfaceIPReg`, `V6QueryIPEnable`, `V6QueryIPType`, `V6QueryUrl`, `WebHookTimeout`, `WebhookDisableCallbackSuccessContentCheck`, `WebhookEnable`, `WebhookHeaders`, `WebhookInsecureSkipVerify`, `WebhookLocalAddr`, `WebhookMethod`, `WebhookNetworkType`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyPassword`, `WebhookProxyUser`, `WebhookRequestBody`, `WebhookSuccessContent`, `WebhookURL` | `json` | `runtime-verified` |
| `GET` | `/api/ddns/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ddns/configure` | `mutating` | — | `CustomDomainSuffix`, `CustomFullDomain`, `Enable`, `FirstCheckDelay`, `Intervals`, `LogLevel`, `RetryCount`, `RetryInterval`, `WebHookTimeout`, `WebhookDisableCallbackSuccessContentCheck`, `WebhookEnable`, `WebhookHeaders`, `WebhookInsecureSkipVerify`, `WebhookLocalAddr`, `WebhookMethod`, `WebhookNetworkType`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyPassword`, `WebhookProxyUser`, `WebhookRequestBody`, `WebhookSuccessContent`, `WebhookURL` | `json` | `runtime-verified` |
| `GET` | `/api/ddns/credential-sources` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ddns/enable` | `mutating` | `enable`, `key` | — | `json` | `frontend-call` |
| `GET` | `/api/ddns/expanded` | `mutating` | `expanded`, `key` | — | `json` | `frontend-call` |
| `GET` | `/api/ddns/getipfromcmdtest` | `dangerous` | `command`, `iptype` | — | `json` | `frontend-call` |
| `GET` | `/api/ddns/ipsectionexpanded` | `mutating` | `expanded`, `key` | — | `json` | `frontend-call` |
| `GET` | `/api/ddns/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ddns/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/ddns/manualSync/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ddns/odhcpdclients` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ddns/recordOrderadjustment/{param}` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/ddns/task/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ddns/taskorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `POST` | `/api/ddns/webhooktest` | `mutating` | `key` | `WebhookURL`, `WebhookMethod`, `WebhookRequestBody`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyUser`, `RetryCount`, `RetryInterval`, `WebhookProxyPassword`, `WebhookHeaders`, `WebhookSuccessContent`, `WebhookDisableCallbackSuccessContentCheck` | `json` | `runtime-verified` |
| `DELETE` | `/api/ddns/{param}/{param2}` | `mutating` | — | `deleteFromProvider` | `json` | `runtime-verified` |
| `PUT` | `/api/ddns/{param}/{param2}/option/{param3}` | `mutating` | — | — | `json` | `frontend-call` |

## `ddnstasklist`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/ddnstasklist` | `read-only` | — | — | `json` | `runtime-verified` |

## `dlnaservice`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/dlnaservice/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/dlnaservice/configure` | `mutating` | — | `Enable`, `ListenIP`, `ListenPort`, `NetInterfaceList`, `FriendlyName`, `DeviceUUID`, `MountList` | `json` | `runtime-verified` |
| `GET` | `/api/dlnaservice/lastlogs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/dlnaservice/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/dlnaservice/status` | `read-only` | — | — | `json` | `runtime-verified` |

## `docker`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `POST` | `/api/docker/compose/backup` | `dangerous` | — | `project_name`, `project_path` | `json` | `runtime-verified` |
| `GET` | `/api/docker/compose/backup/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/config` | `mutating` | — | `project_path` | `json` | `runtime-verified` |
| `GET` | `/api/docker/compose/containers-for-cron` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/discover` | `mutating` | — | `scan_path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/dockerfile` | `mutating` | — | `project_path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/down` | `dangerous` | — | `project_name`, `project_path`, `config_file_name`, `remove_volumes` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/down-async` | `mutating` | — | `project_name`, `project_path`, `config_file_name`, `remove_volumes` | `json` | `runtime-verified` |
| `GET` | `/api/docker/compose/projects` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/read-file` | `mutating` | — | `filename`, `working_dir` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/restart` | `dangerous` | — | `project_name`, `project_path`, `config_file_name` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/restore` | `dangerous` | — | `file`, `target_path`, `project_name`, `auto_start`, `config_file_name` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/start` | `dangerous` | — | `project_name`, `project_path`, `config_file_name` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/stop` | `dangerous` | — | `project_name`, `project_path`, `config_file_name` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/stop-async` | `mutating` | — | `project_name`, `project_path`, `config_file_name` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/up` | `mutating` | — | `project_name`, `project_path`, `config_file_name`, `working_dir`, `compose_content`, `force_recreate`, `build` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/up-async` | `mutating` | — | `project_name`, `project_path`, `config_file_name`, `working_dir`, `compose_content`, `force_recreate`, `build` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/update-config` | `mutating` | — | `content`, `project_path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/update-dockerfile` | `mutating` | — | `content`, `project_path` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/compose/{param}/backup/cancel` | `dangerous` | — | — | `json` | `frontend-call` |
| `DELETE` | `/api/docker/compose/{param}/backups` | `mutating` | — | `backup` | `json` | `runtime-verified` |
| `GET` | `/api/docker/compose/{param}/backups` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/compose/{param}/backups/all` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/compose/{param}/backups/download.tar.gz` | `read-only` | `backup` | — | `blob` | `frontend-call` |
| `POST` | `/api/docker/compose/{param}/backups/restore` | `dangerous` | — | `backup` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/{param}/backups/upload` | `dangerous` | — | `file` | `json` | `runtime-verified` |
| `POST` | `/api/docker/compose/{param}/logs` | `mutating` | — | `project_name`, `project_path`, `services`, `tail`, `timestamps`, `follow` | `json` | `runtime-verified` |
| `GET` | `/api/docker/compose/{param}/ps` | `read-only` | `name`, `path` | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/config` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/config` | `mutating` | — | `docker_host`, `volume_backup_path`, `volume_backup_default_max`, `volume_backup_max_per_volume`, `volume_backup_stop_containers`, `volume_backup_stop_containers_per_volume`, `compose_backup_path`, `compose_backup_default_max`, `compose_backup_max_per_project`, `compose_discover_path`, `temp_operation_path`, `quick_access_host`, `container_view_mode`, `container_show_stopped`, `container_selected_custom_group` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/container-groups` | `mutating` | `key` | — | `json` | `frontend-call` |
| `GET` | `/api/docker/container-groups` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/container-groups` | `mutating` | — | `Name` | `json` | `runtime-verified` |
| `PUT` | `/api/docker/container-groups` | `mutating` | — | `Key`, `Name` | `json` | `runtime-verified` |
| `PUT` | `/api/docker/container-groups/collapsed` | `mutating` | — | `collapsed`, `key` | `json` | `runtime-verified` |
| `GET` | `/api/docker/container-groups/collapsed/states` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/container-groups/count` | `read-only` | `groupKey` | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers` | `read-only` | `all`, `filters`, `includeNetworkMode`, `includeStats` | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers` | `mutating` | — | `name`, `config`, `hostConfig` | `json` | `runtime-verified` |
| `PUT` | `/api/docker/containers/group` | `mutating` | — | `containerName`, `groupKey` | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/sort-config` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/docker/containers/sort/compose` | `mutating` | — | `containerOrders`, `groupOrder` | `json` | `runtime-verified` |
| `PUT` | `/api/docker/containers/sort/custom` | `mutating` | — | `containerGroupMap`, `containerOrders`, `groupOrder` | `json` | `runtime-verified` |
| `PUT` | `/api/docker/containers/sort/flat` | `mutating` | — | `orderList` | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/stats-cached` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/switch-version` | `mutating` | — | `container_ids`, `target_image_ref` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/containers/{param}` | `mutating` | `force`, `remove_volumes` | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/commit` | `dangerous` | — | `repository`, `tag`, `comment` | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}/compose-config` | `read-only` | — | — | `json` | `frontend-call` |
| `POST` | `/api/docker/containers/{param}/copy` | `dangerous` | — | `name` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/edit` | `dangerous` | — | `name`, `config`, `hostConfig`, `auto_start`, `remove_old` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/export` | `dangerous` | — | — | `blob` | `frontend-call` |
| `DELETE` | `/api/docker/containers/{param}/files` | `mutating` | — | `path`, `recursive` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/chmod` | `dangerous` | — | `path`, `permissions` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/compress` | `dangerous` | — | `output_name`, `output_path`, `paths` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/compress-async` | `mutating` | — | `output_name`, `output_path`, `paths` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/copy` | `dangerous` | — | `dst_path`, `src_path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/decompress` | `dangerous` | — | `file_path`, `output_path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/decompress-async` | `mutating` | — | `file_path`, `output_path` | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}/files/download` | `read-only` | `path` | — | `blob` | `frontend-call` |
| `GET` | `/api/docker/containers/{param}/files/list` | `read-only` | `path` | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/mkdir` | `mutating` | — | `path` | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}/files/preview-archive` | `read-only` | `path` | — | `json` | `frontend-call` |
| `GET` | `/api/docker/containers/{param}/files/read` | `read-only` | `path` | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/rename` | `dangerous` | — | `new_path`, `old_path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/search` | `read-only` | — | `file_type`, `keyword`, `max_depth`, `max_result`, `path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/touch` | `mutating` | — | `path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/upload` | `dangerous` | — | `file`, `path` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/files/write` | `dangerous` | — | `content`, `path` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/containers/{param}/label` | `mutating` | — | — | `json` | `frontend-call` |
| `POST` | `/api/docker/containers/{param}/label` | `mutating` | — | `label` | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}/logs` | `read-only` | `tail`, `timestamps` | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/pause` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/containers/{param}/processes` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/rename` | `dangerous` | — | `name` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/restart` | `dangerous` | — | `timeout` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/start` | `dangerous` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}/stats` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}/stats-cached` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/stop` | `dangerous` | — | `timeout` | `json` | `runtime-verified` |
| `POST` | `/api/docker/containers/{param}/unpause` | `dangerous` | — | — | `json` | `frontend-call` |
| `POST` | `/api/docker/containers/{param}/upgrade` | `dangerous` | — | `object` | `json` | `runtime-verified` |
| `GET` | `/api/docker/containers/{param}/upgrade-check` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/disk-usage` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/images` | `read-only` | `all` | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/backup-tag` | `mutating` | — | `image_ref` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/build` | `mutating` | — | `dockerfile` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/build-from-git` | `mutating` | — | `git_url` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/build-from-zip` | `mutating` | — | `zip_path` | `json` | `runtime-verified` |
| `GET` | `/api/docker/images/containers` | `read-only` | `image_ref` | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/import` | `dangerous` | — | `source` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/load` | `mutating` | — | `path`, `cleanup` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/pull` | `mutating` | — | `image`, `tag` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/pull-async` | `mutating` | — | `architecture`, `image`, `tag` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/pull-with-backup` | `mutating` | — | `architecture`, `backup_tag`, `image_ref` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/pull-with-backup-async` | `mutating` | — | `architecture`, `backup_tag`, `image_ref` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/push` | `mutating` | — | `image`, `tag` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/images/remove` | `dangerous` | `force`, `noprune`, `tag` | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/remove-saved-digest` | `mutating` | — | `image_id` | `json` | `runtime-verified` |
| `GET` | `/api/docker/images/save.withoutcompression` | `dangerous` | `imageid` | — | `blob` | `runtime-verified` |
| `POST` | `/api/docker/images/search` | `read-only` | — | `limit`, `term` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/upgrade-check` | `mutating` | — | `image_ref` | `json` | `runtime-verified` |
| `GET` | `/api/docker/images/upgrade-check-ws` | `mutating` | — | — | `websocket` | `runtime-verified` |
| `POST` | `/api/docker/images/upgrade-containers` | `mutating` | — | `container_ids`, `image_ref`, `upgrade_compose`, `upgrade_standalone` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/upgrade-containers-async` | `mutating` | — | `container_ids`, `image_ref`, `upgrade_compose`, `upgrade_standalone` | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/upgrade-dismiss` | `mutating` | — | `image_id`, `image_ref` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/images/upgrade-status` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/images/upgrade-status` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/upload-temp` | `mutating` | — | `file` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/images/{param}` | `mutating` | `force`, `noprune` | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/images/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/images/{param}/filesystem` | `read-only` | `path` | — | `json` | `frontend-call` |
| `GET` | `/api/docker/images/{param}/history` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/images/{param}/tag` | `mutating` | — | `repository`, `tag` | `json` | `runtime-verified` |
| `GET` | `/api/docker/images/{param}/tags` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/info` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/labels` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/labels/{param}/containers` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/monitor/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/networks` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/networks` | `mutating` | — | `name`, `driver`, `internal`, `enable_ipv6`, `attachable`, `options`, `ipam` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/networks/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `POST` | `/api/docker/prune` | `dangerous` | — | `all`, `volumes` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/registry/mirrors` | `mutating` | — | `mirror` | `json` | `runtime-verified` |
| `GET` | `/api/docker/registry/mirrors` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/registry/mirrors` | `mutating` | — | `mirror` | `json` | `runtime-verified` |
| `GET` | `/api/docker/self-container` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/summary` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/system-info` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/tasks` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/tasks` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/tasks/image-pull/active` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/tasks/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/tasks/{param}` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/docker/version` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/volumes` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/volumes` | `mutating` | — | `name`, `driver` | `json` | `runtime-verified` |
| `GET` | `/api/docker/volumes/backup/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/docker/volumes/export` | `dangerous` | `name` | — | `blob` | `frontend-call` |
| `POST` | `/api/docker/volumes/import` | `dangerous` | — | `file`, `volume_name`, `driver` | `json` | `runtime-verified` |
| `DELETE` | `/api/docker/volumes/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `POST` | `/api/docker/volumes/{param}/backup` | `dangerous` | — | — | `json` | `frontend-call` |
| `DELETE` | `/api/docker/volumes/{param}/backup/cancel` | `dangerous` | — | — | `json` | `frontend-call` |
| `DELETE` | `/api/docker/volumes/{param}/backups` | `mutating` | — | `backup` | `json` | `runtime-verified` |
| `GET` | `/api/docker/volumes/{param}/backups` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/docker/volumes/{param}/backups/restore` | `dangerous` | — | `backup` | `json` | `runtime-verified` |
| `POST` | `/api/docker/volumes/{param}/backups/upload` | `dangerous` | — | `file` | `json` | `runtime-verified` |

## `frontend-preferences`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `PUT` | `/api/frontend-preferences` | `mutating` | — | `theme`, `language` | `json` | `runtime-verified` |

## `frp`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/frp/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/frp/list` | `mutating` | — | `Key`, `Remark`, `Enable`, `Type`, `ConfigMode`, `ConfigText`, `Params`, `Proxies`, `Visitors` | `json` | `runtime-verified` |
| `PUT` | `/api/frp/list` | `mutating` | — | `Key`, `Remark`, `Enable`, `Type`, `ConfigMode`, `ConfigText`, `Params`, `Proxies`, `Visitors` | `json` | `runtime-verified` |
| `DELETE` | `/api/frp/list/{param}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/frp/list/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/frp/list/{param}/{param2}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/frp/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `PUT` | `/api/frp/orderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/frp/{param}/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/frp/{param}/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/frp/{param}/proxies` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/frp/{param}/proxies` | `mutating` | — | `allowUsers`, `annotations`, `bandwidthLimit`, `bandwidthLimitMode`, `customDomains`, `disabled`, `healthCheckHTTPHeaders`, `healthCheckInterval`, `healthCheckMaxFailed`, `healthCheckPath`, `healthCheckTimeout`, `healthCheckType`, `hostHeaderRewrite`, `httpPassword`, `httpUser`, `loadBalancerGroup`, `loadBalancerGroupKey`, `localIP`, `localPort`, `locations`, `metadatas`, `multiplexer`, `name`, `natTraversal`, `plugin`, `pluginCrtPath`, `pluginEnableHttp2`, `pluginHostHeaderRewrite`, `pluginHttpPassword`, `pluginHttpUser`, `pluginKeyPath`, `pluginLocalAddr`, `pluginLocalPath`, `pluginRequestHeaders`, `pluginStripPrefix`, `pluginUnixPath`, `proxyProtocolVersion`, `remotePort`, `requestHeaders`, `responseHeaders`, `routeByHTTPUser`, `secretKey`, `subdomain`, `type`, `useCompression`, `useEncryption` | `json` | `runtime-verified` |
| `PUT` | `/api/frp/{param}/proxies` | `mutating` | — | `oldName`, `newProxy` | `json` | `runtime-verified` |
| `DELETE` | `/api/frp/{param}/proxies/{param2}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/frp/{param}/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/frp/{param}/visitors` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/frp/{param}/visitors` | `mutating` | — | `bindAddr`, `bindPort`, `disabled`, `fallbackTimeoutMs`, `fallbackTo`, `keepTunnelOpen`, `maxRetriesAnHour`, `minRetryInterval`, `name`, `natTraversal`, `plugin`, `protocol`, `secretKey`, `serverName`, `serverUser`, `transport`, `type` | `json` | `runtime-verified` |
| `PUT` | `/api/frp/{param}/visitors` | `mutating` | — | `oldName`, `newVisitor` | `json` | `runtime-verified` |
| `DELETE` | `/api/frp/{param}/visitors/{param2}` | `mutating` | — | — | `json` | `runtime-verified` |

## `ftpserver`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/ftpserver/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ftpserver/configure` | `mutating` | — | `ActiveConnectionsCheck`, `ActiveTransferPortNon20`, `AdvancedParametersShow`, `AutoFireWall`, `ConfVersion`, `ConnectionTimeout`, `DefaultTransferType`, `DisableActiveMode`, `DisableLISTArgs `, `DisableMFMT`, `DisableMLSD`, `DisableMLST`, `DisableSTAT`, `DisableSYST`, `DisableSite`, `Enable`, `EnableCOMB`, `EnableHASH`, `IdleTimeout`, `Network`, `PassivePortEnd`, `PassivePortStart`, `PasvConnectionsCheck`, `Port`, `TLSRequired`, `Users` | `json` | `runtime-verified` |
| `GET` | `/api/ftpserver/lastlogs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/ftpserver/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/ftpserver/status` | `read-only` | — | — | `json` | `runtime-verified` |

## `iconlib`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/iconlib/icon` | `read-only` | `path` | — | `blob` | `runtime-verified` |
| `GET` | `/api/iconlib/icons` | `read-only` | `source` | — | `json` | `runtime-verified` |
| `GET` | `/api/iconlib/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/iconlib/search` | `read-only` | `keyword`, `source` | — | `json` | `runtime-verified` |
| `GET` | `/api/iconlib/sources` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/iconlib/sources` | `mutating` | — | `Alias`, `Type`, `Path`, `RcloneKey`, `RcloneRoot`, `StoreKey`, `StoreRoot`, `Enable`, `Description` | `json` | `runtime-verified` |
| `PUT` | `/api/iconlib/sources` | `mutating` | — | `Alias`, `Type`, `Path`, `RcloneKey`, `RcloneRoot`, `StoreKey`, `StoreRoot`, `Enable`, `Description` | `json` | `runtime-verified` |
| `DELETE` | `/api/iconlib/sources/{param}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/iconlib/sources/{param}/enable/{param2}` | `mutating` | — | — | `json` | `runtime-verified` |

## `info`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/info` | `read-only` | — | — | `json` | `runtime-verified` |

## `ipdb`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/ipdb/avalidDBFiles` | `read-only` | `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/ipdb/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ipdb/configure` | `mutating` | — | `CustomIPDBPath` | `json` | `runtime-verified` |
| `DELETE` | `/api/ipdb/dbfile` | `mutating` | `file`, `key` | — | `json` | `frontend-call` |
| `GET` | `/api/ipdb/download` | `dangerous` | — | — | `blob` | `runtime-verified` |
| `PUT` | `/api/ipdb/instanceorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `DELETE` | `/api/ipdb/item` | `mutating` | `key` | — | `json` | `frontend-call` |
| `POST` | `/api/ipdb/item` | `mutating` | — | `Key`, `Remark`, `Enable`, `Format`, `FilePath`, `SupportTypes`, `BufferType`, `DBParam1` | `json` | `runtime-verified` |
| `PUT` | `/api/ipdb/item` | `mutating` | — | `Key`, `Remark`, `Enable`, `Format`, `FilePath`, `SupportTypes`, `BufferType`, `DBParam1` | `json` | `runtime-verified` |
| `GET` | `/api/ipdb/item/{param}/{param2}` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ipdb/items` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ipdb/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/ipdb/query` | `read-only` | `ip` | — | `json` | `frontend-call` |

## `ipfliter`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/ipfliter/autorecordipconf` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ipfliter/autorecordipconf` | `mutating` | — | `SafeURL`, `BasicAccount`, `BasicPassword` | `json` | `runtime-verified` |
| `GET` | `/api/ipfliter/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ipfliter/list/subrulelist/order/{param}` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/ipfliter/list/subrulelist/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/ipfliter/list/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ipfliter/list/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/ipfliter/list/{param}` | `mutating` | — | `Key`, `Remark`, `Enable`, `Type`, `LongTermValid`, `ValidTimestamp`, `IPTextSets`, `IPDBKeyWords`, `AutoDeleteOnExpiry`, `InvalidIPTextEntryCount`, `InvalidIPTextEntriesPreview`, `IPInfoKeywordFilter` | `json` | `runtime-verified` |
| `PUT` | `/api/ipfliter/list/{param}` | `mutating` | — | `Key`, `Name`, `Action`, `SubRuleList`, `AutoRecordTxtLimit`, `AutoRecordMemLimit` | `json` | `runtime-verified` |
| `DELETE` | `/api/ipfliter/list/{param}/{param2}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ipfliter/list/{param}/{param2}` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ipfliter/list/{param}/{param2}` | `mutating` | — | `Key`, `Remark`, `Enable`, `Type`, `LongTermValid`, `ValidTimestamp`, `IPTextSets`, `IPDBKeyWords`, `AutoDeleteOnExpiry`, `InvalidIPTextEntryCount`, `InvalidIPTextEntriesPreview`, `IPInfoKeywordFilter` | `json` | `runtime-verified` |
| `POST` | `/api/ipfliter/list/{param}/{param2}/match` | `mutating` | — | `ip` | `json` | `runtime-verified` |
| `GET` | `/api/ipfliter/list/{param}/{param2}/{param3}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ipfliter/listlite` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ipfliter/oneclickrecord` | `mutating` | `ip` | — | `json` | `frontend-call` |
| `GET` | `/api/ipfliter/porttrap/blockedips` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `POST` | `/api/ipfliter/porttrap/blockedips/batch-delete` | `mutating` | — | `ips` | `json` | `runtime-verified` |
| `POST` | `/api/ipfliter/porttrap/blockedips/clear` | `dangerous` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ipfliter/porttrap/blockedips/export` | `dangerous` | — | — | `json` | `frontend-call` |
| `POST` | `/api/ipfliter/porttrap/blockedips/refresh-ipinfo` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ipfliter/porttrap/blockedips/search` | `read-only` | `page`, `pageSize`, `q`, `type` | — | `json` | `runtime-verified` |
| `DELETE` | `/api/ipfliter/porttrap/blockedips/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ipfliter/porttrap/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/ipfliter/porttrap/stats` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/ipfliter/porttrap/stats/reset` | `dangerous` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ipfliter/porttrapconf` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ipfliter/porttrapconf` | `mutating` | — | `AllowRuleKeys`, `DefaultAllowIPs`, `Enable`, `IPv6PrefixLen`, `Script`, `ScriptEnable`, `ScriptTriggerInterval`, `TCPPorts`, `TargetRuleKey`, `UDPPorts`, `WebhookBody`, `WebhookDisableCallbackSuccessContentCheck`, `WebhookEnable`, `WebhookHeaders`, `WebhookMethod`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyPassword`, `WebhookProxyUser`, `WebhookRetryCount`, `WebhookRetryInterval`, `WebhookSuccessContent`, `WebhookTimeout`, `WebhookTriggerInterval`, `WebhookURL` | `json` | `runtime-verified` |

## `ipregtest`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/ipregtest` | `read-only` | `ipreg`, `iptype`, `netinterface` | — | `json` | `runtime-verified` |

## `local-path-browser`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/local-path-browser/list` | `read-only` | `path`, `showFiles` | — | `json` | `runtime-verified` |
| `POST` | `/api/local-path-browser/mkdir` | `mutating` | — | `path` | `json` | `runtime-verified` |
| `DELETE` | `/api/local-path-browser/path` | `dangerous` | — | `confirmName`, `path` | `json` | `runtime-verified` |
| `PUT` | `/api/local-path-browser/rename` | `dangerous` | — | `newName`, `path` | `json` | `runtime-verified` |
| `GET` | `/api/local-path-browser/roots` | `read-only` | — | — | `json` | `runtime-verified` |

## `login`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `POST` | `/api/login` | `mutating` | — | `challengeId`, `cipherText` | `json` | `runtime-verified` |
| `GET` | `/api/login/challenge` | `read-only` | — | — | `json` | `runtime-verified` |

## `logout`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `PUT` | `/api/logout` | `mutating` | — | — | `json` | `frontend-call` |

## `logs`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/logs` | `read-only` | `pre` | — | `json` | `runtime-verified` |

## `logscenter`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/logscenter/query` | `read-only` | — | — | `json` | `runtime-verified` |

## `lucky`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `PUT` | `/api/lucky/service` | `mutating` | `option` | — | `json` | `frontend-call` |

## `modules`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `PUT` | `/api/modules/hidden` | `mutating` | — | `hiddenModules` | `json` | `runtime-verified` |
| `GET` | `/api/modules/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/modules/{param}/2fa/config` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/modules/{param}/2fa/config` | `mutating` | — | `enable`, `key`, `secret`, `validated`, `code`, `oldSecret`, `oldCode` | `json` | `runtime-verified` |
| `GET` | `/api/modules/{param}/2fa/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/modules/{param}/verify2fa` | `mutating` | — | `code` | `json` | `runtime-verified` |

## `natdetect`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/natdetect/ws` | `mutating` | — | — | `websocket` | `runtime-verified` |

## `netinterfaces`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/netinterfaces` | `read-only` | — | — | `json` | `runtime-verified` |

## `oauth`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `POST` | `/api/oauth/login` | `mutating` | — | `challengeId`, `cipherText` | `json` | `runtime-verified` |
| `GET` | `/api/oauth/status` | `read-only` | `code`, `type` | — | `json` | `frontend-call` |
| `GET` | `/api/oauth/tmpcode` | `dangerous` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/oauth/userinfo` | `read-only` | `code`, `type` | — | `json` | `frontend-call` |

## `password`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `PUT` | `/api/password/verify` | `mutating` | — | `oldPassword` | `json` | `runtime-verified` |

## `portforward`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `DELETE` | `/api/portforward` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `POST` | `/api/portforward` | `mutating` | — | `Name`, `Key`, `DiaglogShowMode`, `ForwardTypes`, `ListenAddress`, `ListenPorts`, `TargetAddressList`, `TargetPorts`, `Enable`, `LogLevel`, `OpenFirewallPorts`, `LogOutputToConsole`, `AccessLogMaxNum`, `WebListShowLastLogMaxCount`, `Options`, `LogStreamSettings` | `json` | `runtime-verified` |
| `PUT` | `/api/portforward` | `mutating` | — | `Name`, `Key`, `DiaglogShowMode`, `ForwardTypes`, `ListenAddress`, `ListenPorts`, `TargetAddressList`, `TargetPorts`, `Enable`, `LogLevel`, `OpenFirewallPorts`, `LogOutputToConsole`, `AccessLogMaxNum`, `WebListShowLastLogMaxCount`, `Options`, `LogStreamSettings` | `json` | `runtime-verified` |
| `GET` | `/api/portforward/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/portforward/configure` | `mutating` | — | `ConfVer`, `ConnectionDownloadRateLimit`, `ConnectionDownloadRateLimitEnabled`, `ConnectionUploadRateLimit`, `ConnectionUploadRateLimitEnabled`, `Enable`, `IPConnectionsLimit`, `IPDownloadRateLimit`, `IPDownloadRateLimitEnabled`, `IPMaxConnections`, `IPUploadRateLimit`, `IPUploadRateLimitEnabled`, `Nolimit`, `PortForwardsLimit`, `TCPPortforwardMaxConnections`, `UDPReadTargetDataMaxgoroutineCount` | `json` | `runtime-verified` |
| `GET` | `/api/portforward/enable` | `mutating` | `enable`, `key` | — | `json` | `frontend-call` |
| `PUT` | `/api/portforward/ruleorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/portforward/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/portforward/{param}/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/portforward/{param}/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |

## `portforwards`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/portforwards` | `read-only` | — | — | `json` | `runtime-verified` |

## `portforwards_lite`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/portforwards_lite` | `read-only` | — | — | `json` | `runtime-verified` |

## `rclone`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/rclone/globalconfig` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/rclone/globalconfig` | `mutating` | — | `DefaultCaCheDir`, `UploadFileTmpDir` | `json` | `runtime-verified` |
| `PUT` | `/api/rclone/itemorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/rclone/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/remote/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/rclone/remotelist` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/remotelist` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/rclone/remotelist` | `mutating` | — | `Key`, `Type`, `Enable`, `Remark`, `Root`, `Params`, `HttpClienInsecureSkipVerify`, `HttpClientProxyType`, `HttpClientProxyAddr`, `HttpClientProxyUser`, `HttpClientProxyPassword`, `SystemMount` | `json` | `runtime-verified` |
| `PUT` | `/api/rclone/remotelist` | `mutating` | — | `Key`, `Type`, `Enable`, `Remark`, `Root`, `Params`, `HttpClienInsecureSkipVerify`, `HttpClientProxyType`, `HttpClientProxyAddr`, `HttpClientProxyUser`, `HttpClientProxyPassword`, `SystemMount` | `json` | `runtime-verified` |
| `GET` | `/api/rclone/remotelist/option` | `mutating` | `enable`, `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/remotelistlite` | `read-only` | `vfs` | — | `json` | `runtime-verified` |
| `DELETE` | `/api/rclone/sync/list` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/sync/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/rclone/sync/list` | `mutating` | — | `Key`, `Enable`, `Remark`, `SourceType`, `SourceRemoteKey`, `SourcePath`, `DestType`, `DestRemoteKey`, `DestPath`, `SyncMode`, `DeleteOnDest`, `DryRun`, `CreateEmptyDirs`, `IgnoreExisting`, `IgnoreErrors`, `CheckFirst`, `Transfers`, `Checkers`, `BandwidthLimit`, `MinAge`, `MaxAge`, `MinSize`, `MaxSize`, `IncludePatterns`, `ExcludePatterns`, `ExtraArgs`, `ScheduleEnable`, `ScheduleCron`, `ScheduleInterval`, `BisyncResync`, `BisyncCheckAccess`, `BisyncForce` | `json` | `runtime-verified` |
| `PUT` | `/api/rclone/sync/list` | `mutating` | — | `Key`, `Enable`, `Remark`, `SourceType`, `SourceRemoteKey`, `SourcePath`, `DestType`, `DestRemoteKey`, `DestPath`, `SyncMode`, `DeleteOnDest`, `DryRun`, `CreateEmptyDirs`, `IgnoreExisting`, `IgnoreErrors`, `CheckFirst`, `Transfers`, `Checkers`, `BandwidthLimit`, `MinAge`, `MaxAge`, `MinSize`, `MaxSize`, `IncludePatterns`, `ExcludePatterns`, `ExtraArgs`, `ScheduleEnable`, `ScheduleCron`, `ScheduleInterval`, `BisyncResync`, `BisyncCheckAccess`, `BisyncForce` | `json` | `runtime-verified` |
| `GET` | `/api/rclone/sync/option` | `mutating` | `enable`, `key` | — | `json` | `runtime-verified` |
| `POST` | `/api/rclone/sync/run/{param}` | `mutating` | `resync` | — | `json` | `runtime-verified` |
| `POST` | `/api/rclone/sync/stop/{param}` | `dangerous` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/sync/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/third/115pan/authcheck/{param}` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/rclone/third/115pan/authurl` | `read-only` | `cburl`, `lkbaseurl` | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/third/115pan/authuserlist` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/rclone/third/115pan/user` | `dangerous` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/third/alipan/authcheck/{param}` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/rclone/third/alipan/authurl` | `read-only` | `cburl`, `lkbaseurl` | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/third/alipan/authuserlist` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/rclone/third/alipan/user` | `dangerous` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/third/baidupan/authcheck/{param}` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/rclone/third/baidupan/authurl` | `read-only` | `cburl`, `lkbaseurl` | — | `json` | `runtime-verified` |
| `GET` | `/api/rclone/third/baidupan/authuserlist` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/rclone/third/baidupan/user` | `dangerous` | — | — | `json` | `runtime-verified` |

## `reboot_program`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/reboot_program` | `dangerous` | — | — | `json` | `frontend-call` |

## `restoreconfigureconfirm`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/restoreconfigureconfirm` | `mutating` | `key` | — | `json` | `frontend-call` |

## `security-groups`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/security-groups` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/security-groups` | `mutating` | — | `Key`, `Name`, `Enable`, `SessionTTLMinutes`, `AllowWebAuthIPBypass`, `Description` | `json` | `runtime-verified` |
| `GET` | `/api/security-groups/grants` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/security-groups/grants/delete` | `dangerous` | — | `grantKeys` | `json` | `runtime-verified` |
| `DELETE` | `/api/security-groups/grants/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/security-groups/lite` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/security-groups/oauth-users` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/security-groups/oauth-users` | `mutating` | — | `Key`, `ThirdAuthUserKey`, `Provider`, `SkipTwoFA`, `MatchID`, `MatchEmail`, `MatchName`, `Enable`, `GrantSecurityGroups`, `Description` | `json` | `runtime-verified` |
| `DELETE` | `/api/security-groups/oauth-users/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `PUT` | `/api/security-groups/oauth-users/{param}` | `mutating` | — | `Key`, `ThirdAuthUserKey`, `Provider`, `SkipTwoFA`, `MatchID`, `MatchEmail`, `MatchName`, `Enable`, `GrantSecurityGroups`, `Description` | `json` | `runtime-verified` |
| `GET` | `/api/security-groups/users` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/security-groups/users` | `mutating` | — | `Key`, `Name`, `Username`, `PasswordHash`, `Password`, `TwoFASecret`, `Enable`, `GrantSecurityGroups`, `Description`, `HasPassword` | `json` | `runtime-verified` |
| `DELETE` | `/api/security-groups/users/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `PUT` | `/api/security-groups/users/{param}` | `mutating` | — | `Key`, `Name`, `Username`, `PasswordHash`, `Password`, `TwoFASecret`, `Enable`, `GrantSecurityGroups`, `Description`, `HasPassword` | `json` | `runtime-verified` |
| `DELETE` | `/api/security-groups/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `PUT` | `/api/security-groups/{param}` | `mutating` | — | `Key`, `Name`, `Enable`, `SessionTTLMinutes`, `AllowWebAuthIPBypass`, `Description` | `json` | `runtime-verified` |

## `smb`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/smb/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/smb/configure` | `mutating` | — | `AutoFirewall`, `DiscoveryIP`, `Enable`, `EnableMDNS`, `EnableNBNS`, `EnableWSDD`, `Encryption`, `GuestEnable`, `ListenIP`, `ListenNetwork`, `ListenPort`, `LiteSMBLogLevel`, `LiteSMBLogToTerminal`, `MaxConnections`, `Multichannel`, `PublicMountList`, `SMBConfVersion`, `ServerName`, `Signing`, `Users`, `Workgroup` | `json` | `runtime-verified` |
| `POST` | `/api/smb/connections/{param}/disconnect` | `dangerous` | — | — | `json` | `frontend-call` |
| `GET` | `/api/smb/lastlogs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/smb/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/smb/runtime` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/smb/status` | `read-only` | — | — | `json` | `runtime-verified` |

## `ssl`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `DELETE` | `/api/ssl` | `mutating` | `key` | — | `json` | `frontend-call` |
| `GET` | `/api/ssl` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/ssl` | `mutating` | — | `AcmeErrorMsg`, `AddFrom`, `AddTime`, `AllSyncClient`, `CertBase64`, `Enable`, `ExtParams`, `IssuerCertificate`, `Key`, `KeyBase64`, `MappingChangeScript`, `MappingPath`, `MappingToPath`, `Remark`, `SyncClientList`, `UpdateTime` | `json` | `runtime-verified` |
| `PUT` | `/api/ssl` | `mutating` | — | `AcmeErrorMsg`, `AddFrom`, `AddTime`, `AllSyncClient`, `CertBase64`, `Enable`, `ExtParams`, `IssuerCertificate`, `Key`, `KeyBase64`, `MappingChangeScript`, `MappingPath`, `MappingToPath`, `Remark`, `SyncClientList`, `UpdateTime` | `json` | `runtime-verified` |
| `GET` | `/api/ssl/credential-sources` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ssl/download` | `dangerous` | `key` | — | `blob` | `runtime-verified` |
| `PUT` | `/api/ssl/flush` | `mutating` | `key` | — | `json` | `frontend-call` |
| `GET` | `/api/ssl/lastlogs` | `read-only` | `key` | — | `json` | `runtime-verified` |
| `GET` | `/api/ssl/logs` | `read-only` | `key`, `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/ssl/manualsync/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/ssl/setting` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ssl/setting` | `mutating` | — | `certificateCheckTime`, `defaultACMEEMail`, `globalPrivateKey`, `renewalThresholdDays`, `shortlivedCheckTimesPerDay`, `shortlivedRenewalThresholdHours`, `syncClientList` | `json` | `runtime-verified` |
| `PUT` | `/api/ssl/sslorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/ssl/syncclients` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/ssl/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/ssl/{param}` | `mutating` | `enable` | — | `json` | `frontend-call` |
| `DELETE` | `/api/ssl/{param}/acmecancel` | `mutating` | — | — | `json` | `frontend-call` |

## `status`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/status/history` | `read-only` | `start`, `end`, `bucket` | — | `json` | `runtime-verified` |
| `POST` | `/api/status/history/clear` | `dangerous` | — | — | `json` | `frontend-call` |
| `GET` | `/api/status/history/meta` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/status/host-connections` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/status/host-overview` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/status/host-process-kill` | `mutating` | — | `pid` | `json` | `runtime-verified` |
| `GET` | `/api/status/host-processes` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/status/module-overview` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/status/ws` | `read-only` | — | — | `websocket` | `runtime-verified` |

## `storagemanagement`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/storagemanagement/aliyunpan_auth` | `read-only` | `cburl`, `lkurl` | — | `json` | `runtime-verified` |
| `GET` | `/api/storagemanagement/aliyunpan_auth_check/{param}` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/storagemanagement/enable` | `mutating` | `enable`, `key` | — | `json` | `runtime-verified` |
| `PUT` | `/api/storagemanagement/itemorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/storagemanagement/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/storagemanagement/list` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `POST` | `/api/storagemanagement/list` | `mutating` | — | `Type`, `Enable`, `Key`, `Remark`, `Writable`, `Log`, `Params`, `SystemMount` | `json` | `runtime-verified` |
| `PUT` | `/api/storagemanagement/list` | `mutating` | — | `Type`, `Enable`, `Key`, `Remark`, `Writable`, `Log`, `Params`, `SystemMount` | `json` | `runtime-verified` |
| `GET` | `/api/storagemanagement/litelist` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/storagemanagement/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |

## `stun`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/stun/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/stun/configure` | `mutating` | — | `ConfVer`, `EnableModule`, `GlobalStunServerList`, `RetryCount`, `RetryInterval`, `WebHookTimeout`, `WebhookDisableCallbackSuccessContentCheck`, `WebhookEnable`, `WebhookHeaders`, `WebhookInsecureSkipVerify`, `WebhookLocalAddr`, `WebhookMethod`, `WebhookNetworkType`, `WebhookOnlyAddrChange`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyPassword`, `WebhookProxyUser`, `WebhookRequestBody`, `WebhookSuccessContent`, `WebhookURL` | `json` | `runtime-verified` |
| `PUT` | `/api/stun/ruleorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/stun/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/stun/{param}/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/stun/{param}/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |

## `stunrule`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `DELETE` | `/api/stunrule` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `POST` | `/api/stunrule` | `mutating` | — | `Name`, `Key`, `Enable`, `UseGlobalStunServerList`, `DiaglogShowMode`, `StunHeartbeatInterval`, `StunTimeout`, `StunRetryInterval`, `StunAutoRetry`, `AutoAddPubAddrWhiteList`, `StunType`, `StunListenType`, `SpecifyNetworkInterface`, `NetworkInterfaceReg`, `ListenIP`, `AutoOptionsFirewall`, `ListenPort`, `NatPMP`, `UPnPGawayIP`, `NatPMPGateway`, `UPnP`, `UPnPLocalPort`, `UPnpLocalHost`, `UPnPInternalClientIP`, `UpnPDiyControlAPIUrl`, `DisableStunAvalidCheck`, `DisablePortForward`, `TargetAddressList`, `TargetPort`, `LogLevel`, `LogOutputToConsole`, `AccessLogMaxNum`, `WebListShowLastLogMaxCount`, `Options`, `StunServerList`, `TcpKeepAliveServerList`, `GlobalWebhook`, `WebhookEnable`, `WebhookOnlyAddrChange`, `WebhookURL`, `WebhookMethod`, `WebhookHeaders`, `WebhookRequestBody`, `WebhookDisableCallbackSuccessContentCheck`, `WebhookSuccessContent`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyUser`, `WebhookProxyPassword`, `CallScript`, `CallScriptContent`, `RetryCount`, `RetryInterval`, `LogStreamSettings` | `json` | `runtime-verified` |
| `PUT` | `/api/stunrule` | `mutating` | — | `Name`, `Key`, `Enable`, `UseGlobalStunServerList`, `DiaglogShowMode`, `StunHeartbeatInterval`, `StunTimeout`, `StunRetryInterval`, `StunAutoRetry`, `AutoAddPubAddrWhiteList`, `StunType`, `StunListenType`, `SpecifyNetworkInterface`, `NetworkInterfaceReg`, `ListenIP`, `AutoOptionsFirewall`, `ListenPort`, `NatPMP`, `UPnPGawayIP`, `NatPMPGateway`, `UPnP`, `UPnPLocalPort`, `UPnpLocalHost`, `UPnPInternalClientIP`, `UpnPDiyControlAPIUrl`, `DisableStunAvalidCheck`, `DisablePortForward`, `TargetAddressList`, `TargetPort`, `LogLevel`, `LogOutputToConsole`, `AccessLogMaxNum`, `WebListShowLastLogMaxCount`, `Options`, `StunServerList`, `TcpKeepAliveServerList`, `GlobalWebhook`, `WebhookEnable`, `WebhookOnlyAddrChange`, `WebhookURL`, `WebhookMethod`, `WebhookHeaders`, `WebhookRequestBody`, `WebhookDisableCallbackSuccessContentCheck`, `WebhookSuccessContent`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyUser`, `WebhookProxyPassword`, `CallScript`, `CallScriptContent`, `RetryCount`, `RetryInterval`, `LogStreamSettings` | `json` | `runtime-verified` |
| `GET` | `/api/stunrule/enable` | `mutating` | `enable`, `key` | — | `json` | `runtime-verified` |
| `POST` | `/api/stunrule/webhooktest` | `mutating` | `key` | `WebhookURL`, `WebhookMethod`, `WebhookRequestBody`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyUser`, `RetryCount`, `RetryInterval`, `WebhookProxyPassword`, `WebhookHeaders`, `WebhookSuccessContent`, `WebhookDisableCallbackSuccessContentCheck` | `json` | `runtime-verified` |

## `stunrulelist`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/stunrulelist` | `read-only` | — | — | `json` | `runtime-verified` |

## `stunrulelist_lite`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/stunrulelist_lite` | `read-only` | — | — | `json` | `runtime-verified` |

## `temp-access-tickets`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `POST` | `/api/temp-access-tickets` | `dangerous` | — | — | `json` | `runtime-verified` |

## `third`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/third/filebrowser/backupdb` | `dangerous` | — | — | `blob` | `runtime-verified` |
| `GET` | `/api/third/filebrowser/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/third/filebrowser/configure` | `mutating` | — | `Address`, `AutoFirewall`, `BaseURL`, `CacheDir`, `ConfVersion`, `DBFile`, `DirPerm`, `DisableExec`, `DisablePreviewResize`, `DisableThumbnails`, `DisableTypeDetectionByHeader`, `Enable`, `FilePerm`, `HTTPEnable`, `IMGProcessors`, `ListenNetwork`, `MountList`, `Port`, `RedisCacheUrl`, `TLSEnable`, `TLSListenPort`, `TokenExpirationHour`, `TrustHostList` | `json` | `runtime-verified` |
| `GET` | `/api/third/filebrowser/lastlogs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/third/filebrowser/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/third/filebrowser/resetadmin` | `dangerous` | — | — | `json` | `frontend-call` |
| `GET` | `/api/third/filebrowser/status` | `read-only` | — | — | `json` | `runtime-verified` |

## `thirdPartyAuthManager`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/thirdPartyAuthManager/config` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/thirdPartyAuthManager/config` | `mutating` | — | `GithubRedirectURI`, `GithubClientID`, `GoogleRedirectURI`, `GoogleClientID`, `QQRedirectURI`, `QQClientID`, `AuthentikRedirectURI`, `AuthentikClientID`, `AuthentikServer`, `WeiboClientKey`, `WeiboRedirectURI`, `OIDCRedirectURI`, `OIDCClientID`, `OIDCAuthorizationEndpoint` | `json` | `runtime-verified` |
| `GET` | `/api/thirdPartyAuthManager/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/thirdPartyAuthManager/list` | `mutating` | — | `Key`, `Type`, `Enable`, `Remark`, `ID`, `Name`, `Avatar`, `EMail`, `Phone`, `RefreshToken`, `AccessToken`, `CreateTime`, `UpdateTime`, `TwoFAKey` | `json` | `runtime-verified` |
| `PUT` | `/api/thirdPartyAuthManager/list` | `mutating` | — | `Key`, `Type`, `Enable`, `Remark`, `ID`, `Name`, `Avatar`, `EMail`, `Phone`, `RefreshToken`, `AccessToken`, `CreateTime`, `UpdateTime`, `TwoFAKey` | `json` | `runtime-verified` |
| `DELETE` | `/api/thirdPartyAuthManager/list/{param}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/thirdPartyAuthManager/list/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/thirdPartyAuthManager/list/{param}/{param2}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/thirdPartyAuthManager/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `PUT` | `/api/thirdPartyAuthManager/orderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |

## `twofapassword`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/twofapassword` | `read-only` | — | — | `json` | `frontend-call` |

## `update`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/update/cancel` | `dangerous` | — | — | `json` | `frontend-call` |
| `PUT` | `/api/update/comfire` | `dangerous` | — | `Name`, `ARCH`, `OS`, `Version`, `GoVersion`, `Date`, `MD5` | `json` | `runtime-verified` |

## `v2l`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `POST` | `/api/v2l` | `mutating` | — | `v2l` | `json` | `runtime-verified` |

## `webdav`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/webdav/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webdav/configure` | `mutating` | — | `AutoFirewall`, `Enable`, `HTTPEnable`, `ListenIP`, `ListenNetwork`, `ListenPort`, `TLSEnable`, `TLSListenPort`, `TrustHostList`, `Users`, `WebDavConfVersion` | `json` | `runtime-verified` |
| `GET` | `/api/webdav/lastlogs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/webdav/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/webdav/status` | `read-only` | — | — | `json` | `runtime-verified` |

## `webservice`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `POST` | `/api/webservice/cgi` | `mutating` | — | `Key`, `Name`, `Enable`, `CGIType`, `Network`, `Address`, `MaxConns`, `ConnectTimeout`, `ForbiddenPaths`, `DefaultDocRoot`, `DefaultIndexNames`, `FileExtensions` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/cgi/list` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/webservice/cgi/{param}` | `mutating` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webservice/cgi/{param}` | `mutating` | — | `Key`, `Name`, `Enable`, `CGIType`, `Network`, `Address`, `MaxConns`, `ConnectTimeout`, `ForbiddenPaths`, `DefaultDocRoot`, `DefaultIndexNames`, `FileExtensions` | `json` | `runtime-verified` |
| `PUT` | `/api/webservice/cgi/{param}/{param2}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/discovery/active` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/discovery/cancel` | `mutating` | — | `jobId` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/discovery/latest` | `read-only` | `ruleKey` | — | `json` | `frontend-call` |
| `POST` | `/api/webservice/discovery/start` | `dangerous` | — | `ruleKey`, `targets`, `ports`, `excludePorts`, `domainSuffix`, `timeoutMs`, `maxScanDurationMs`, `maxHostRetriesPerEndpoint`, `allowedRedirectHosts`, `maxHosts`, `maxPortTargets`, `tcpConcurrency`, `probeConcurrency`, `tcpCompatibilityMode`, `maxRedirects` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/discovery/status/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/frontend-state` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webservice/frontend-state` | `mutating` | — | `listTabLayout`, `viewMode` | `json` | `runtime-verified` |
| `DELETE` | `/api/webservice/groups` | `mutating` | `key` | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/groups` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/groups` | `mutating` | — | `Name` | `json` | `runtime-verified` |
| `PUT` | `/api/webservice/groups` | `mutating` | — | `Key`, `Name` | `json` | `runtime-verified` |
| `PUT` | `/api/webservice/groups/orderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/groups/subrulecount` | `read-only` | `groupKey` | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/lightpanel/configtemplate` | `mutating` | — | `type`, `path`, `rcloneKey`, `rcloneRoot`, `storeKey`, `storeRoot` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `DELETE` | `/api/webservice/rule/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/rule/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webservice/rule/{param}` | `mutating` | — | `AutoOptionsFirewall`, `CorazaWAFInstance`, `DefaultProxy`, `DiaglogShowMode`, `DisableStatistics`, `ECDHPrivateKey`, `ECH`, `ECHConfigList`, `ECHDomain`, `Enable`, `EnableTLS`, `FrontRuleListDisplay`, `GlobalAllowAllThirdAuthUsers`, `GlobalAllowThirdUserSkipTwoFA`, `GlobalBasicAuthUserList`, `GlobalThirdAuthLoginUserList`, `Http3`, `IPFilterRule`, `ListenIP`, `ListenPort`, `MaxContinuous404Count`, `MaxCorazaInterceptionCount`, `MaxHeaderKBytes`, `Network`, `ProxyList`, `ReceRateLimit`, `ReceRateLimitEnabled`, `RuleKey`, `RuleName`, `SendRateLimit`, `SendRateLimitEnabled`, `SingleConnReceRateLimit`, `SingleConnReceRateLimitEnabled`, `SingleConnSendRateLimit`, `SingleConnSendRateLimitEnabled`, `SingleIPConnectionsLimit`, `SingleIPConnectionsLimitEnabled`, `SingleIPReceRateLimit`, `SingleIPReceRateLimitEnabled`, `SingleIPSendRateLimit`, `SingleIPSendRateLimitEnabled`, `TLSMinVersion` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/rule/{param}/{param2}/{param3}` | `read-only` | — | — | `json` | `frontend-call` |
| `PUT` | `/api/webservice/ruleorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/rules` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/rules` | `mutating` | — | `AutoOptionsFirewall`, `CorazaWAFInstance`, `DefaultProxy`, `DiaglogShowMode`, `DisableStatistics`, `ECDHPrivateKey`, `ECH`, `ECHConfigList`, `ECHDomain`, `Enable`, `EnableTLS`, `FrontRuleListDisplay`, `GlobalAllowAllThirdAuthUsers`, `GlobalAllowThirdUserSkipTwoFA`, `GlobalBasicAuthUserList`, `GlobalThirdAuthLoginUserList`, `Http3`, `IPFilterRule`, `ListenIP`, `ListenPort`, `MaxContinuous404Count`, `MaxCorazaInterceptionCount`, `MaxHeaderKBytes`, `Network`, `ProxyList`, `ReceRateLimit`, `ReceRateLimitEnabled`, `RuleKey`, `RuleName`, `SendRateLimit`, `SendRateLimitEnabled`, `SingleConnReceRateLimit`, `SingleConnReceRateLimitEnabled`, `SingleConnSendRateLimit`, `SingleConnSendRateLimitEnabled`, `SingleIPConnectionsLimit`, `SingleIPConnectionsLimitEnabled`, `SingleIPReceRateLimit`, `SingleIPReceRateLimitEnabled`, `SingleIPSendRateLimit`, `SingleIPSendRateLimitEnabled`, `TLSMinVersion` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/rules_lite` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/settings` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webservice/settings` | `mutating` | — | `LogLevel`, `Statistics`, `WebAuthSessionTTLMinutes` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/capabilities` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/statistics/clear` | `dangerous` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/statistics/daily` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/events` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/export` | `dangerous` | — | — | `blob` | `frontend-call` |
| `GET` | `/api/webservice/statistics/geo/aggregate` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/statistics/geo/rebuild` | `mutating` | — | `mode` | `json` | `runtime-verified` |
| `POST` | `/api/webservice/statistics/geo/rebuild/cancel` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/statistics/geo/rebuild/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/history` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/statistics/import` | `dangerous` | `mode` | `file` | `json` | `runtime-verified` |
| `POST` | `/api/webservice/statistics/import/cancel` | `dangerous` | — | — | `json` | `frontend-call` |
| `POST` | `/api/webservice/statistics/import/start` | `dangerous` | `mode` | `file` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/import/status` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/ip-info-refresh` | `mutating` | — | — | `json` | `frontend-call` |
| `POST` | `/api/webservice/statistics/ip-info-refresh` | `mutating` | — | `mode` | `json` | `runtime-verified` |
| `POST` | `/api/webservice/statistics/ip-info-refresh/cancel` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/statistics/ip-profile` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/meta` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/rankings` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/realtime` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/recent-ips` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/recent-ips/visits` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/summary` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/waf/events` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/statistics/waf/summary` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webservice/webauth/sessions` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webservice/webauth/sessions/clear-subrule` | `mutating` | — | `ruleKey`, `subRuleKey` | `json` | `runtime-verified` |
| `POST` | `/api/webservice/webauth/sessions/delete` | `dangerous` | — | `sessionIds` | `json` | `runtime-verified` |
| `DELETE` | `/api/webservice/webauth/sessions/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `DELETE` | `/api/webservice/{param}/disconnect/{param2}` | `dangerous` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/{param}/httpserver/logs` | `read-only` | `page`, `pageSize` | — | `json` | `frontend-call` |
| `PUT` | `/api/webservice/{param}/subrulegrouporderupdate` | `mutating` | — | `subRulesMap`, `orderList`, `defaultProxyGroupKey` | `json` | `runtime-verified` |
| `GET` | `/api/webservice/{param}/{param2}/accessdetail` | `read-only` | `page`, `pageSize` | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/{param}/{param2}/corazalogs` | `read-only` | `page`, `pageSize` | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/{param}/{param2}/lastlogs` | `read-only` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webservice/{param}/{param2}/logs` | `read-only` | `page`, `pageSize` | — | `json` | `frontend-call` |
| `DELETE` | `/api/webservice/{param}/{param2}/updatefolder/cancel/{param3}` | `mutating` | — | — | `json` | `frontend-call` |
| `POST` | `/api/webservice/{param}/{param2}/updatefolder/confirm` | `mutating` | — | `tempId` | `json` | `runtime-verified` |
| `POST` | `/api/webservice/{param}/{param2}/updatefolder/upload` | `dangerous` | — | `file`, `mountIndex` | `json` | `runtime-verified` |

## `webterminal`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/webterminal/config` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webterminal/config` | `mutating` | — | `bufferSize`, `heartbeatInterval`, `idleTimeout`, `maxSessions`, `sessionKeepAlive` | `json` | `runtime-verified` |
| `PUT` | `/api/webterminal/connectionorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/connections` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/connections` | `mutating` | — | `key`, `name`, `type`, `remark`, `localConfig`, `sshConfig`, `telnetConfig`, `shortcuts`, `quickAccessDirs` | `json` | `runtime-verified` |
| `PUT` | `/api/webterminal/connections` | `mutating` | — | `key`, `name`, `type`, `remark`, `localConfig`, `sshConfig`, `telnetConfig`, `shortcuts`, `quickAccessDirs` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/connections/test` | `mutating` | — | `key`, `name`, `type`, `remark`, `localConfig`, `sshConfig`, `telnetConfig`, `shortcuts`, `quickAccessDirs` | `json` | `runtime-verified` |
| `DELETE` | `/api/webterminal/connections/{param}` | `mutating` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/connections/{param}` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webterminal/connections/{param}/quickaccess` | `mutating` | — | `quickAccessDirs` | `json` | `runtime-verified` |
| `DELETE` | `/api/webterminal/connections/{param}/ssh-host-key` | `mutating` | — | — | `json` | `frontend-call` |
| `PUT` | `/api/webterminal/connections/{param}/ssh-host-key` | `mutating` | — | `host`, `port`, `hostname`, `hostKey`, `hostKeyFingerprint`, `hostKeyTrustedAt`, `keyType`, `previousHostKeyFingerprint`, `changed` | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/globalshortcuts` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webterminal/globalshortcuts` | `mutating` | — | `array<object>` | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/sessions` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/webterminal/sessions/{param}` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webterminal/sessions/{param}` | `read-only` | — | — | `json` | `frontend-call` |
| `PUT` | `/api/webterminal/sessions/{param}/remark` | `mutating` | — | `remark` | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/sessions/{param}/stats` | `read-only` | — | — | `json` | `frontend-call` |
| `POST` | `/api/webterminal/sftp/{param}/chmod` | `dangerous` | — | `path`, `permissions` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/sftp/{param}/compress` | `dangerous` | — | `output_name`, `output_path`, `paths` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/sftp/{param}/copy` | `dangerous` | — | `dst_path`, `src_path` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/sftp/{param}/decompress` | `dangerous` | — | `file_path`, `output_path` | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/sftp/{param}/list` | `read-only` | `path` | — | `json` | `frontend-call` |
| `POST` | `/api/webterminal/sftp/{param}/mkdir` | `mutating` | — | `path` | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/sftp/{param}/preview-archive` | `read-only` | `path` | — | `json` | `frontend-call` |
| `GET` | `/api/webterminal/sftp/{param}/read` | `read-only` | `path` | — | `json` | `frontend-call` |
| `DELETE` | `/api/webterminal/sftp/{param}/remove` | `dangerous` | `path` | — | `json` | `frontend-call` |
| `POST` | `/api/webterminal/sftp/{param}/rename` | `dangerous` | — | `newPath`, `oldPath` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/sftp/{param}/touch` | `mutating` | — | `path` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/sftp/{param}/upload` | `dangerous` | — | `file`, `path`, `filename` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/sftp/{param}/upload-streaming` | `mutating` | `path`, `filename` | `string` | `json` | `runtime-verified` |
| `POST` | `/api/webterminal/sftp/{param}/write` | `dangerous` | — | `content`, `path` | `json` | `runtime-verified` |
| `GET` | `/api/webterminal/shells` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/webterminal/splitlayout` | `mutating` | — | — | `json` | `frontend-call` |
| `GET` | `/api/webterminal/splitlayout` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/webterminal/splitlayout` | `mutating` | — | `direction`, `isQuadLayout`, `panes` | `json` | `runtime-verified` |

## `wol`

| 方法 | 路径 | 风险 | 查询字段 | 请求体 | 响应 | 证据等级 |
|---|---|---|---|---|---|---|
| `GET` | `/api/wol/client/state` | `read-only` | — | — | `json` | `runtime-verified` |
| `DELETE` | `/api/wol/device` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `POST` | `/api/wol/device` | `mutating` | — | `Key`, `DeviceName`, `MacList`, `BroadcastIPs`, `ProbeTargets`, `Port`, `Relay`, `Repeat`, `IOT_DianDeng_Enable`, `IOT_DianDeng_AUTHKEY`, `IOT_DianDeng_InsecureSkipVerify`, `IOT_DianDengBindComponentEnable`, `IOT_DianDengBindComponent`, `IOT_Bemfa_Enable`, `IOT_Bemfa_SecretKey`, `IOT_Bemfa_Topic`, `IOT_Bemfa_InsecureSkipVerify` | `json` | `runtime-verified` |
| `PUT` | `/api/wol/device` | `mutating` | — | `Key`, `DeviceName`, `MacList`, `BroadcastIPs`, `ProbeTargets`, `Port`, `Relay`, `Repeat`, `IOT_DianDeng_Enable`, `IOT_DianDeng_AUTHKEY`, `IOT_DianDeng_InsecureSkipVerify`, `IOT_DianDengBindComponentEnable`, `IOT_DianDengBindComponent`, `IOT_Bemfa_Enable`, `IOT_Bemfa_SecretKey`, `IOT_Bemfa_Topic`, `IOT_Bemfa_InsecureSkipVerify` | `json` | `runtime-verified` |
| `GET` | `/api/wol/device/shutdown` | `dangerous` | `key` | — | `json` | `frontend-call` |
| `GET` | `/api/wol/device/wakeup` | `mutating` | `key` | — | `json` | `runtime-verified` |
| `PUT` | `/api/wol/deviceorderadjustment` | `mutating` | — | `array<string>` | `json` | `runtime-verified` |
| `GET` | `/api/wol/devices` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/wol/devices_lite` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/wol/lastlogs` | `read-only` | — | — | `json` | `runtime-verified` |
| `GET` | `/api/wol/logs` | `read-only` | `page`, `pageSize` | — | `json` | `runtime-verified` |
| `GET` | `/api/wol/service/configure` | `read-only` | — | — | `json` | `runtime-verified` |
| `PUT` | `/api/wol/service/configure` | `mutating` | — | `Client`, `Server` | `json` | `runtime-verified` |
| `GET` | `/api/wol/service/getipv4interface` | `read-only` | — | — | `json` | `runtime-verified` |
| `POST` | `/api/wol/webhooktest` | `mutating` | — | `WebhookURL`, `WebhookMethod`, `WebhookRequestBody`, `WebhookProxy`, `WebhookProxyAddr`, `WebhookProxyUser`, `WebhookProxyPassword`, `WebhookHeaders`, `WebhookSuccessContent`, `WebhookDisableCallbackSuccessContentCheck`, `RetryCount`, `RetryInterval` | `json` | `runtime-verified` |
