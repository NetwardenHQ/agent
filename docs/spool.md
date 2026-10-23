# Spool and state file: the local-producer interface (v1)

A local producer is software on the same host that knows something the agent
does not, for example an OPNsense UI plugin that evaluates the pf ruleset,
port forwards and connected clients. Producers hand that data to the agent
through a spool directory, and the agent sends it as typed snapshots on its
normal `/agent/data` cycle. Producers never talk to the Netwarden API, and the
agent opens no listener.

This document is the contract both sides rely on. The limits are the
constants in [`internal/spool/spool.go`](../internal/spool/spool.go).

## Transport

The spool directory is `spool_dir` in `netwarden.conf`:

| OS | Default |
|---|---|
| FreeBSD / OPNsense | `/var/db/netwarden/spool` |
| Linux | `/var/lib/netwarden/spool` |
| Windows | `%ProgramData%\Netwarden\spool` |
| other (macOS) | off unless `spool_dir` is set |

`spool_dir: off` disables the spool.

Writers write `<name>.tmp` and then `rename()` it into place. The agent never
reads `*.tmp` files or names starting with `.`, and does not follow symlinks.

| File | Written by | Agent sends as snapshot | When |
|---|---|---|---|
| `events/*.jsonl` | producer | `events` | every cycle while non-empty (at most 500 events per post) |
| `exposure.json` | producer | `network_exposure` | when its SHA-256 changes, and at least hourly |
| `identity.json` | producer (optional) | merged into `device_identity` | every cycle |
| (none) | agent | `device_identity` | every cycle, on every agent |

Limits:

- A whole post is at most 1 MB and 16 snapshots. When there is no room,
  spool data waits for a later cycle; `exposure.json` takes priority over
  events.
- `exposure.json`: 256 KB. `identity.json`: 16 KB.
- One events file: 10 MB. One event line: 32 KB. At most 2000 events files
  are considered per cycle.

Producers should cap the spool at 10 MB themselves, dropping the oldest events
file and writing one `spool.overflow` event. No file may contain secrets, raw
configuration or API keys.

## `events/*.jsonl`

One JSON object per line:

```json
{"v":1,"type":"firewall.exposure_changed","severity":"warning","title":"…","detail":"…",
 "occurred_at":"2026-10-18T13:00:00Z","dedupe_key":"…","labels":{"k":"v"}}
```

| Field | Rule |
|---|---|
| `v` | `1` |
| `type` | lower-case, at least two dot-separated parts of `[a-z0-9_]` (`client.new_device`, `firewall.exposure_changed`, `gui.login`, `ssh.login`, `config.changed`, …) |
| `severity` | `info`, `warning` or `critical` |
| `title` | required, 1 to 200 characters |
| `detail` | optional, up to 4000 characters |
| `occurred_at` | required, RFC 3339 |
| `dedupe_key` | required, 1 to 200 characters |
| `labels` | optional, at most 32, string to string |

Files are read in name order. Invalid lines are skipped and counted, never
repaired. An event that does not fit an otherwise empty post for 10
consecutive posts is skipped, so it cannot block the queue.

Delivery is at least once. The agent deletes a file only after the post that
carried all of its events returned 2xx. A file larger than one post is
delivered in parts, tracked by byte offset; if the file is replaced by a
shorter one, reading starts again from the beginning. A file that holds only
invalid or blank lines is deleted once read. The platform deduplicates on the
host and `dedupe_key` within 24 hours.

### Events the agent writes itself

The agent's own collectors write security events into the same directory, as
`events/agent-auth-<nanoseconds>.jsonl`, and they travel like any producer's.
`spool_dir: off` therefore turns them off too; the agent then reports
`security_events_enabled 0`. Every one has `"v":1` and `"severity":"info"`;
the platform raises findings from them, so they never notify on their own.

| `type` | Source | `labels` |
|---|---|---|
| `ssh.login` | sshd `Accepted …` (Linux) | `user`, `source_ip`, `method`, `key_fp` (public-key logins), `prior_failures`, `count` |
| `rdp.login` | 4624, logon type 10 (Windows) | `user`, `source_ip`, `prior_failures`, `count` |
| `console.login` | 4624, logon types 2 and 11 (Windows) | `user`, `count` |
| `network.login` | 4624, logon type 3, public source only (Windows) | `user`, `source_ip`, `auth`, `prior_failures`, `count` |
| `account.created` | `useradd` (Linux), 4720 (Windows) | `user`, `by` when known, `count` |
| `account.admin_granted` | `usermod`/`gpasswd` into sudo, wheel or admin (Linux), 4732 into Administrators (Windows) | `user`, `group`, `by` when known, `count` |
| `audit.log_cleared` | 1102 (Windows) | `by`, `count` |

- `count`: identical events in one collection are folded into one; the event
  carries the first occurrence's time.
- `prior_failures`: failed logins from `source_ip` on this host in the hour
  before the login.
- `dedupe_key`: `auth:` and 32 hex digits of the log line's SHA-256 on Linux,
  `win:<EventRecordID>` on Windows.
- A failed login is never an event, only a count (`security_failed_logins`):
  the username of a failed login is sometimes a mistyped password.

## `exposure.json`

A full replacement each time it is written:

```json
{"v":1,"generated_at":"RFC3339","analyzer":"example-pfeval",
 "wan":[{"interface":"em0","addresses":["203.0.113.10"],"hostnames":["gw.example.net"]}],
 "forwards":[{"proto":"tcp","ext_ports":"443","target":"10.0.0.20","internal_port":"443",
   "sources":{"summary":"anywhere except …","allow_cidrs":[],"deny_aliases":["Blocked_Countries"],
              "restricted_to":["192.0.2.44/32"]},
   "deciding_rules":["…"],"exactness":"exact"}],
 "lan":[{"ip":"10.0.0.20","mac":"aa:bb:cc:dd:ee:ff","verdict":"reachable","ports":["tcp/443"],"explanation":"…"}],
 "scan":{"consent":true,"targets":["203.0.113.10","gw.example.net"]}}
```

- `exactness`: `exact` or `explicit`. `verdict`: `reachable`, `not_reachable` or `partial`.
- `restricted_to` holds resolved CIDRs; `deny_aliases` holds the alias names.
- `scan.consent`: outside-in scanning of the listed targets runs only while
  this is `true` and scanning is not switched off in Netwarden.
- The agent checks only that the file is a JSON object within the size
  limit. The platform validates the rest.

## `identity.json` and `device_identity`

Every agent sends a `device_identity` snapshot of its own:

```json
{"role":"gateway","platform":"opnsense","platform_version":"26.7.7","vendor":"Deciso",
 "capabilities":["firewall","nat","ids","vpn","dhcp","dns","crowdsec"],
 "interfaces":[{"name":"em0","role":"wan","addresses":["203.0.113.10/24"],"mac":"…"}],
 "unisense_version":"…"}
```

- `role`: `gateway`, `server` or `cluster`. Servers omit the interface `role`.
- `addresses` are CIDR strings (IPv4 and IPv6), without loopback or link-local.
- Anything the agent cannot determine is omitted, never zeroed.

A producer may add to it through `identity.json`. Only allow-listed keys are
merged. Today that is `unisense_version`: the producer's version, a non-empty
string of at most 64 bytes. Other keys are ignored.

## Ownership and permissions

When it runs as root (on Windows, as the service), the agent creates the spool directory and
`spool/events` at startup (mode 0700) if they are missing, and leaves existing
directories as they are. A producer may create them instead, with the same
owner and mode. Producer files should be 0600.

The agent reads a directory or file only if it passes these checks, made on
the open descriptor:

- Unix: owned by root and not writable by group or others. Every directory
  above the spool must be owned by root (or the spool's owner) and not
  writable by group or others, unless it is root-owned and sticky like
  `/tmp`.
- Windows: owned by SYSTEM or Administrators, and no ACL entry lets anyone
  else write, delete or change permissions. The agent creates missing
  directories with a protected SYSTEM and Administrators ACL. To fix an
  existing one:

  ```
  icacls <dir> /inheritance:r /grant:r SYSTEM:(OI)(CI)F Administrators:(OI)(CI)F
  ```

A spool that fails a check is ignored and the reason is logged once.

## Agent state file

The agent writes `state.json` (0644, atomic rename) at startup and after every
post attempt, so a producer can show whether the agent is running and
current. Cycles skipped while the agent backs off after failures are not
attempts and are not recorded. The file lives in the parent directory of
`spool_dir` when that is set, otherwise in `/var/db/netwarden` (FreeBSD) or
`/var/lib/netwarden` (Linux). On other systems it is written only when
`spool_dir` is set.

```json
{"v":1,"agent_version":"3.1.0","started_at":"RFC3339","pid":12345,
 "spool":{"supported":true,"version":1,"dir":"/var/db/netwarden/spool"},
 "interval_seconds":60,
 "last_post_attempt_at":"RFC3339","last_post_ok_at":"RFC3339",
 "last_post_status":200,"last_error":null,
 "events_sent_total":0,"events_pending":0}
```

| Field | Meaning |
|---|---|
| `spool.supported` | `false` when the spool is disabled; `dir` is then empty |
| `spool.version` | spool feature level; currently `1` |
| `last_post_attempt_at` | `null` until the first attempt |
| `last_post_ok_at` | absent until the first successful post since startup |
| `last_post_status` | HTTP status of the last reply; `null` when no reply arrived |
| `last_error` | message of the last failed attempt; `null` after a success |
| `events_sent_total` | events acknowledged since the agent started |
| `events_pending` | non-blank lines not yet delivered (invalid lines count until they are read) |

A producer should ask the operator to update the agent when the file is
missing, `spool.supported` is false, or `spool.version` is lower than it
needs.
