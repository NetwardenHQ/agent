# Ransomware tripwire

Ransomware that stays unnoticed long enough outlives your backups: snapshot
locks expire, clean versions rotate out, and every new copy is encrypted. The
tripwire is there to notice within minutes. It works on every platform the
agent runs on, needs no privileges beyond read access to what it watches, and
never changes or moves your files.

It has three parts. Use any of them.

## Canary files

Decoy files nobody has any reason to open, placed where ransomware will find
them: a `Passwords.xls` in Documents, a tax return in a finance folder. The
agent hashes each one about every minute. If a canary changes, disappears, is
renamed or replaced by a link, the platform raises a critical alert at once.
A canary the agent can no longer read is a separate critical alert: either
its permissions were reset or something changed them, and both need a look.

Create realistic decoys with the agent itself (it refuses to overwrite):

```sh
netwarden -plant-canaries "/home/alice/Documents/Finance"
```

It prints the line to add to `netwarden.conf`, with each file's SHA-256
pinned. A pinned hash is checked from the first collection, so a canary that
was already altered is caught too. Without a pin, the agent takes the file as
it first finds it as the baseline.

```yaml
tripwire_canaries: /home/alice/Documents/Finance/Passwords.txt@sha256:...,/srv/share/Taxes/Tax return 2025.pdf@sha256:...
```

The baseline is kept in `tripwire.json` beside the config file (move it with
`tripwire_state_path`), so a canary encrypted while the agent was stopped is
still caught when it starts. To accept a canary you changed on purpose,
update its pinned hash, or delete its entry from `tripwire.json`.

The agent never needs to list the folder a canary is in, only to read the
file itself. On a system with ACLs (Synology DSM, Windows), give the agent's
user read on the canary file and traverse on its parent folders, and nothing
else: it then cannot see any other file there.

## Watched folders

```yaml
tripwire_folders: /srv/share,/home/alice/Documents
tripwire_walk_minutes: 15
```

Every walk interval (15 minutes by default) the agent walks each folder,
reading file metadata only, and counts the files changed since the previous
walk. On Linux, macOS and FreeBSD a rename counts as a change. It raises:

- a change burst, when more than 200 files changed and that is more than ten
  times the folder's usual count over the last day of walks (judged once
  eight walks exist), or when more than a fifth of the folder disappeared;
- suspicious files, judged only among the changed ones: a known ransomware
  extension appended to the file's own (`Report.docx.lockbit`), a ransom
  note (`HOW_TO_DECRYPT.txt` or `.html`), a file whose contents no longer
  match its type (a `.jpg` that does not start like a JPEG, a `.docx` that is
  no longer a zip), or a text file whose start has become random bytes.
  Photos, video and archives look random by nature, so they are judged by
  their type only. macOS `._` files, Office lock files (`~$...`),
  `Thumbs.db` and `.DS_Store` are never judged: they are not what their
  names say.

A burst is not proof: a large copy, a restore or a permissions change applied
to a whole folder (which changes every file's ctime) looks the same. The
alert says so.

The first walk of a folder only records its baseline. Walks run in the
background; a folder of half a million files takes around half a minute. A
walk that has not finished after ten minutes (a hung network mount) is
discarded and reported as `tripwire_walk_complete` 0, and a folder whose walk
failed waits for the next interval like any other.

## Snapshots (Synology)

On a Synology NAS with Snapshot Replication, the snapshot folders under
`/volumeN/@sharesnap/<share>/` can be listed by any user, and each snapshot's
name carries the time it was taken. The agent reports each share's newest
snapshot age and its usual interval, and flags a share whose newest snapshot
is more than an hour past that interval: with immutable snapshots, that is how
clean copies age out without anyone noticing.

When a canary lives in a snapshotted share, the agent also checks its copy in
the share's newest snapshot. A snapshot taken before the canary was first seen
is not judged. If the copy has changed, the newest snapshot was taken after
the encryption; roll back to an older one.

## Metrics

| Metric | Meaning |
|---|---|
| `tripwire_canary_intact{canary,state}` | 1 when intact; `state` is intact, modified, missing or unreadable |
| `tripwire_canaries_watched`, `tripwire_canaries_tampered`, `tripwire_canaries_unreadable` | counts |
| `tripwire_canary_snapshot_intact{canary,share,snapshot,state}`, `tripwire_canary_snapshots_bad`, `tripwire_canary_snapshots_unreadable` | the canary's copy in the newest snapshot |
| `tripwire_folder_readable{folder}`, `tripwire_walk_complete`, `tripwire_files_total`, `tripwire_files_changed`, `tripwire_bytes_changed` | per watched folder, from its latest walk |
| `tripwire_change_spike{folder}`, `tripwire_folders_change_spike` | change bursts |
| `tripwire_suspicious_files{folder}`, `tripwire_suspicious_file{folder,file,reason}`, `tripwire_suspicious_files_total` | changed files that look like ransomware's work (up to five named per folder) |
| `tripwire_folders_unreadable` | watched folders the agent cannot read |
| `synology_snapshot_age_seconds{share}`, `synology_snapshot_interval_seconds`, `synology_snapshot_count`, `synology_snapshot_stale`, `synology_snapshots_stale` | Synology share snapshots |

## What it does not do

It detects; it does not stop anything. It cannot pause snapshot rotation or
extend a lock, and it does not kill processes. The alerts are meant to reach
you while the clean snapshots still exist.
