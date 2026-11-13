# Synology DSM

On DSM the agent reports drive health (DSM's own SMART, error and wear
verdicts, bad sectors, temperature, SSD life left), drives missing from the
RAID arrays, volumes DSM has remounted read-only, the unit's temperature and
the UPS. It does so as the unprivileged package user DSM 7 runs it as: DSM
keeps its per-drive verdicts in world-readable files under
`/run/synostorage/disks`, RAID state is in `/proc/mdstat`, and DSM's UPS
service answers any local user. Nothing needs setting up.

Four things are readable only by root: Security Advisor's results, the
sign-ins DSM flags as abnormal, the DSM update check and Container Manager.
The agent never asks for root. If you want those reported too, create the
optional status task below: it runs as root in DSM's Task Scheduler and
saves the replies of DSM's own APIs into a root-owned directory every five
minutes, and the agent reads them.

## The optional status task

Control Panel > Task Scheduler > Create > Scheduled Task > User-defined script:

- General: task name `Netwarden status`, user `root`.
- Schedule: daily, repeat every 5 minutes, from 00:00 to 23:55.
- Task Settings > Run command: paste the script below as it is.

Keep the script in the task. Do not save it as a file inside the package
directory and call that: the package user can write there, and a root task
running a file the package user controls hands root to anyone who takes over
the agent.

```sh
#!/bin/sh
# Netwarden status task: saves DSM API replies for the Netwarden agent.
umask 022
DIR=/var/lib/netwarden-dsm
mkdir -p "$DIR" || exit 1
chown root:root "$DIR" && chmod 755 "$DIR" || exit 1

# put NAME COMMAND...: keep the reply only when the command succeeded, so a
# failed call leaves the previous file to age (the agent ignores old files).
put() {
  name=$1; shift
  tmp=$(mktemp "$DIR/.$name.XXXXXX") || return
  if "$@" >"$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    chmod 644 "$tmp" && mv -f "$tmp" "$DIR/$name"
  else
    rm -f "$tmp"
  fi
}
api() {
  a=$1; m=$2; v=$3; shift 3
  synowebapi --exec "api=$a" "method=$m" "version=$v" "$@"
}

put security_scan.json  api SYNO.Core.SecurityScan.Status system_get 1
put login_activity.json api SYNO.SecurityAdvisor.LoginActivity list 1 offset=0 limit=50
put containers.json     api SYNO.Docker.Container list 1 offset=0 limit=-1 type=all

# The update check asks Synology's servers: once an hour is enough.
if [ -z "$(find "$DIR/upgrade.json" -mmin -60 2>/dev/null)" ]; then
  put upgrade.json api SYNO.Core.Upgrade.Server check 1
fi

exit 0
```

Without Container Manager that line simply leaves no file, and the agent
reports nothing for it.

## Check it

After the first run, `ls -l /var/lib/netwarden-dsm` shows the files owned by
root, mode 644. Within a report cycle the host page shows
`synology_status_present` at 1 and `synology_status_age_seconds` under 300.
Without the task, `synology_status_present` is 0 and everything else is
reported as usual.

The agent refuses a status file that is not a regular file owned by root, or
that is writable by group or others, and ignores one older than 20 minutes
(three hours for the update check): an old file means that DSM call has
been failing.

## What is reported

| Metric | Meaning | Source |
|---|---|---|
| `synology_disk_healthy{disk,model,type,smart,status}`, `synology_disks_unhealthy` | DSM's verdicts per drive: SMART, unrecoverable errors, timeouts, resets, wear past DSM's threshold, bad blocks, bad sectors | `/run/synostorage/disks` |
| `synology_disk_bad_sectors`, `synology_disk_temperature_celsius`, `synology_disk_max_temperature_celsius` | bad sector count and temperature per drive | `/run/synostorage/disks` |
| `synology_disk_remaining_life_percent`, `synology_disk_min_remaining_life_percent` | SSD life left, when DSM has a value | `/run/synostorage/disks` |
| `synology_md_degraded{array}`, `synology_md_arrays_degraded`, `synology_disks_missing` | RAID arrays running without all their members, and how many drives that means | `/proc/mdstat` |
| `synology_volume_healthy{volume,status}`, `synology_volumes_unhealthy` | a `/volumeN` DSM has remounted read-only | `/proc/mounts` |
| `synology_system_temperature_celsius` | the CPU package temperature | `/sys/class/hwmon` |
| `synology_ups_reachable`, `synology_ups_on_battery`, `synology_ups_low_battery`, `synology_ups_replace_battery`, `synology_ups_battery_charge_percent`, `synology_ups_runtime_seconds` | the UPS (absent when no UPS service runs) | DSM's UPS service, `127.0.0.1:3493` |
| `synology_status_present`, `synology_status_age_seconds` | whether the status task is running, and how fresh its files are | status task |
| `synology_security_scan_safe`, `synology_security_scan_findings`, `synology_security_scan_failing{category,severity}`, `synology_security_scan_age_seconds` | Security Advisor's last scan | status task |
| `synology_update_available` | a DSM update is available | status task |
| `synology_abnormal_logins_new`, `synology_abnormal_login{user,ip,country,city,protocol}` | sign-ins DSM flagged as abnormal since the last report | status task |
| `synology_container_running{container}`, `synology_containers_stopped` | Container Manager | status task |

Share snapshots (`synology_snapshot_*`) and ransomware canaries are covered
in `docs/tripwire.md`.

Volume usage is the ordinary `disk_usage_percent` of each `/volumeN`.

The collector is on by default and inactive on anything but DSM. Turn it off
with `enable_synology: false`; move the status directory with
`synology_status_dir`.
