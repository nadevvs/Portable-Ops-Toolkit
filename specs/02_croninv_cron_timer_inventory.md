# Task: `croninv` — Cron and Systemd Timer Inventory

## Goal

Create a lightweight Python CLI tool that inventories scheduled jobs on a Linux system.

It should collect cron jobs and systemd timers into one readable report.

Example:

```bash
python3 croninv.py
python3 croninv.py --json
python3 croninv.py --state /media/usb/ops-state
```

## Main questions this tool answers

- What scheduled jobs exist on this server?
- Which user runs each job?
- Where is the job defined?
- What command will run?
- Is the job enabled?
- When did it last run, if known?
- When will it run next, if known?
- Are there suspicious or unusual scheduled tasks?

## Scope

Inspect:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`
- `/etc/cron.daily/*`
- `/etc/cron.weekly/*`
- `/etc/cron.monthly/*`
- user crontabs, where accessible
- systemd timers

This tool should be read-only.

## CLI

Required:

```bash
python3 croninv.py
python3 croninv.py --json
python3 croninv.py --no-color
python3 croninv.py --state PATH
```

Optional:

```bash
python3 croninv.py --include-users
python3 croninv.py --suspicious
```

`--include-users` tries to list user crontabs. Some systems require root to read all users' crontabs.

`--suspicious` can focus on unusual entries only.

## Data sources

### 1. System crontab

Read:

```text
/etc/crontab
```

Parse lines like:

```text
17 * * * * root cd / && run-parts --report /etc/cron.hourly
```

Fields:

- minute
- hour
- day of month
- month
- day of week
- user
- command
- source file

Ignore comments and empty lines.

Preserve environment assignments like:

```text
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

But do not treat them as jobs.

### 2. `/etc/cron.d`

Read each file in:

```text
/etc/cron.d/
```

Parse with the same format as `/etc/crontab`.

Show the source filename.

### 3. Periodic directories

List executable files in:

```text
/etc/cron.hourly
/etc/cron.daily
/etc/cron.weekly
/etc/cron.monthly
```

For each file, show:

- period
- path
- owner
- permissions
- modified time
- executable yes/no

Do not execute anything.

### 4. User crontabs

Best-effort options:

- run `crontab -l` for current user
- if root, inspect `/var/spool/cron/crontabs/` or distro equivalent
- optionally use `getent passwd` to enumerate users and `crontab -l -u USER`

Handle permission errors.

Do not require this to work on every distro.

### 5. Systemd timers

Use:

```bash
systemctl list-timers --all --no-pager
systemctl list-unit-files --type=timer --no-pager
```

For each timer, collect:

- timer unit
- next run time
- last run time
- passed/left values if available
- activates service/unit
- enabled/disabled/static

Optional deeper check:

```bash
systemctl show TIMER
```

Fields:

- `NextElapseUSecRealtime`
- `LastTriggerUSec`
- `Unit`
- `ActiveState`
- `UnitFileState`

## Suspicious indicators

Mark warnings for jobs that:

- run from `/tmp`, `/var/tmp`, `/dev/shm`
- call `curl | sh` or `wget | sh`
- use base64 decoding
- call unknown scripts in world-writable locations
- run as root and execute from a user home directory
- hide output with `>/dev/null 2>&1`
- use unusual network tools like `nc`, `ncat`, `socat` in cron
- have very broad writable permissions
- are recently modified compared to current time

Do not claim compromise. Say "suspicious indicator" or "review recommended".

## Output format

### Human output

Suggested:

```text
croninv: scheduled job inventory

System cron jobs
  /etc/crontab
    17 * * * * root run-parts /etc/cron.hourly

Cron.d jobs
  /etc/cron.d/certbot
    0 */12 * * * root certbot -q renew

Periodic directories
  daily: /etc/cron.daily/logrotate owner=root perms=755

Systemd timers
  apt-daily.timer enabled next=Mon ... activates=apt-daily.service

Warnings
  [WARN] /etc/cron.d/custom runs command from /tmp
```

### JSON output

Suggested:

```json
{
  "cron_jobs": [],
  "periodic_jobs": [],
  "systemd_timers": [],
  "warnings": [],
  "errors": []
}
```

## Implementation hints

Use pure parser functions:

- `parse_crontab(text, source, has_user_field=True)`
- `parse_systemd_timers(text)`
- `check_suspicious(job)`
- `file_metadata(path)`

Cron parsing should not try to fully understand every schedule feature. Keep the schedule fields as strings.

Support special cron strings:

```text
@reboot
@daily
@hourly
@weekly
@monthly
@yearly
@annually
```

In user crontabs, there is usually no user field. In `/etc/crontab` and `/etc/cron.d`, there usually is a user field.

## Edge cases

Handle:

- unreadable files
- missing directories
- broken symlinks
- crontab files with environment variables
- cron entries split weirdly
- system without systemd
- timer list output with locale differences

## Non-goals

Do not:

- edit cron files
- disable timers
- run jobs
- delete suspicious files
- install packages

## Suggested tests

1. Parse `/etc/crontab` style line with user field.
2. Parse user crontab line without user field.
3. Parse `@reboot` line.
4. Detect `/tmp/script.sh` as review warning.
5. Parse sample `systemctl list-timers` output.

## Definition of done

The tool is done when:

- it lists system cron jobs
- it lists periodic cron directories
- it lists systemd timers if available
- it supports `--json`
- it handles permission errors cleanly
- it does not modify anything
