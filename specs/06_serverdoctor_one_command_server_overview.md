# Task: `serverdoctor` — One-Command Server Overview

## Goal

Create a lightweight Python CLI tool that gives a practical one-command health overview of a Linux server.

This is the main "first command to run" when troubleshooting.

Example:

```bash
python3 serverdoctor.py
python3 serverdoctor.py --json
python3 serverdoctor.py --deep
```

## Main questions this tool answers

- Is the server generally healthy?
- Is disk or memory close to full?
- Are any systemd services failed?
- What ports are publicly listening?
- Were there recent SSH login failures?
- Are there obvious kernel/OOM errors?
- Are backups or important paths present, if configured?
- What should I check next?

## Scope

This tool should combine quick checks into one report.

It should not be too deep. For focused details, it can recommend running the other tools:

- `svcdep` for service detail
- `croninv` for scheduled jobs
- `permdrift` for permission baseline
- `sshexpose` for SSH audit
- `blackbox` for history

## CLI

Required:

```bash
python3 serverdoctor.py
python3 serverdoctor.py --json
python3 serverdoctor.py --no-color
python3 serverdoctor.py --state PATH
```

Optional:

```bash
python3 serverdoctor.py --deep
python3 serverdoctor.py --checks system,disk,memory,network,security,logs
python3 serverdoctor.py --config serverdoctor.conf
```

## Checks

### 1. Identity and uptime

Collect:

```bash
hostname
hostnamectl
uptime
```

Also read:

```text
/proc/uptime
/proc/sys/kernel/random/boot_id
```

Show:

- hostname
- OS/distro if available from `/etc/os-release`
- kernel version
- uptime
- load average

### 2. Memory

Read `/proc/meminfo`.

Show:

- total memory
- available memory
- used percent
- swap usage

Warn if:
- memory available below 10–15%
- swap used heavily

### 3. Disk

Use:

```bash
df -hP
```

Show important mounts.

Warn if:
- used percent >= 85%
- used percent >= 95% critical
- inode usage high if implemented with `df -iP`

### 4. Failed services

Use:

```bash
systemctl --failed --no-pager
```

Show failed units.

Warn if any failed services exist.

If systemd unavailable, show info.

### 5. Listening ports

Use:

```bash
ss -tulpn
```

Show listening TCP/UDP ports.

Classify:

- `127.0.0.1` / `::1` = local-only
- `0.0.0.0` / `::` = all interfaces
- private IP = internal/interface-specific

Highlight likely risky public listeners:

- database ports exposed on all interfaces, e.g. PostgreSQL 5432, MySQL 3306, Redis 6379, MongoDB 27017
- Docker API 2375
- Elasticsearch 9200
- SSH on all interfaces is normal but should be noted

Do not claim something is internet-exposed unless you only know it listens on all interfaces. Phrase as "listening on all interfaces".

### 6. Recent logs

Best effort:

```bash
journalctl -p warning..alert -n 50 --no-pager
```

or check:

```text
/var/log/syslog
/var/log/messages
/var/log/auth.log
```

Look for:

- OOM kill
- disk I/O errors
- segfaults
- service failures
- authentication failures
- denied/refused/timeout patterns

Keep it short.

### 7. SSH quick summary

Do a shallow SSH check:

- is ssh/sshd service active?
- listening addresses/ports
- password auth setting if easy to determine
- root login setting if easy to determine
- recent failed attempts count from auth logs

For deeper output, recommend `sshexpose`.

### 8. Backup/status path checks

Optional config can define paths to check:

```text
# serverdoctor.conf
path:/var/backups:warn_if_missing
path:/opt/app/.env:warn_if_world_readable
service:nginx
service:postgresql
url:http://127.0.0.1/health
```

Keep config optional.

If config is missing, run generic checks only.

### 9. Network basics

Collect:

```bash
ip addr
ip route
```

Show:

- primary default route
- main IP addresses
- DNS resolvers from `/etc/resolv.conf`

Do not overcomplicate.

### 10. Final summary

Compute simple overall status:

- OK
- WARN
- CRITICAL

Example:
- Any disk >= 95% => CRITICAL
- Any failed service => WARN
- OOM detected recently => WARN/CRITICAL depending count
- public DB listener => CRITICAL
- memory low => WARN

Also show recommended next commands:

```text
Next checks:
  python3 sshexpose.py
  python3 croninv.py
  python3 svcdep.py nginx
```

## Human output

Suggested:

```text
serverdoctor: quick health overview

System
  Hostname: web01
  OS: Ubuntu 22.04
  Kernel: 5.15...
  Uptime: 12 days
  Load: 0.12 0.18 0.20

Memory
  Used: 62%
  Swap: 0%

Disk
  /      71% OK
  /var   91% WARN

Services
  failed units: 1
  nginx.service failed [WARN]

Network listeners
  0.0.0.0:22 sshd [INFO all interfaces]
  127.0.0.1:5432 postgres [OK local-only]

Logs
  OOM kills: 0
  Recent warnings: 4

SSH
  active: yes
  password auth: no
  root login: no

Overall: WARN

Next checks:
  python3 svcdep.py nginx
  python3 sshexpose.py
```

## JSON output

Suggested:

```json
{
  "overall": "WARN",
  "system": {},
  "memory": {},
  "disk": [],
  "services": {},
  "listeners": [],
  "logs": {},
  "ssh": {},
  "findings": [],
  "next_checks": []
}
```

## Implementation hints

Use common helper functions where possible.

Suggested functions:

- `collect_system_info()`
- `collect_memory()`
- `collect_disk()`
- `collect_failed_services()`
- `collect_listeners()`
- `collect_recent_log_summary()`
- `collect_ssh_quick()`
- `classify_findings(data)`
- `recommend_next_checks(findings)`

Keep each check independent. If one fails, the report should continue.

Use timeouts for every external command.

## Edge cases

Handle:

- no root permissions
- no systemd
- missing `ss`
- missing `journalctl`
- weird `df` output
- containers where some files are missing
- localized command output if possible by using parse-friendly flags

Set environment variable for commands where useful:

```text
LC_ALL=C
```

## Non-goals

Do not:

- install monitoring
- fix problems automatically
- restart services
- change firewall
- upload results
- scan the public internet

## Suggested tests

1. Parse `/etc/os-release`.
2. Parse `/proc/meminfo`.
3. Parse `df -P` output.
4. Parse `ss -tulpn` output.
5. Classify public DB listener as critical.
6. Overall status becomes WARN/CRITICAL based on findings.

## Definition of done

The tool is done when:

- one command prints a useful server overview
- JSON output works
- missing permissions do not crash it
- it recommends next focused checks
- it stays read-only
