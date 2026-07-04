# Task: `svcdep` — Service Dependency Checker

## Goal

Create a lightweight Python CLI tool that diagnoses one systemd service and shows the most useful related information in one place.

The goal is not to replace `systemctl`, but to avoid manually running many commands during troubleshooting.

Example:

```bash
python3 svcdep.py nginx
python3 svcdep.py ssh --json
python3 svcdep.py postgresql --state /media/usb/ops-state
```

## Main questions this tool answers

For a selected service:

- Is it active?
- Is it enabled?
- When was it last started?
- Has it failed recently?
- What ports is it listening on?
- Which processes belong to it?
- What are the last important log lines?
- What unit files or drop-in overrides are used?
- Are there obvious dependency problems?

## Scope

Implement for Linux with systemd first.

The tool should still degrade gracefully on non-systemd systems by showing a clear warning.

## CLI

Required:

```bash
python3 svcdep.py SERVICE_NAME
python3 svcdep.py SERVICE_NAME --json
python3 svcdep.py SERVICE_NAME --no-color
python3 svcdep.py SERVICE_NAME --logs 50
python3 svcdep.py SERVICE_NAME --state PATH
```

Optional:

```bash
python3 svcdep.py SERVICE_NAME --deep
```

`--deep` may run extra slower checks.

## Data to collect

### 1. Basic service status

Use:

```bash
systemctl show SERVICE --no-pager
systemctl status SERVICE --no-pager
```

Parse useful fields from `systemctl show`:

- `Id`
- `LoadState`
- `ActiveState`
- `SubState`
- `UnitFileState`
- `MainPID`
- `ExecMainPID`
- `ExecMainStatus`
- `Restart`
- `NRestarts`
- `FragmentPath`
- `DropInPaths`
- `Description`
- `After`
- `Requires`
- `Wants`

Output example:

```text
Service: nginx.service
State: active/running
Enabled: enabled
Main PID: 923
Restarts: 0
Unit file: /lib/systemd/system/nginx.service
Drop-ins: none
```

### 2. Process information

If `MainPID` exists, inspect:

```text
/proc/<pid>/cmdline
/proc/<pid>/exe
/proc/<pid>/status
/proc/<pid>/cwd
```

Show:

- PID
- user
- command
- executable path
- current working directory
- memory RSS if available

Also find child processes:

```bash
ps -eo pid,ppid,user,comm,args
```

### 3. Listening ports

Use:

```bash
ss -tulpn
```

Parse entries that include the service process PID or process name.

Show:

```text
TCP 0.0.0.0:80    pid=923 nginx
TCP 0.0.0.0:443   pid=923 nginx
```

If permission prevents seeing process names, still show what can be found and warn.

### 4. Recent logs

Use:

```bash
journalctl -u SERVICE -n N --no-pager
```

Default N: 30.

Also support:

```bash
journalctl -u SERVICE --since "1 hour ago" --no-pager
```

If not implementing `--since`, keep only `--logs`.

Flag suspicious lines containing:

- failed
- error
- denied
- refused
- timeout
- killed
- oom
- permission
- traceback
- exception

Do not over-detect. Just mark them as notable.

### 5. Dependencies

Parse fields:

- `Requires`
- `Wants`
- `After`
- `Before`

For each required/wanted unit, optionally check if it exists and is active:

```bash
systemctl is-active UNIT
systemctl is-enabled UNIT
```

Keep this lightweight. Do not traverse endlessly.

### 6. Unit file and drop-ins

Display paths:

- main unit file
- drop-in override files

If readable, show short metadata:

- file exists
- owner
- permissions
- last modified time

Do not dump the whole unit file by default.

Optional `--deep` can show important directives like:

- `ExecStart`
- `User`
- `Group`
- `EnvironmentFile`
- `WorkingDirectory`
- `Restart`

## Output format

### Human output

Suggested layout:

```text
svcdep: nginx.service

Status
  State: active/running
  Enabled: enabled
  PID: 923
  Restarts: 0

Processes
  923 root nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
  924 www-data nginx: worker process

Listening ports
  tcp 0.0.0.0:80
  tcp 0.0.0.0:443

Unit files
  /lib/systemd/system/nginx.service
  Drop-ins: none

Dependencies
  Requires: system.slice
  Wants: network-online.target

Recent notable logs
  [WARN] 2026-... connect() failed ...
```

### JSON output

Should include:

```json
{
  "service": "nginx.service",
  "status": {},
  "processes": [],
  "ports": [],
  "unit_files": [],
  "dependencies": {},
  "logs": [],
  "warnings": []
}
```

## Edge cases

Handle:

- service not found
- service exists but inactive
- systemctl missing
- journalctl permission denied
- no root permissions for `ss -p`
- service with multiple processes
- service name passed without `.service`
- templated service like `foo@bar.service`

## Implementation hints

Normalize service name:

- If user passes `nginx`, try `nginx.service`.
- If user passes `ssh.service`, keep it.

Use a shared `run_cmd()` helper.

Avoid `shell=True`.

Use `/proc` directly where possible.

Use small pure functions:

- `parse_systemctl_show(text)`
- `parse_ss_output(text)`
- `parse_ps_output(text)`
- `extract_notable_logs(lines)`

These are easy to test.

## Non-goals

Do not:

- restart the service
- enable/disable the service
- edit unit files
- modify dependencies
- install packages
- upload logs anywhere

## Suggested tests

Create parser tests using sample strings:

1. `parse_systemctl_show()` extracts `ActiveState`, `MainPID`, `FragmentPath`.
2. `parse_ss_output()` extracts protocol, address, port, process, pid.
3. `extract_notable_logs()` flags error/warn lines.
4. Missing command returns warning, not crash.

## Definition of done

The tool is done when:

- `python3 svcdep.py nginx` prints a useful report
- `--json` returns valid JSON
- missing systemd results in a clear warning
- no root required for basic checks
- logs and ports are best-effort
