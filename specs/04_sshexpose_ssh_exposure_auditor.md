# Task: `sshexpose` — SSH Exposure Auditor

## Goal

Create a lightweight Python CLI tool that audits the local SSH server configuration and recent SSH exposure indicators.

It should help quickly answer whether SSH is exposed safely.

Example:

```bash
python3 sshexpose.py
python3 sshexpose.py --json
python3 sshexpose.py --logs 100
```

## Main questions this tool answers

- Is SSH installed and running?
- Which address and port is SSH listening on?
- Is root login disabled?
- Is password authentication disabled?
- Are public key permissions safe?
- Which users have authorized SSH keys?
- Were there recent successful or failed logins?
- Is Fail2ban active, if installed?
- Are there obvious risky settings?

## Scope

Read local SSH configuration and logs.

Read-only only.

Target OpenSSH server on Linux.

## CLI

Required:

```bash
python3 sshexpose.py
python3 sshexpose.py --json
python3 sshexpose.py --no-color
python3 sshexpose.py --logs 100
python3 sshexpose.py --state PATH
```

Optional:

```bash
python3 sshexpose.py --users
python3 sshexpose.py --deep
```

`--users` inspects user home directories for `.ssh/authorized_keys`, where permissions allow.

`--deep` can run extra checks.

## Checks

### 1. SSH service status

Try common unit names:

```text
ssh.service
sshd.service
```

Use:

```bash
systemctl is-active ssh
systemctl is-enabled ssh
systemctl status ssh --no-pager
```

Gracefully handle systems without systemd.

### 2. Listening ports

Use:

```bash
ss -tulpn
```

Find `sshd` listeners.

Show:

```text
0.0.0.0:22
[::]:22
127.0.0.1:2222
```

Classify:

- loopback-only = lower exposure
- `0.0.0.0` / `::` = public-facing or all interfaces
- custom port = informational, not automatically safe

### 3. Config files

Read:

```text
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/*.conf
```

Parse key settings:

- `Port`
- `ListenAddress`
- `PermitRootLogin`
- `PasswordAuthentication`
- `PubkeyAuthentication`
- `KbdInteractiveAuthentication`
- `ChallengeResponseAuthentication`
- `AllowUsers`
- `AllowGroups`
- `DenyUsers`
- `DenyGroups`
- `MaxAuthTries`
- `PermitEmptyPasswords`
- `X11Forwarding`
- `AllowTcpForwarding`
- `ClientAliveInterval`
- `UsePAM`

Important: OpenSSH config semantics can be complex. Keep parser simple but honest.

If possible, prefer:

```bash
sshd -T
```

This prints effective config. It may require root or valid config access. Use it if available, otherwise parse files.

### 4. Risk classification

Suggested warnings:

Critical:
- `PermitRootLogin yes`
- `PermitEmptyPasswords yes`
- SSH listening on all interfaces with password auth enabled
- `authorized_keys` file writable by group/others
- `.ssh` directory writable by group/others

Warning:
- `PasswordAuthentication yes`
- `KbdInteractiveAuthentication yes`
- no `AllowUsers` or `AllowGroups` on exposed server
- `MaxAuthTries` high, for example above 6
- root has authorized keys
- SSH config file writable by group/others
- unknown included config file unreadable

Info:
- custom port
- key-only login
- root login disabled/prohibit-password
- Fail2ban active

Do not exaggerate. The tool should say "review recommended", not "hacked".

### 5. Authorized keys inventory

If `--users` is enabled:

Use `getent passwd` or `/etc/passwd`.

For normal users with home directories, inspect:

```text
~/.ssh
~/.ssh/authorized_keys
```

For each accessible file, report:

- username
- path
- number of keys
- file mode
- owner
- group
- suspicious permissions
- key types present, for example `ssh-ed25519`, `ssh-rsa`

Do not print full public keys by default. Print short fingerprints if implemented.

Fingerprint can be simple SHA256 of key material if easy, but not required.

### 6. Recent auth logs

Check common locations:

```text
/var/log/auth.log
/var/log/secure
```

Also try:

```bash
journalctl -u ssh -n N --no-pager
journalctl -u sshd -n N --no-pager
```

Parse:

- failed password attempts
- accepted publickey/password
- invalid user attempts
- disconnected from
- userauth_pubkey

Show top IPs and usernames.

Default N: 100 log lines.

### 7. Fail2ban

If installed:

```bash
fail2ban-client status
fail2ban-client status sshd
```

Show whether sshd jail exists and banned count if available.

If not installed, just show info.

## Output format

### Human output

Suggested:

```text
sshexpose: SSH exposure audit

Service
  active: yes
  enabled: yes

Listening
  0.0.0.0:22 [WARN all interfaces]
  [::]:22 [WARN all interfaces]

Effective config
  PermitRootLogin: no [OK]
  PasswordAuthentication: no [OK]
  PubkeyAuthentication: yes [OK]
  MaxAuthTries: 3 [OK]

Authorized keys
  deploy: 2 keys, perms OK
  root: 1 key [WARN review root access]

Recent auth
  failed logins: 42
  accepted logins: 3
  top failed IP: 1.2.3.4 count=12

Summary
  Risk: MEDIUM
  Main warning: SSH listens on all interfaces
```

### JSON output

Suggested:

```json
{
  "service": {},
  "listeners": [],
  "config": {},
  "authorized_keys": [],
  "auth_log_summary": {},
  "fail2ban": {},
  "findings": [],
  "risk": "LOW"
}
```

## Risk scoring

Keep simple:

- Critical finding adds 3
- Warning adds 1
- Info adds 0

Final:
- 0 = LOW
- 1-2 = MEDIUM
- 3+ = HIGH

Show that this is a heuristic.

## Implementation hints

Suggested functions:

- `find_ssh_service()`
- `parse_sshd_config(text)`
- `parse_sshd_T(text)`
- `parse_ss_listeners(text)`
- `inspect_authorized_keys(path)`
- `parse_auth_log(lines)`
- `score_findings(findings)`

Prefer `sshd -T` if possible. It gives effective lowercase keys.

Use `shlex.split()` carefully if parsing config lines with arguments.

## Edge cases

Handle:

- no SSH server installed
- config includes files
- permission denied reading logs
- root-only files
- `sshd -T` fails due to missing privilege or invalid config
- distro uses `ssh.service` vs `sshd.service`
- IPv6 listeners
- multiple ports
- `Match` blocks in sshd config

For `Match` blocks: simple parser may skip or warn that conditional config is not fully evaluated.

## Non-goals

Do not:

- change SSH config
- restart SSH
- ban IPs
- delete keys
- print private keys
- print complete public keys unless user adds future flag

## Suggested tests

1. Parse `sshd -T` output.
2. Parse basic `sshd_config`.
3. Detect `PermitRootLogin yes` critical.
4. Detect password auth warning.
5. Parse failed and accepted login log lines.
6. Detect unsafe `.ssh` permissions.

## Definition of done

The tool is done when:

- it reports SSH service status
- it reports SSH listeners
- it reports main SSH security settings
- it summarizes recent auth attempts
- it optionally inventories authorized keys
- it supports JSON
- it is read-only
