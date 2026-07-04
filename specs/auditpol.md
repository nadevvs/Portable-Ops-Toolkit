# auditpol

## Purpose

Review local Linux audit policy and logging posture.

## Inputs

- `auditctl -s`
- `auditctl -l`
- `/etc/audit/audit.rules`
- `/etc/audit/rules.d/audit.rules`
- `/etc/audit/auditd.conf`

## Output

- Audit status, rule summary, auditd config, findings, and warnings

## Safety

Read-only. Does not load, delete, or make audit rules immutable.

## Example

```bash
python3 auditpol.py --json
```
