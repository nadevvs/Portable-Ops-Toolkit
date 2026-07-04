# accttrail

## Purpose

Summarize local login records and account inventory for incident response.

## Inputs

- `last`
- `lastlog`
- `/etc/passwd`

## Output

- Recent logins, lastlog sample, account list, findings, and warnings

## Safety

Read-only. Does not lock, unlock, create, remove, or modify accounts.

## Example

```bash
python3 accttrail.py --limit 100
```
