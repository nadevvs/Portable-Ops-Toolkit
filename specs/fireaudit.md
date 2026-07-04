# fireaudit

## Purpose

Audit local firewall posture without modifying firewall rules.

## Inputs

- `ufw status verbose`
- `iptables -L -n`
- `nft list ruleset`

## Output

- Firewall availability, default policies, basic rule posture, and findings

## Safety

Read-only. Does not add, remove, flush, reload, or persist firewall rules.

## Example

```bash
python3 fireaudit.py
```
