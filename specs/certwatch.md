# certwatch

## Purpose

Inventory local X.509 certificates and flag expiration windows.

## Inputs

- PEM/CRT/CER files under selected directories

## Output

- Certificate paths, expiry metadata, findings, and overall status

## Safety

Read-only. Does not renew, delete, or modify certificates.

## Example

```bash
python3 certwatch.py --paths /etc/ssl/certs,/etc/letsencrypt/live
```
