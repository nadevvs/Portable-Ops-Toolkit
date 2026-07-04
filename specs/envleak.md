# envleak

## Purpose

Find secret-like keys in local configuration and environment files without printing values.

## Inputs

- User-selected files/directories
- Defaults including `/etc/environment`, `/etc/profile`, `/etc/default`, and `.env`

## Output

- Path, line number, and key name for secret-like entries

## Safety

Read-only. Values are not printed.

## Example

```bash
python3 envleak.py --paths /etc/default,/srv/app --json
```
