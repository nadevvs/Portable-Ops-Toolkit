# iocscan

## Purpose

Scan local files for exact-match offline indicators of compromise.

## Inputs

- IOC file with `sha256:`, `path:`, `domain:`, `ip:`, or `text:` entries
- User-selected scan paths

## Output

- Matched indicators and file paths

## Safety

Read-only. Does not quarantine or delete files. File and byte limits bound scan cost.

## Example

```bash
python3 iocscan.py --iocs configs/iocscan.example.ioc --paths /etc,/tmp
```
