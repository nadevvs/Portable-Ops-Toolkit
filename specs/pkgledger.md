# pkgledger

## Purpose

Build an offline package inventory and summarize recent package changes.

## Inputs

- `dpkg-query`, `rpm`, or `apk`
- Local apt history logs when present

## Output

- Package manager, package count, recent changes, and findings

## Safety

Read-only. Does not update repositories, install packages, or access vulnerability feeds.

## Example

```bash
python3 pkgledger.py --limit 100 --json
```
