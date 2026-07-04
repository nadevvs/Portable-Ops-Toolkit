# suidscan

## Purpose

Find SUID/SGID files and world-writable directories that deserve review.

## Inputs

- User-selected roots, defaulting to common system and temporary directories

## Output

- Interesting file metadata and severity findings

## Safety

Read-only. Does not change file ownership, modes, ACLs, or extended attributes.

## Example

```bash
python3 suidscan.py --paths /usr/bin,/tmp --max-entries 10000
```
