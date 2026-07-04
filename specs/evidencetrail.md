# evidencetrail

## Purpose

Create and verify file metadata/hash manifests for practical evidence tracking.

## Inputs

- Selected files or directories
- Optional target list file

## Output

- Manifest under `STATE/evidencetrail/CASE/manifest.json`
- Verification report with changed hashes

## Safety

Only writes its own manifest under `--state`. Does not copy, delete, or alter evidence content.

## Example

```bash
python3 evidencetrail.py record --case web1 --paths /etc/passwd --state ./ops_state
python3 evidencetrail.py verify --case web1 --state ./ops_state
```
