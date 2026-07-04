# opsrun

## Purpose

Run selected toolkit tools as a local profile and collect JSON reports into one bundle.

## Inputs

- Local toolkit scripts
- Profile selection: `ops`, `dfir`, `posture`, or `all`
- Optional explicit comma-separated `--tools`

## Output

- Consolidated JSON report
- Optional saved bundle under `STATE/opsrun/TIMESTAMP/bundle.json`

## Safety

Only runs local toolkit scripts. Writes only its own bundle when `--save` is used.
Stateful/targeted tools are skipped by default unless `--include-stateful` is set.

## Example

```bash
python3 opsrun.py --profile posture --json --save --state ./ops_state
python3 opsrun.py --tools netaudit,logtriage,persistwatch --json
```
