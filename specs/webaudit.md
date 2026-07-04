# webaudit

## Purpose

Audit local nginx/apache configuration for exposure and logging leads.

## Inputs

- nginx/apache config files under selected directories

## Output

- Parsed directives, findings, warnings, and overall status

## Safety

Read-only. Does not reload, edit, enable, disable, or test web server services.

## Example

```bash
python3 webaudit.py --paths /etc/nginx,/etc/apache2 --json
```
