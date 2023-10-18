# Secret-cleaner
## _Clean outdated Google Secret Manager Secrets_

This app disables all GSM secrets except the latest one and destroys all disabled secrets

## Command line switches
```
-project # GCP Project name
-debug   # More diag output
-dry-run # No real changes just output
```
## Example
```./cleaner -project gcp-project -dry-run -debug```