# Secret-cleaner
## _Clean outdated Google Secret Manager Secrets_

This app disables all GSM secrets except the latest, keeps several disabled versions (2 by default) and destroys the rest

## Command line switches
```
-project      # GCP Project name
-keepversions # Number of disabled versions to keep
-debug        # More diag output
-dry-run      # No real changes just output
```

## Environment variables
- ```CORALOGIX_APP_NAME``` - Coralogix application name
- ```CORALOGIX_KEY_GSM_NAME``` - Google Secret Manager secret name with Coralogix private key (make sure the secrets cleaner app has access to this secret via Application Default Credentials). Example value: projects/1234566789/secrets/secrets-cleaner-namespace-coralogix-private-key

## Example
```./cleaner -project gcp-project -dry-run -debug```