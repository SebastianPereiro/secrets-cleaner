package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/coralogix/go-coralogix-sdk"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
)

var (
	// Command line flags
	project string
	dryrun  bool
	debug   bool
	// Coralogix creds
	coralogix_app_name       string = os.Getenv("CORALOGIX_APP_NAME")
	coralogix_key_gsm_name   string = os.Getenv("CORALOGIX_KEY_GSM_NAME")
	coralogix_subsystem_name        = "secrets-cleaner"
	// Disabled versions to keep
	keepVersions = 2
)

func init() {
	flag.StringVar(&project, "project", "", "Google Cloud Project")
	flag.BoolVar(&dryrun, "dry-run", false, "Just analyze the Secrets and propose the changes")
	flag.BoolVar(&debug, "debug", false, "Add additional debugging output")
	flag.IntVar(&keepVersions, "keepversions", 2, "Disabled versions to keep")
}

type SecretName struct {
	Name string
}

type SecretVersion struct {
	Name              string
	CreateTimeSeconds int64
	CreateTimeNanos   int32
}

// Get all secrets for a given project
func listSecrets(ctx context.Context, c *secretmanager.Client, projectName string) ([]SecretName, error) {
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: projectName,
	}
	var secrets []SecretName
	it := c.ListSecrets(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"timestamp":     time.Now(),
				"unixtimestamp": time.Now().UnixNano(),
				"project":       project,
			}).Fatalf("Failed to get the list of secrets: %v", err)
		}
		secrets = append(secrets, SecretName{Name: resp.Name})
	}
	return secrets, nil
}

// Disable all enabled secret versions except the latest one for a given secret
func disableExceptThelatestVersions(ctx context.Context, c *secretmanager.Client, secretName string) {
	// get all secret versions and store them in slice
	req := &secretmanagerpb.ListSecretVersionsRequest{
		Parent: secretName,
		Filter: "state:ENABLED", // https://cloud.google.com/secret-manager/docs/filtering
	}
	var versions []SecretVersion
	it := c.ListSecretVersions(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"timestamp":     time.Now(),
				"unixtimestamp": time.Now().UnixNano(),
				"project":       project,
			}).Fatalf("Failed to get secret versions: %v", err)
		}
		// versions slice contains the list of secret versions sorted in reverse by create_time (newest first).
		// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1#ListSecretVersionsResponse
		versions = append(versions, SecretVersion{Name: resp.Name, CreateTimeSeconds: resp.CreateTime.Seconds, CreateTimeNanos: resp.CreateTime.Nanos})
	}
	// Show the latest enabled secret version in the debug output
	logrus.WithFields(logrus.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       project,
	}).Debug("The latest enabled secret is : ", versions[0].Name)
	// In case the versions slice contains more than 1 enabled version
	if (len(versions) - 1) > 0 {
		// Iterate throught all elements except the first (latest version) one
		for _, version := range versions[1:] {
			if dryrun {
				logrus.WithFields(logrus.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       project,
				}).Debug("Secrect version to disable: ", version.Name)
			} else {
				// Request to disable
				req := &secretmanagerpb.DisableSecretVersionRequest{
					Name: version.Name,
				}
				resp, err := c.DisableSecretVersion(ctx, req)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"timestamp":     time.Now(),
						"unixtimestamp": time.Now().UnixNano(),
						"project":       project,
					}).Fatalf("Failed to disable secret version: %v", err)
				}
				logrus.WithFields(logrus.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       project,
				}).Info("Disabled the secret version: ", version.Name)
				logrus.WithFields(logrus.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       project,
				}).Debug("Operation responce", resp)
			}
		}
	}
}

// Destroy disabled versions for a given secret
func destroyDisabledVersions(ctx context.Context, c *secretmanager.Client, secretName string) {
	// search only for disabled versions
	req := &secretmanagerpb.ListSecretVersionsRequest{
		Parent: secretName,
		Filter: "state:DISABLED", // https://cloud.google.com/secret-manager/docs/filtering
	}
	var versionsDisabled []SecretVersion
	it := c.ListSecretVersions(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"timestamp":     time.Now(),
				"unixtimestamp": time.Now().UnixNano(),
				"project":       project,
			}).Fatalf("Failed to get secret versions: %v", err)
		}
		versionsDisabled = append(versionsDisabled, SecretVersion{Name: resp.Name, CreateTimeSeconds: resp.CreateTime.Seconds, CreateTimeNanos: resp.CreateTime.Nanos})
	}
	// If we have more disabled versions than keepVersions
	if len(versionsDisabled) > keepVersions {
		for _, version := range versionsDisabled[keepVersions:] {
			if dryrun {
				logrus.WithFields(logrus.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       project,
				}).Debug("Secret version to destroy: ", version.Name)
			} else {
				destroyReq := &secretmanagerpb.DestroySecretVersionRequest{
					Name: version.Name,
				}
				destroyResp, err := c.DestroySecretVersion(ctx, destroyReq)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"timestamp":     time.Now(),
						"unixtimestamp": time.Now().UnixNano(),
						"project":       project,
					}).Fatalf("Failed to destroy secret version: %v", err)
				}
				logrus.WithFields(logrus.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       project,
				}).Info("Destroyed the secret version: ", version.Name)
				logrus.WithFields(logrus.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       project,
				}).Debug("Destroy operation responce", destroyResp)
			}
		}
	}
}

// Show usage options if no project specified
func customHelp() {
	fmt.Println("Usage: cleaner [OPTIONS]")
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
}

func main() {
	// Check the cmd line args
	flag.Parse()
	if project == "" {
		customHelp()
		os.Exit(1)
	}

	// Debug
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		coralogix.SetDebug(true)
	}

	// The main context
	ctx := context.Background()
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       project,
		}).Fatalf("Failed to create Secret Manager client: %v", err)
	}
	defer c.Close()

	// If we have CORALOGIX_KEY_GSM_NAME and CORALOGIX_APP_NAME env variables defined, enable Coralogix logging
	if coralogix_key_gsm_name != "" && coralogix_app_name != "" {
		// Get Coralogix credentials from the secret name obtained from ENV
		// Access the secret from Secret Manager.
		accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
			Name: coralogix_key_gsm_name + "/versions/latest",
		}

		coralogix_private_key, err := c.AccessSecretVersion(ctx, accessRequest)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"timestamp":     time.Now(),
				"unixtimestamp": time.Now().UnixNano(),
				"project":       project,
			}).Fatalf("Failed to access secret version: %v", err)
		}

		// Initialise logging to Coralogix
		// Coralogix docs:
		// https://coralogix.com/docs/go/
		// https://pkg.go.dev/github.com/coralogix/go-coralogix-sdk?utm_source=godoc#section-readme
		CoralogixHook := coralogix.NewCoralogixHook(
			string(coralogix_private_key.Payload.Data),
			coralogix_app_name,
			coralogix_subsystem_name,
		)
		logrus.AddHook(CoralogixHook)
		defer CoralogixHook.Close()
	}

	logrus.WithFields(logrus.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       project,
	}).Info("Starting the secrets cleaner for ", project, " project")

	// Get all project secrets
	secrets, err := listSecrets(ctx, c, "projects/"+project)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       project,
		}).Fatalf("Failed to list secrets: %v", err)
	}

	for _, secret := range secrets {
		disableExceptThelatestVersions(ctx, c, secret.Name)
		destroyDisabledVersions(ctx, c, secret.Name)
	}

	// Exit the app
	logrus.WithFields(logrus.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       project,
	}).Info("Stopping the secrets cleaner")
}
