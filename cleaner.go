package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
)

// Command line flags
var (
	project string
	dryrun  bool
	debug   bool
)

func init() {
	flag.StringVar(&project, "project", "", "Google Cloud Project")
	flag.BoolVar(&dryrun, "dry-run", false, "Just analyze the Secrets and propose the changes")
	flag.BoolVar(&debug, "debug", false, "Add additional debugging output")
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
			log.Fatalf("Failed to get the list of secrets: %v", err)
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
			log.Fatalf("Failed to get secret versions: %v", err)
		}
		versions = append(versions, SecretVersion{Name: resp.Name, CreateTimeSeconds: resp.CreateTime.Seconds, CreateTimeNanos: resp.CreateTime.Nanos})
	}
	if debug {
		fmt.Println("Versions found:")
		fmt.Println(versions)
	}
	// find the latest version by comparing the creation timestamp (unix seconds + nanoseconds)
	var latestVerName string
	highestTimestamp := int64(0)
	highestTimestampNano := int32(0)
	for _, version := range versions {
		timestamp := version.CreateTimeSeconds
		timestampNano := version.CreateTimeNanos
		// compare unix seconds
		if timestamp > highestTimestamp {
			highestTimestamp = timestamp
			highestTimestampNano = timestampNano
			latestVerName = version.Name
		}
		// if secrets have identical unix timestamps compare the nanoseconds part
		if timestamp == highestTimestamp && timestampNano > highestTimestampNano {
			highestTimestampNano = timestampNano
			latestVerName = version.Name
		}
	}
	// disable all versions except the latest
	for _, version := range versions {
		if version.Name != latestVerName {
			req := &secretmanagerpb.DisableSecretVersionRequest{
				Name: version.Name,
			}
			if dryrun {
				fmt.Println("Secret to disable and destroy: ", version.Name)
			} else {
				resp, err := c.DisableSecretVersion(ctx, req)
				if err != nil {
					log.Fatalf("Failed to disable secret version: %v", err)
				}
				fmt.Println("Disabled secret version: ", version.Name)
				if debug {
					fmt.Println("Operation responce", resp)
				}
			}
		}
	}
}

// Destroy all disabled versions for a given secret
func destroyDisabledVersions(ctx context.Context, c *secretmanager.Client, secretName string) {
	// search only for disabled versions
	req := &secretmanagerpb.ListSecretVersionsRequest{
		Parent: secretName,
		Filter: "state:DISABLED", // https://cloud.google.com/secret-manager/docs/filtering
	}
	it := c.ListSecretVersions(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to get secret versions: %v", err)
		}
		if dryrun {
			fmt.Println("Secret to destroy: ", resp.Name)
		} else {
			destroyReq := &secretmanagerpb.DestroySecretVersionRequest{
				Name: resp.Name,
			}
			destroyResp, err := c.DestroySecretVersion(ctx, destroyReq)
			if err != nil {
				log.Fatalf("Failed to destroy secret version: %v", err)
			}
			fmt.Println("Destroyed secret version: ", resp.Name)
			if debug {
				fmt.Println("Operation responce", destroyResp)
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
	flag.Parse()
	if project == "" {
		customHelp()
		os.Exit(1)
	}
	ctx := context.Background()
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create Secret Manager client: %v", err)
	}
	defer c.Close()

	secrets, err := listSecrets(ctx, c, "projects/"+project)
	if err != nil {
		log.Fatalf("Failed to list secrets: %v", err)
	}

	for _, secret := range secrets {
		if debug {
			fmt.Println("Analyzing secret: ", secret)
		}
		disableExceptThelatestVersions(ctx, c, secret.Name)
		destroyDisabledVersions(ctx, c, secret.Name)
	}
}
