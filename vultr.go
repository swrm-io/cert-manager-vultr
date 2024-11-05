package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cmacmev1alpha1 "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/vultr/govultr/v3"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type vultr struct {
	client *govultr.Client
}

// vultrClient returns a configured client to work with the vultr API.
func vultrClient(clientset *kubernetes.Clientset, req *cmacmev1alpha1.ChallengeRequest) (*vultr, error) {
	providerCfg := VultrProviderConfig{}

	if req.Config == nil {
		return nil, fmt.Errorf("%w: missing vultr solver config", errInvalidProviderConfig)
	}

	if err := json.Unmarshal(req.Config.Raw, &providerCfg); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidProviderConfig, err)
	}

	if providerCfg.APIKeySecretRef.Name == "" {
		return nil, fmt.Errorf("%w: missing apiKeySecretRef.name", errInvalidProviderConfig)
	}

	if providerCfg.APIKeySecretRef.Key == "" {
		return nil, fmt.Errorf("%w: missing apiKeySecretRef.key", errInvalidProviderConfig)
	}

	namespace := req.ResourceNamespace
	secretName := providerCfg.APIKeySecretRef.Name
	secretAPIKey := providerCfg.APIKeySecretRef.Key

	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	secret, err := clientset.CoreV1().Secrets(namespace).Get(
		ctx,
		secretName,
		metav1.GetOptions{},
	)

	// if we error here, its an upstream k8s issue.
	if err != nil {
		return nil, err
	}

	apiKey := secret.Data[secretAPIKey]
	if apiKey == nil {
		return nil, fmt.Errorf("%w: api key not set", errInvalidVultrConfig)
	}

	auth := strings.TrimSpace(string(apiKey))
	config := &oauth2.Config{}
	token := &oauth2.Token{AccessToken: auth}
	ts := config.TokenSource(context.Background(), token)

	oathClient := oauth2.NewClient(context.Background(), ts)

	client := govultr.NewClient(oathClient)
	client.SetUserAgent("cert-manager-vultr")

	return &vultr{client: client}, nil
}

// zoneExists validates that you have the correct
// zone in vultr
func (v *vultr) zoneExists(zone string) error {
	_, err := v.client.Domain.Get(context.Background(), zone)
	return err
}

// getTXTRecord validates that there is an existing record that matches both
// the fqdn and given record data.
func (v *vultr) getTXTRecord(zone string, fqdn string, key string) (*govultr.DomainRecord, error) {
	subdomain := strings.TrimSuffix(fqdn, "."+zone)

	listOptions := &govultr.ListOptions{PerPage: 100}
	for {
		rl, meta, err := v.client.DomainRecord.List(context.Background(), zone, listOptions)
		if err != nil {
			return nil, err
		}

		for _, i := range rl {
			if i.Type == "TXT" {
				if i.Name == subdomain {
					if i.Data == fmt.Sprintf("\"%s\"", key) {
						return &i, nil
					}
				}
			}
		}

		if meta.Links.Next == "" {
			break
		}
		listOptions.Cursor = meta.Links.Next
	}

	return nil, nil
}

// createTXTRecord creates a text record.
func (v *vultr) createTXTRecord(zone string, fqdn string, key string) error {
	record := &govultr.DomainRecordReq{
		Name: fqdn,
		Type: "TXT",
		Data: key,
		TTL:  60,
	}

	_, err := v.client.DomainRecord.Create(context.Background(), zone, record)
	return err

}

func (v *vultr) deleteTXTRecord(zone string, record *govultr.DomainRecord) error {
	return v.client.DomainRecord.Delete(context.Background(), zone, record.ID)
}
