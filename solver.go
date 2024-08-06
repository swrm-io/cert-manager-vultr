package main

import (
	cmacmev1alpha1 "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// VultrProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
type VultrProviderConfig struct {
	APIKeySecretRef cmmetav1.SecretKeySelector `json:"apiKeySecretRef"`
}

// VultrSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type VultrSolver struct {
	logger *zap.Logger
	client *kubernetes.Clientset
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
func (v *VultrSolver) Name() string {
	return "vultr"
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initializing
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (v *VultrSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		v.logger.Error(err.Error())
		return err
	}
	v.client = client

	return nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (v *VultrSolver) Present(req *cmacmev1alpha1.ChallengeRequest) error {
	// Remove trailing . from ResolvedZone because the Vultr API
	// doesn't like it.
	zone := util.UnFqdn(req.ResolvedZone)
	fqdn := util.UnFqdn(req.ResolvedFQDN)

	// create a logger with standard fields
	logger := v.logger.With(zap.Any("uid", req.UID), zap.String("zone", zone), zap.String("fqdn", fqdn), zap.String("key", req.Key))

	client, err := vultrClient(v.client, req)
	if err != nil {
		logger.Error("error creating vultr client", zap.Error(err))
		return err
	}

	// validate that the wanted zone exists before we
	// even try to continue
	err = client.zoneExists(zone)
	if err != nil {
		logger.Error("vultr zone error", zap.Error(err))
		return err
	}

	// lookup the record, vultr will error if we try to create
	// the same record with the same key.  Return nil if one exists.
	record, err := client.getTXTRecord(zone, fqdn, req.Key)
	if err != nil {
		logger.Error("error getting DNS records", zap.Error(err))
		return err
	}

	if record != nil {
		logger.Info("record exists")
		return nil
	}

	logger.Info("creating TXT record")

	err = client.createTXTRecord(zone, fqdn, req.Key)
	if err != nil {
		logger.Error("error creating record", zap.Error(err))
		return err
	}

	// Return because we created the Record
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (v *VultrSolver) CleanUp(req *cmacmev1alpha1.ChallengeRequest) error {
	// Remove trailing . from ResolvedZone because the Vultr API
	// doesn't like it.
	zone := util.UnFqdn(req.ResolvedZone)
	fqdn := util.UnFqdn(req.ResolvedFQDN)

	// create a logger with standard fields
	logger := v.logger.With(zap.Any("uid", req.UID), zap.String("zone", zone), zap.String("fqdn", fqdn))

	client, err := vultrClient(v.client, req)
	if err != nil {
		logger.Error("error creating vultr client", zap.Error(err))
		return err
	}

	// lookup the record, vultr will error if we try to create
	// the same record with the same key.  Return nil if one exists.
	record, err := client.getTXTRecord(zone, fqdn, req.Key)
	if err != nil {
		logger.Error("error getting DNS records", zap.Error(err))
		return err
	}

	if record == nil {
		logger.Info("record doesn't exist")
		return nil
	}

	err = client.deleteTXTRecord(zone, record)
	if err != nil {
		logger.Error("error deleting record", zap.Error(err))
		return err
	}

	logger.Info("record deleted")

	return nil
}
