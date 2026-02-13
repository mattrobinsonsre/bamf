package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// K8sSecretCertStore stores certificates in a Kubernetes Secret.
// Used when the agent runs as a pod in Kubernetes.
//
// The agent needs RBAC permissions to create/get/update the Secret:
//
//	rules:
//	  - apiGroups: [""]
//	    resources: ["secrets"]
//	    resourceNames: ["<secret-name>"]
//	    verbs: ["get", "update", "patch"]
//	  - apiGroups: [""]
//	    resources: ["secrets"]
//	    verbs: ["create"]
type K8sSecretCertStore struct {
	client     kubernetes.Interface
	namespace  string
	secretName string

	// Local file cache for TLS loading (crypto/tls needs files)
	dataDir  string
	certFile string
	keyFile  string
	caFile   string
}

// NewK8sSecretCertStore creates a Kubernetes Secret-based certificate store.
// It uses in-cluster config to connect to the Kubernetes API.
//
// Parameters:
//   - namespace: Kubernetes namespace (usually from BAMF_NAMESPACE env var or downward API)
//   - secretName: Name of the Secret to store certificates in
//   - dataDir: Local directory to cache certificates for TLS loading
func NewK8sSecretCertStore(namespace, secretName, dataDir string) (*K8sSecretCertStore, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return &K8sSecretCertStore{
		client:     client,
		namespace:  namespace,
		secretName: secretName,
		dataDir:    dataDir,
		certFile:   filepath.Join(dataDir, "agent.crt"),
		keyFile:    filepath.Join(dataDir, "agent.key"),
		caFile:     filepath.Join(dataDir, "ca.crt"),
	}, nil
}

func (s *K8sSecretCertStore) HasCertificates(ctx context.Context) bool {
	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		return false
	}

	_, hasCert := secret.Data["tls.crt"]
	_, hasKey := secret.Data["tls.key"]
	return hasCert && hasKey
}

func (s *K8sSecretCertStore) LoadCertificates(ctx context.Context) (cert, key, ca []byte, err error) {
	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get secret %s/%s: %w", s.namespace, s.secretName, err)
	}

	cert, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("secret %s/%s missing tls.crt", s.namespace, s.secretName)
	}

	key, ok = secret.Data["tls.key"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("secret %s/%s missing tls.key", s.namespace, s.secretName)
	}

	ca, ok = secret.Data["ca.crt"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("secret %s/%s missing ca.crt", s.namespace, s.secretName)
	}

	// Write to local files for TLS loading (crypto/tls.LoadX509KeyPair needs files)
	if err := s.writeLocalCache(cert, key, ca); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write local cache: %w", err)
	}

	return cert, key, ca, nil
}

func (s *K8sSecretCertStore) SaveCertificates(ctx context.Context, cert, key, ca []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.secretName,
			Namespace: s.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "bamf",
				"app.kubernetes.io/component": "agent",
				"app.kubernetes.io/managed-by": "bamf-agent",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": cert,
			"tls.key": key,
			"ca.crt":  ca,
		},
	}

	// Try to create first
	_, err := s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err == nil {
		// Created successfully, write local cache
		return s.writeLocalCache(cert, key, ca)
	}

	if !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create secret %s/%s: %w", s.namespace, s.secretName, err)
	}

	// Secret exists, update it
	_, err = s.client.CoreV1().Secrets(s.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update secret %s/%s: %w", s.namespace, s.secretName, err)
	}

	return s.writeLocalCache(cert, key, ca)
}

// writeLocalCache writes certificates to local files for TLS loading.
func (s *K8sSecretCertStore) writeLocalCache(cert, key, ca []byte) error {
	if err := os.MkdirAll(s.dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	if err := os.WriteFile(s.certFile, cert, 0600); err != nil {
		return fmt.Errorf("failed to write cert file: %w", err)
	}
	if err := os.WriteFile(s.keyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}
	if err := os.WriteFile(s.caFile, ca, 0644); err != nil {
		return fmt.Errorf("failed to write CA file: %w", err)
	}

	return nil
}

// CertFile returns the path to the local certificate file cache.
func (s *K8sSecretCertStore) CertFile() string { return s.certFile }

// KeyFile returns the path to the local key file cache.
func (s *K8sSecretCertStore) KeyFile() string { return s.keyFile }

// CAFile returns the path to the local CA file cache.
func (s *K8sSecretCertStore) CAFile() string { return s.caFile }

// IsRunningInKubernetes returns true if the process appears to be running in a Kubernetes pod.
func IsRunningInKubernetes() bool {
	// Check for Kubernetes service account token (mounted by default in pods)
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	// Check for explicit env var
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	return false
}

// GetNamespace returns the namespace the pod is running in.
func GetNamespace() string {
	// Try downward API / env var first
	if ns := os.Getenv("BAMF_NAMESPACE"); ns != "" {
		return ns
	}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	// Read from service account mount
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		return string(data)
	}
	return "default"
}
