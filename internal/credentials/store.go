package credentials

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Credentials holds the token and CA certificate for a cluster
type Credentials struct {
	Token  string
	CACert []byte
}

// Store manages credentials for remote clusters
type Store struct {
	mu          sync.RWMutex
	credentials map[string]*Credentials
	client      kubernetes.Interface
	namespace   string
	secretName  string
}

// NewStore creates a new credential store
// If running in-cluster, it will persist credentials to a Kubernetes Secret
func NewStore(namespace, secretName string) (*Store, error) {
	s := &Store{
		credentials: make(map[string]*Credentials),
		namespace:   namespace,
		secretName:  secretName,
	}

	// Try to create in-cluster client
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Not running in cluster, credentials will not be persisted: %v", err)
		return s, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Failed to create Kubernetes client, credentials will not be persisted: %v", err)
		return s, nil
	}

	s.client = client

	// Load existing credentials from Secret
	if err := s.loadFromSecret(context.Background()); err != nil {
		log.Printf("Failed to load credentials from secret: %v", err)
	}

	return s, nil
}

// Get returns credentials for a cluster
func (s *Store) Get(cluster string) (*Credentials, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	creds, ok := s.credentials[cluster]
	return creds, ok
}

// Set stores credentials for a cluster and persists to Secret
func (s *Store) Set(ctx context.Context, cluster string, creds *Credentials) error {
	s.mu.Lock()
	s.credentials[cluster] = creds
	s.mu.Unlock()

	// Persist to Secret if we have a client
	if s.client != nil {
		if err := s.saveToSecret(ctx); err != nil {
			return fmt.Errorf("persisting credentials: %w", err)
		}
	}

	return nil
}

// loadFromSecret loads credentials from the Kubernetes Secret
func (s *Store) loadFromSecret(ctx context.Context) error {
	if s.client == nil {
		return nil
	}

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			log.Printf("Credentials secret %s/%s not found, starting fresh", s.namespace, s.secretName)
			return nil
		}
		return fmt.Errorf("getting secret: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse credentials from secret data
	// Format: cluster-{name}-token, cluster-{name}-ca.crt
	clusters := make(map[string]bool)
	for key := range secret.Data {
		if len(key) > 8 && key[:8] == "cluster-" {
			// Extract cluster name from key
			suffix := key[8:]
			if len(suffix) > 6 && suffix[len(suffix)-6:] == "-token" {
				clusters[suffix[:len(suffix)-6]] = true
			} else if len(suffix) > 7 && suffix[len(suffix)-7:] == "-ca.crt" {
				clusters[suffix[:len(suffix)-7]] = true
			}
		}
	}

	for cluster := range clusters {
		tokenKey := fmt.Sprintf("cluster-%s-token", cluster)
		caKey := fmt.Sprintf("cluster-%s-ca.crt", cluster)

		token, hasToken := secret.Data[tokenKey]
		ca, hasCA := secret.Data[caKey]

		if hasToken && hasCA {
			s.credentials[cluster] = &Credentials{
				Token:  string(token),
				CACert: ca,
			}
			log.Printf("Loaded credentials for cluster %s from secret", cluster)
		}
	}

	return nil
}

// saveToSecret persists all credentials to the Kubernetes Secret
func (s *Store) saveToSecret(ctx context.Context) error {
	if s.client == nil {
		return nil
	}

	s.mu.RLock()
	data := make(map[string][]byte)
	for cluster, creds := range s.credentials {
		data[fmt.Sprintf("cluster-%s-token", cluster)] = []byte(creds.Token)
		data[fmt.Sprintf("cluster-%s-ca.crt", cluster)] = creds.CACert
	}
	s.mu.RUnlock()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.secretName,
			Namespace: s.namespace,
		},
		Data: data,
	}

	// Try to update first, create if not exists
	_, err := s.client.CoreV1().Secrets(s.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("creating secret: %w", err)
			}
			log.Printf("Created credentials secret %s/%s", s.namespace, s.secretName)
			return nil
		}
		return fmt.Errorf("updating secret: %w", err)
	}

	log.Printf("Updated credentials secret %s/%s", s.namespace, s.secretName)
	return nil
}

// LoadFromFiles loads bootstrap credentials from files (for initial setup)
func (s *Store) LoadFromFiles(cluster, tokenPath, caPath string) error {
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("reading token file: %w", err)
	}

	ca, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("reading CA file: %w", err)
	}

	s.mu.Lock()
	s.credentials[cluster] = &Credentials{
		Token:  string(token),
		CACert: ca,
	}
	s.mu.Unlock()

	log.Printf("Loaded bootstrap credentials for cluster %s from files", cluster)
	return nil
}

// ParseBase64CACert decodes a base64-encoded CA certificate
func ParseBase64CACert(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
