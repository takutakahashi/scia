package secrets

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesStore struct {
	client    kubernetes.Interface
	namespace string
	users     map[string]string
}

func NewKubernetesStore(client kubernetes.Interface, namespace string, users map[string]string) (*KubernetesStore, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("kubernetes namespace is required")
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("at least one user secret mapping is required for kubernetes mode")
	}
	copied := make(map[string]string, len(users))
	for userID, secretName := range users {
		if userID == "" {
			return nil, fmt.Errorf("user id cannot be empty")
		}
		if secretName == "" {
			return nil, fmt.Errorf("user %q is missing secretName", userID)
		}
		copied[userID] = secretName
	}
	return &KubernetesStore{
		client:    client,
		namespace: namespace,
		users:     copied,
	}, nil
}

func NewKubernetesStoreFromRESTConfig(restConfig *rest.Config, namespace string, users map[string]string) (*KubernetesStore, error) {
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	return NewKubernetesStore(client, namespace, users)
}

func KubernetesRESTConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	return kubeConfig.ClientConfig()
}

func (s *KubernetesStore) Get(ctx context.Context, userID, key string) (string, bool, error) {
	secretName, err := s.secretName(userID)
	if err != nil {
		return "", false, err
	}
	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", false, nil
	}
	return string(value), true, nil
}

func (s *KubernetesStore) Put(ctx context.Context, userID, key, value string) error {
	secretName, err := s.secretName(userID)
	if err != nil {
		return err
	}
	existing, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: s.namespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "scia",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{key: []byte(value)},
		}
		_, err = s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if existing.Data == nil {
		existing.Data = map[string][]byte{}
	}
	existing.Data[key] = []byte(value)
	_, err = s.client.CoreV1().Secrets(s.namespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

func (s *KubernetesStore) Close() error {
	return nil
}

func (s *KubernetesStore) secretName(userID string) (string, error) {
	secretName, ok := s.users[userID]
	if !ok {
		return "", fmt.Errorf("unknown user %q", userID)
	}
	return secretName, nil
}
