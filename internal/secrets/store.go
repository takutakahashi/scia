package secrets

import "context"

type Store interface {
	Get(ctx context.Context, credentialID, key string) (string, bool, error)
	Put(ctx context.Context, credentialID, key, value string) error
	Delete(ctx context.Context, credentialID, key string) error
	Close() error
}

type NoopStore struct{}

func (NoopStore) Get(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (NoopStore) Put(context.Context, string, string, string) error {
	return nil
}

func (NoopStore) Delete(context.Context, string, string) error {
	return nil
}

func (NoopStore) Close() error {
	return nil
}
