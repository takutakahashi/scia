package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

func ResolveRef(ctx context.Context, store Store, ref string) (string, error) {
	if strings.HasPrefix(ref, "env:") {
		return os.Getenv(strings.TrimPrefix(ref, "env:")), nil
	}
	if strings.HasPrefix(ref, "secret:") {
		ref = strings.TrimPrefix(ref, "secret:")
	}
	credentialID, key, err := RefParts(ref)
	if err != nil {
		return "", err
	}
	value, ok, err := store.Get(ctx, credentialID, key)
	if err != nil {
		return "", err
	}
	if ok {
		return value, nil
	}
	return "", nil
}

func RefParts(ref string) (string, string, error) {
	namespace, rest, ok := strings.Cut(ref, ".")
	if !ok || namespace == "" {
		return "", "", fmt.Errorf("secret ref %q must be formatted as namespace.provider.key", ref)
	}
	provider, key, ok := strings.Cut(rest, ".")
	if !ok || provider == "" || key == "" {
		return "", "", fmt.Errorf("secret ref %q must be formatted as namespace.provider.key", ref)
	}
	return namespace + "." + provider, key, nil
}
