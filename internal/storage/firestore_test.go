package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirestoreStorageConfig(t *testing.T) {
	t.Run("missing GCP project ID", func(t *testing.T) {
		// Test that Firestore storage requires GCP project ID
		ctx := context.Background()
		encryptor, _ := crypto.NewEncryptor([]byte("test-encryption-key-32-bytes-ok!"))

		_, err := NewFirestoreStorage(ctx, "", "(default)", "test_collection", encryptor)
		assert.Error(t, err, "Expected error when GCP project ID is missing for Firestore storage")
		assert.Contains(t, err.Error(), "projectID is required")
	})

	t.Run("missing encryption key", func(t *testing.T) {
		// Test that creating encryptor with invalid key fails
		_, err := crypto.NewEncryptor([]byte("short"))
		assert.Error(t, err, "Expected error when creating encryptor with short key")
		assert.Contains(t, err.Error(), "key must be 32 bytes")
	})

	t.Run("nil encryptor", func(t *testing.T) {
		// Test that Firestore storage requires non-nil encryptor
		ctx := context.Background()

		_, err := NewFirestoreStorage(ctx, "test-project", "(default)", "test_collection", nil)
		assert.Error(t, err, "Expected error when encryptor is nil")
		assert.Contains(t, err.Error(), "encryptor is required")
	})

	t.Run("missing collection", func(t *testing.T) {
		// Test that collection is required
		ctx := context.Background()
		encryptor, _ := crypto.NewEncryptor([]byte("test-encryption-key-32-bytes-ok!"))

		_, err := NewFirestoreStorage(ctx, "test-project", "(default)", "", encryptor)
		assert.Error(t, err, "Expected error when collection is empty")
		assert.Contains(t, err.Error(), "collection is required")
	})
}

// TestFirestoreConnectionDirectory needs the Firestore emulator, e.g.
// `firebase emulators:start --only firestore` with FIRESTORE_EMULATOR_HOST set.
func TestFirestoreConnectionDirectory(t *testing.T) {
	if os.Getenv("FIRESTORE_EMULATOR_HOST") == "" {
		t.Skip("FIRESTORE_EMULATOR_HOST not set")
	}

	ctx := context.Background()
	encryptor, err := crypto.NewEncryptor([]byte("test-encryption-key-32-bytes-ok!"))
	require.NoError(t, err)

	projectID := fmt.Sprintf("demo-connections-%d", time.Now().UnixNano())
	s, err := NewFirestoreStorage(ctx, projectID, "(default)", "mcp_front_oauth_clients", encryptor)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	expiresAt := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	seedConnectionDirectory(t, ctx, s, expiresAt)
	assertConnectionDirectory(t, ctx, s, expiresAt)
}
