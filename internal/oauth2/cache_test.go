package oauth2

import (
	"testing"
	"time"

	"github.com/jpmorganchase/quorum-security-plugin-enterprise/internal/config"
	testifyassert "github.com/stretchr/testify/assert"
)

func TestExpirationAwareLRUCache_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	testObject, err := newExpirationAwareLRUCache(&config.CacheConfiguration{
		Limit:               10,
		ExpirationInSeconds: 10,
	})

	assert.NoError(err)

	testObject.AddExpiryAwareItem("key1", "value1")

	cachedItem, ok := testObject.GetExpiryAwareItem("key1")

	assert.True(ok, "cached item must exist")

	assert.Equal("value1", cachedItem)
}

func TestExpirationAwareLRUCache_whenExpired(t *testing.T) {
	assert := testifyassert.New(t)

	testObject, err := newExpirationAwareLRUCache(&config.CacheConfiguration{
		Limit:               10,
		ExpirationInSeconds: 1,
	})

	assert.NoError(err)

	testObject.AddExpiryAwareItem("key1", "value1")

	time.Sleep(1 * time.Second) // wait for cached item to be expired

	_, ok := testObject.GetExpiryAwareItem("key1")

	assert.False(ok, "cached item must not exist")
}
