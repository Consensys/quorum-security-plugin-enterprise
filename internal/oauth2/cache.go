package oauth2

import (
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/jpmorganchase/quorum-security-plugin-enterprise/internal/config"
)

type cachedItem struct {
	item      interface{}
	expiredAt time.Time
}

type expirationAwareLRUCache struct {
	*lru.Cache
	// cached item time to live
	maxTTLInSeconds int
}

func newExpirationAwareLRUCache(conf *config.CacheConfiguration) (*expirationAwareLRUCache, error) {
	c, err := lru.New(conf.Limit)
	if err != nil {
		return nil, err
	}
	return &expirationAwareLRUCache{
		Cache:           c,
		maxTTLInSeconds: conf.ExpirationInSeconds,
	}, nil
}

func (ec *expirationAwareLRUCache) GetExpiryAwareItem(key interface{}) (interface{}, bool) {
	if raw, ok := ec.Get(key); ok {
		if ci, ok := raw.(*cachedItem); ok {
			if time.Now().Before(ci.expiredAt) {
				return ci.item, true
			} else {
				ec.Remove(key)
			}
		}
	}
	return nil, false
}

func (ec *expirationAwareLRUCache) AddExpiryAwareItem(key interface{}, item interface{}) bool {
	return ec.Add(key, &cachedItem{
		item:      item,
		expiredAt: time.Now().Add(time.Duration(ec.maxTTLInSeconds) * time.Second),
	})
}
