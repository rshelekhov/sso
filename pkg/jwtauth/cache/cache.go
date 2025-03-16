package cache

import (
	"sync"
	"time"
)

// Cache represents an in-memory key-value store with expiry support.
type Cache struct {
	data map[string]Item
	mu   sync.RWMutex
}

// Item represents an item stored in the cache with its associated TTL.
type Item struct {
	value  any
	expiry time.Time
}

// New creates and initializes a new Cache instance.
func New() *Cache {
	return &Cache{
		data: make(map[string]Item),
	}
}

const DefaultExpiration = time.Hour

// Set adds or updates a key-value pair in the cache with the given TTL.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl <= time.Duration(0) {
		ttl = DefaultExpiration
	}

	c.data[key] = Item{
		value:  value,
		expiry: time.Now().Add(ttl),
	}
}

// Get retrieves the value associated with the given key from the cache.
// It also checks for expiry and removes expired items.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	item, ok := c.data[key]
	if !ok {
		return nil, false
	}

	// item found - check for expiry
	if time.Now().After(item.expiry) {
		// remove entry from cache if time is beyond the expiry
		delete(c.data, key)
		return nil, false
	}

	return item.value, true
}

// Delete removes a key-value pair from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
}

// Clear removes all key-value pairs from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]Item)
}
