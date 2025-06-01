package cache_test

import (
	"testing"
	"time"

	"github.com/rshelekhov/sso/pkg/jwtauth/cache"
)

func TestCache_SetAndGet(t *testing.T) {
	c := cache.New()
	key := "test"
	value := "value"

	c.Set(key, value, time.Second*10)

	v, ok := c.Get(key)
	if !ok {
		t.Errorf("Expected to get value for key %s, got none", key)
	}

	if v != value {
		t.Errorf("Expected value %s, got %s", value, v)
	}
}

func TestCache_Expiry(t *testing.T) {
	c := cache.New()
	key := "test"
	value := "value"

	c.Set(key, value, time.Millisecond*100)

	time.Sleep(time.Millisecond * 150)

	_, ok := c.Get(key)
	if ok {
		t.Errorf("Expected value to be expired, but it was still present")
	}
}

func TestCache_Delete(t *testing.T) {
	c := cache.New()
	key := "test"
	value := "value"

	c.Set(key, value, time.Second*10)
	c.Delete(key)

	_, ok := c.Get(key)
	if ok {
		t.Errorf("Expected value to be deleted, but it was still present")
	}
}

func TestCache_Clear(t *testing.T) {
	c := cache.New()
	keys := []string{"test1", "test2", "test3"}
	value := "value"

	for _, key := range keys {
		c.Set(key, value, time.Second*10)
	}

	c.Clear()

	for _, key := range keys {
		_, ok := c.Get(key)
		if ok {
			t.Errorf("Expected value for key %s to be cleared, but it was still present", key)
		}
	}
}
