package view

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatTTL(t *testing.T) {
	t.Run("1 hour", func(t *testing.T) {
		ttl := formatTTL(3600)
		expected := "01h00m00s"
		assert.Equal(t, expected, ttl)
	})

	t.Run("3 minutes 42 seconds", func(t *testing.T) {
		ttl := formatTTL(222)
		expected := "03m42s"
		assert.Equal(t, expected, ttl)
	})

	t.Run("59 seconds", func(t *testing.T) {
		ttl := formatTTL(59)
		expected := "59s"
		assert.Equal(t, expected, ttl)
	})

	t.Run("0 seconds", func(t *testing.T) {
		ttl := formatTTL(0)
		expected := "00s"
		assert.Equal(t, expected, ttl)
	})
}
