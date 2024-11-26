package view

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/znscli/zns/internal/arguments"
)

// TestNewRenderer_human tests the NewRenderer function, which should return a HumanRenderer
// and bind provided io.Writer to the view's stream writer.
func TestNewRenderer_human(t *testing.T) {
	b := bytes.Buffer{}
	hv := NewRenderer(arguments.ViewHuman, NewView(&b))

	// Check that the view is a HumanRenderer
	assert.IsType(t, &HumanRenderer{}, hv)

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, hv.(*HumanRenderer).view.Stream.Writer)
}

// TestNewHumanRenderer should simply return a HumanRenderer.
func TestNewHumanRenderer(t *testing.T) {
	b := bytes.Buffer{}
	hv := NewView(&b)
	hr := NewHumanRenderer(hv)

	// Check that the view is a HumanRenderer
	assert.IsType(t, &HumanRenderer{}, hr)

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, hr.view.Stream.Writer)
}

// TestNewRenderer_JSON tests the NewRenderer function, which should return a JSONRenderer
// and bind provided io.Writer to the view's stream writer.
func TestNewRenderer_JSON(t *testing.T) {
	b := bytes.Buffer{}
	jv := NewRenderer(arguments.ViewJSON, NewView(&b))

	// Check that the view is a JSONRenderer
	assert.IsType(t, &JSONRenderer{}, jv)

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, jv.(*JSONRenderer).view.Stream.Writer)
}

// TestNewJSONRenderer should simply return a JSONRenderer.
func TestNewJSONRenderer(t *testing.T) {
	b := bytes.Buffer{}
	jv := NewJSONView(NewView(&b))
	jr := NewJSONRenderer(jv)

	// Check that the view is a JSONRenderer
	assert.IsType(t, &JSONRenderer{}, jr)

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, jr.view.Stream.Writer)
}
