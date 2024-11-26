package view

import (
	"github.com/znscli/zns/internal/arguments"
)

type Renderer interface {
	Render(message string, params ...any)
}

func NewRenderer(vt arguments.ViewType, view *View) Renderer {
	switch vt {
	case arguments.ViewHuman:
		return &HumanRenderer{view}
	case arguments.ViewJSON:
		return &JSONRenderer{NewJSONView(view)}
	default:
		panic("unknown view type")
	}
}

// HumanRenderer is a view layer used to write human-readable output to a stream.
type HumanRenderer struct {
	view *View
}

// Validate that ZnsHuman implements the Zns interface.
var _ Renderer = (*HumanRenderer)(nil)

func (v *HumanRenderer) Render(message string, params ...any) {
	// here we should receive a message looks like:
	// A       google.com.    52s          172.217.168.238
	// and we should write it to the view.Stream.Writer with a newline
	v.view.Stream.Writer.Write([]byte(message + "\n"))
}

// JSONRenderer is a view layer used to write JSON to a stream.
type JSONRenderer struct {
	view *JSONView
}

// Validate that ZnsJSON implements the Zns interface.
var _ Renderer = (*JSONRenderer)(nil)

func NewJSONRenderer(view *JSONView) *JSONRenderer {
	return &JSONRenderer{
		view: view,
	}
}

func (v *JSONRenderer) Render(message string, params ...any) {
	v.view.Output(message, params...)
}
