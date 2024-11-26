package view

import (
	"github.com/miekg/dns"
	"github.com/znscli/zns/internal/arguments"
)

// Renderer interface with a unified Render method
type Renderer interface {
	Render(domain string, record dns.RR)
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

// HumanRenderer for writing human-readable output
type HumanRenderer struct {
	view *View
}

// Validate that HumanRenderer implements the Renderer interface.
var _ Renderer = (*HumanRenderer)(nil)

// NewHumanRenderer creates a HumanRenderer with a "human" view bound to an output stream
func NewHumanRenderer(view *View) *HumanRenderer {
	return &HumanRenderer{
		view: view,
	}
}

// Render method for HumanRenderer
func (v *HumanRenderer) Render(domain string, record dns.RR) {
	humanReadable := formatRecord(domain, record)
	v.view.Stream.Writer.Write([]byte(humanReadable + "\n"))
}

// JSONRenderer for rendering JSON output
type JSONRenderer struct {
	view *JSONView
}

// Validate that JSONRenderer implements the Renderer interface.
var _ Renderer = (*JSONRenderer)(nil)

// NewJSONRenderer creates a JSONRenderer with a JSONView bound to an output stream
func NewJSONRenderer(view *JSONView) *JSONRenderer {
	return &JSONRenderer{
		view: view,
	}
}

func (v *JSONRenderer) Render(domain string, record dns.RR) {
	jsonMap := formatRecordAsJSON(domain, record)

	var params []any
	for key, value := range jsonMap {
		// Append each key-value pair as separate parameters
		params = append(params, key, value)
	}

	v.view.Output("Successful query", params...)
}
