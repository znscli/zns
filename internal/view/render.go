package view

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/miekg/dns"
	"github.com/znscli/zns/internal/arguments"
)

// Renderer interface with a unified Render method
type Renderer interface {
	AddRecord(domain string, record dns.RR)
	Render()
}

func NewRenderer(vt arguments.ViewType, view *View) Renderer {
	switch vt {
	case arguments.ViewHuman:
		return NewHumanRenderer(view)
	case arguments.ViewJSON:
		return &JSONRenderer{NewJSONView(view)}
	default:
		panic("unknown view type")
	}
}

// HumanRenderer for writing human-readable output
type HumanRenderer struct {
	view *View
	t    table.Writer
}

// Validate that HumanRenderer implements the Renderer interface.
var _ Renderer = (*HumanRenderer)(nil)

// NewHumanRenderer creates a HumanRenderer with a "human" view bound to an output stream
func NewHumanRenderer(view *View) *HumanRenderer {
	t := table.NewWriter()
	s := table.Style{
		Options: table.Options{
			SeparateHeader:  false,
			DrawBorder:      false,
			SeparateRows:    false,
			SeparateColumns: false,
		},
		Box: table.StyleBoxDefault,
	}
	t.SetOutputMirror(view.Stream.Writer)
	t.SetStyle(s)

	return &HumanRenderer{
		view: view,
		t:    t,
	}
}

// AddRecord prepares a DNS record in human-readable format to be written to the output stream
func (v *HumanRenderer) AddRecord(domain string, record dns.RR) {
	v.t.AppendRow(append(table.Row{}, formatRecord(domain, record)...))
}

// Render writes the human-readable table to the output stream
func (v *HumanRenderer) Render() {
	v.t.Render()
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

// AddRecord writes a DNS record in JSON format to the output stream
func (v *JSONRenderer) AddRecord(domain string, record dns.RR) {
	jsonMap := formatRecordAsJSON(domain, record)

	var params []any
	for key, value := range jsonMap {
		// Append each key-value pair as separate parameters
		params = append(params, key, value)
	}

	v.view.Output("Successful query", params...)
}

// JSONRender is not buffered, so no need to flush
func (v *JSONRenderer) Render() {
	// No-op
}
