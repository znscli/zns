package view

import (
	"encoding/json"
	"io"
	"time"

	"github.com/miekg/dns"
	znsversion "github.com/znscli/zns/version"
)

// timestampFormat is the RFC 3339 layout used for the timestamp field in JSON
// output.
const timestampFormat = "2006-01-02T15:04:05.000000Z07:00"

// ViewType represents which view layer to use.
type ViewType int

const (
	ViewHuman ViewType = iota
	ViewJSON
)

// Renderer renders DNS records to an output stream.
type Renderer interface {
	Render(domain string, record dns.RR)
}

// NewRenderer returns a Renderer for the given view type, writing to w.
func NewRenderer(vt ViewType, w io.Writer) Renderer {
	switch vt {
	case ViewHuman:
		return NewHumanRenderer(w)
	case ViewJSON:
		return NewJSONRenderer(w)
	default:
		panic("unknown view type")
	}
}

// HumanRenderer writes DNS records as colored, tab-separated lines.
type HumanRenderer struct {
	w io.Writer
}

var _ Renderer = (*HumanRenderer)(nil)

func NewHumanRenderer(w io.Writer) *HumanRenderer {
	return &HumanRenderer{w: w}
}

// Render writes a DNS record in human-readable format to the output stream.
func (r *HumanRenderer) Render(domain string, record dns.RR) {
	if _, err := io.WriteString(r.w, formatRecord(domain, record)+"\n"); err != nil {
		panic(err)
	}
}

// JSONRenderer writes DNS records as JSON, one object per line.
type JSONRenderer struct {
	enc *json.Encoder
}

var _ Renderer = (*JSONRenderer)(nil)

func NewJSONRenderer(w io.Writer) *JSONRenderer {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONRenderer{enc: enc}
}

// Render writes a DNS record as a single JSON object to the output stream.
func (r *JSONRenderer) Render(domain string, record dns.RR) {
	m := formatRecordAsJSON(domain, record)
	m["level"] = "info"
	m["message"] = "Successful query"
	m["timestamp"] = time.Now().Format(timestampFormat)
	m["version"] = znsversion.Version
	m["view"] = "json"
	if err := r.enc.Encode(m); err != nil {
		panic(err)
	}
}
