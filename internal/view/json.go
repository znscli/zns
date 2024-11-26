package view

import (
	"github.com/hashicorp/go-hclog"
)

type JSONView struct {
	View
	log hclog.Logger
}

func NewJSONView(view *View) *JSONView {
	return &JSONView{
		View: *view,
		log: hclog.New(&hclog.LoggerOptions{
			Output:     view.Stream.Writer,
			JSONFormat: true,
			Color:      hclog.ColorOff,
		}),
	}
}

func (v *JSONView) Output(message string, params ...any) {
	v.log.Info(message, params...)
}
