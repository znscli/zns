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
			Output: view.Stream.Writer,
		}),
	}
}

func (v *JSONView) Log(message string) {
	v.log.Info(message, "type", "log")
}
