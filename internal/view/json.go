package view

import (
	"github.com/hashicorp/go-hclog"
	znsversion "github.com/znscli/zns/version"
)

type JSONView struct {
	View
	log hclog.Logger
}

func NewJSONView(view *View) *JSONView {
	return &JSONView{
		View: *view,
		log: hclog.New(&hclog.LoggerOptions{
			Output:               view.Stream.Writer,
			JSONFormat:           true,
			DisableTime:          false,
			Color:                hclog.ColorOff,
			ColorHeaderAndFields: false,
		}).With("@view", "json", "@version", znsversion.Version),
	}
}

func (v *JSONView) Output(message string, params ...any) {
	v.log.Info(message, params...)
}
