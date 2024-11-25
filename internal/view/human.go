package view

import (
	"github.com/hashicorp/go-hclog"
)

type HumanView struct {
	View
	log hclog.Logger
}

func NewHumanView(view *View) *HumanView {
	return &HumanView{
		View: *view,
		log: hclog.New(&hclog.LoggerOptions{
			Output: view.Stream.Writer,
		}),
	}
}

func (v *HumanView) Log(message string) {
	v.log.Info(message)
}
