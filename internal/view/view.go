package view

import "io"

type View struct {
	Stream *Stream
}

type Stream struct {
	Writer io.Writer
}

func (s *Stream) Write(p []byte) (n int, err error) {
	return s.Writer.Write(p)
}

func NewView(w io.Writer) *View {
	return &View{
		Stream: &Stream{
			Writer: w,
		},
	}
}
