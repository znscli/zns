package view

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	znsversion "github.com/znscli/zns/version"

	"github.com/google/go-cmp/cmp"
)

// Calling jsonview.Output("Test") should output a single JSON log message,
// always containing the fields @level, @message, @view, and @version.
// This is a convenient way to test the JSONView output format.
func TestNewJSONView(t *testing.T) {
	b := bytes.Buffer{}
	jv := NewJSONView(NewView(&Stream{Writer: &b}))

	jv.Output("Test")

	want := []map[string]interface{}{
		{
			"@level":   "info",
			"@message": "Test",
			"@view":    "json",
			"@version": znsversion.Version,
		},
	}

	testJSONViewOutputEqualsFull(t, b.String(), want)
}

func TestNewJSONView_params(t *testing.T) {
	b := bytes.Buffer{}
	jv := NewJSONView(NewView(&Stream{Writer: &b}))

	jv.Output("Test", "@foo", "bar")

	want := []map[string]interface{}{
		{
			"@level":   "info",
			"@message": "Test",
			"@view":    "json",
			"@version": znsversion.Version,
			"@foo":     "bar",
		},
	}

	testJSONViewOutputEqualsFull(t, b.String(), want)
}

// This helper function tests a possibly multi-line JSONView output string
// against a slice of structs representing the desired log messages. It
// verifies that the output of JSONView is in JSON log format, one message per
// line.
func testJSONViewOutputEqualsFull(t *testing.T, output string, want []map[string]interface{}) {
	t.Helper()

	// Remove final trailing newline
	output = strings.TrimSuffix(output, "\n")

	// Split log into lines, each of which should be a JSON log message
	gotLines := strings.Split(output, "\n")

	if len(gotLines) != len(want) {
		t.Errorf("unexpected number of messages. got %d, want %d", len(gotLines), len(want))
	}

	// Unmarshal each line and compare to the expected value
	for i := range gotLines {
		var gotStruct map[string]interface{}
		if i >= len(want) {
			t.Error("reached end of want messages too soon")
			break
		}
		wantStruct := want[i]

		if err := json.Unmarshal([]byte(gotLines[i]), &gotStruct); err != nil {
			t.Fatal(err)
		}

		// While we don't control this directly, we can at least ensure that the timestamp
		// is present and correctly formatted, as expected.
		// The timestamp is added by the logger, not the JSONView.
		if timestamp, ok := gotStruct["@timestamp"]; !ok {
			t.Errorf("message has no timestamp: %#v", gotStruct)
		} else {
			// Remove the timestamp value from the struct to allow comparison
			delete(gotStruct, "@timestamp")

			// Verify the timestamp format
			if str, ok := timestamp.(string); ok {
				if _, err := time.Parse(time.RFC3339, str); err != nil {
					t.Errorf("error parsing timestamp on line %d: %s", i, err)
				}
			} else {
				t.Errorf("unexpected type for timestamp on line %d: %T", i, timestamp)
			}
		}

		if !cmp.Equal(wantStruct, gotStruct) {
			t.Errorf("unexpected output on line %d:\n%s", i, cmp.Diff(wantStruct, gotStruct))
		}
	}
}
