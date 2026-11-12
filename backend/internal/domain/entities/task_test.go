package entities

import (
	"errors"
	"strings"
	"testing"
)

func TestTaskSpecValidation(t *testing.T) {
	const base = `apiVersion: ccplant.io/v1alpha1
kind: Task
metadata:
  name: review
spec:
  start:
    session_profile_id: default
    params:
      message: hello
`
	cases := []struct {
		name, body string
		want       error
	}{
		{name: "valid", body: base},
		{name: "unknown", body: strings.Replace(base, "    params:", "    reuse_message: hello\n    params:", 1), want: errors.New("invalid")},
		{name: "numeric message", body: strings.Replace(base, "message: hello", "message: 42", 1), want: errors.New("invalid")},
		{name: "multiple docs", body: base + "---\n" + base, want: errors.New("invalid")},
		{name: "secret env", body: strings.Replace(base, "    params:", "    environment:\n      API_KEY: sample-value\n    params:", 1), want: ErrTaskEnvironment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeTaskSpec([]byte(tc.body), true)
			if (err == nil) != (tc.want == nil) || (tc.want == ErrTaskEnvironment && !errors.Is(err, tc.want)) {
				t.Fatalf("validation error = %v, want %v", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "sample-value") {
				t.Fatal("validation error exposed a submitted value")
			}
		})
	}
}
