package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/takutakahashi/agentapi-proxy/pkg/client"
)

func TestAttachHistoryRecoversMissingNotificationsWithoutDuplicates(t *testing.T) {
	var out bytes.Buffer
	history := attachHistory{seen: make(map[string]string), tail: 1}
	first := client.Message{ID: json.RawMessage(`1`), Role: "user", Content: "initial"}
	second := client.Message{ID: json.RawMessage(`2`), Role: "assistant", Content: "answer"}
	history.print(&out, []client.Message{first, second})
	require.NotContains(t, out.String(), "initial")
	require.Contains(t, out.String(), "answer")
	out.Reset()
	third := client.Message{ID: json.RawMessage(`3`), Role: "user", Content: "posted in browser"}
	history.print(&out, []client.Message{first, second, third})
	require.NotContains(t, out.String(), "answer")
	require.Contains(t, out.String(), "posted in browser")
	out.Reset()
	history.print(&out, []client.Message{first, second, third})
	require.Empty(t, out.String())
}
