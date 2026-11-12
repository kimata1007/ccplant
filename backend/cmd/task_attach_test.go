package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

func TestAttachTUIKeepsDraftAndSessionLifecycleSeparate(t *testing.T) {
	model := newAttachModel(t.Context(), nil, "tsk_example", client.SessionInfo{SessionID: "session", Status: "suspended"}, 0, 1, "")
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.Update(attachSnapshot{status: "suspended", messages: []client.Message{
		{Role: "user", Content: "initial prompt"},
		{Role: "assistant", Content: "the response"},
	}})
	require.Contains(t, model.View(), "the response")
	require.NotContains(t, model.View(), "initial prompt")
	require.Contains(t, model.View(), "suspended")

	model.input.SetValue("a draft")
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("more")})
	require.Contains(t, model.input.Value(), "\n")
	_, send := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.Nil(t, send)
	require.NotEmpty(t, model.input.Value())

	model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	require.Empty(t, model.input.Value())
	_, quit := model.Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	require.IsType(t, tea.QuitMsg{}, quit())
}
