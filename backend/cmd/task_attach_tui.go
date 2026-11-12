package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/takutakahashi/agentapi-proxy/pkg/client"
)

type attachSnapshot struct {
	messages []client.Message
	status   string
	err      error
}

type attachRefresh struct{}
type attachOperation struct {
	note string
	sent bool
}

type attachModel struct {
	ctx                             context.Context
	api                             *client.Client
	updates                         <-chan struct{}
	taskID, uiURL                   string
	session                         client.SessionInfo
	input                           textarea.Model
	history                         viewport.Model
	messages                        []client.Message
	start, tail                     int
	initial, ready, sending, resume bool
	connection, note                string
}

func newAttachModel(ctx context.Context, api *client.Client, id string, session client.SessionInfo, since, tail int, uiURL string) *attachModel {
	input := textarea.New()
	input.Prompt = "> "
	input.Placeholder = "Send a message or type /help"
	input.ShowLineNumbers = false
	input.CharLimit = 128 << 10
	input.MaxWidth = 0
	input.SetHeight(3)
	var taskID string
	if strings.HasPrefix(id, "tsk_") {
		taskID = id
	}
	return &attachModel{ctx: ctx, api: api, taskID: taskID, session: session, input: input, history: viewport.New(0, 0), start: since, tail: tail, uiURL: uiURL, connection: "connecting"}
}

func runAttachTUI(ctx context.Context, api *client.Client, id string, session client.SessionInfo, since, tail int, uiURL string, in io.Reader, out io.Writer) error {
	model := newAttachModel(ctx, api, id, session, since, tail, uiURL)
	model.updates = watchAttachedSession(ctx, api, session.SessionID)
	program := tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen())
	_, err := program.Run()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (m *attachModel) Init() tea.Cmd {
	return tea.Batch(m.input.Focus(), m.waitRefresh(2*time.Second))
}

func (m *attachModel) waitRefresh(interval time.Duration) tea.Cmd {
	// Copy data before returning a command so Update stays the only model writer.
	ctx, updates := m.ctx, m.updates
	return func() tea.Msg {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil
		case <-updates:
		case <-timer.C:
		}
		return attachRefresh{}
	}
}

func (m *attachModel) fetchSnapshot() tea.Cmd {
	ctx, api, id := m.ctx, m.api, m.session.SessionID
	return func() tea.Msg {
		request, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		status, statusErr := api.GetStatus(request, id)
		messages, err := api.GetMessages(request, id)
		snapshot := attachSnapshot{err: err}
		if err == nil {
			snapshot.messages = messages.Messages
		}
		if statusErr == nil {
			snapshot.status = status.Status
		}
		return snapshot
	}
}

func (m *attachModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.ready = true
		width := max(20, msg.Width)
		inputHeight := min(4, max(1, msg.Height/4))
		m.input.SetWidth(width)
		m.input.SetHeight(inputHeight)
		m.history.Width, m.history.Height = width, max(1, msg.Height-inputHeight-4)
		m.renderHistory()
		return m, nil
	case attachRefresh:
		return m, m.fetchSnapshot()
	case attachSnapshot:
		if msg.status != "" {
			m.session.Status = msg.status
		}
		if msg.err != nil {
			m.connection = "reconnecting"
		} else {
			m.connection = "connected"
			m.messages = msg.messages
			if !m.initial {
				if m.tail > 0 {
					m.start = max(m.start, len(msg.messages)-m.tail)
				}
				m.initial = true
			}
			m.renderHistory()
		}
		return m, m.waitRefresh(3 * time.Second)
	case attachOperation:
		m.note = msg.note
		if msg.sent {
			m.sending = false
		}
		return m, nil
	case tea.KeyMsg:
		if !msg.Paste {
			switch msg.String() {
			case "ctrl+d":
				return m, tea.Quit
			case "ctrl+c":
				m.input.Reset()
				m.resume = false
				m.note = "Draft cleared."
				return m, nil
			case "pgup", "pgdown":
				var command tea.Cmd
				m.history, command = m.history.Update(msg)
				return m, command
			case "ctrl+j", "alt+enter":
				m.input.InsertString("\n")
				return m, nil
			case "enter":
				return m, m.submitInput()
			}
		}
	}
	var command tea.Cmd
	m.input, command = m.input.Update(message)
	return m, command
}

func (m *attachModel) submitInput() tea.Cmd {
	value := strings.TrimSpace(m.input.Value())
	if value == "" {
		return nil
	}
	if m.sending && !strings.HasPrefix(value, "/") {
		m.note = "A message is still being sent."
		return nil
	}
	m.input.Reset()
	ctx, api, id := m.ctx, m.api, m.session.SessionID
	if m.resume {
		m.resume = false
		if value != "resume" {
			m.note = "Resume cancelled."
			return nil
		}
		return func() tea.Msg {
			if err := api.ResumeAttachedSession(ctx, id); err != nil {
				return attachOperation{note: "Resume request failed."}
			}
			return attachOperation{note: "Resume requested."}
		}
	}
	switch value {
	case "/detach":
		return tea.Quit
	case "/help":
		m.note = "/history  /status  /resume  /open  /cancel-input  /detach"
	case "/history":
		m.start = 0
		m.renderHistory()
		m.history.GotoTop()
	case "/status":
		m.note = "Session status: " + terminalText(m.session.Status)
	case "/resume":
		m.note = "Type resume to confirm."
		m.resume = true
	case "/cancel-input":
		m.note = "Draft cleared."
	case "/open":
		uiURL := m.uiURL
		return func() tea.Msg {
			if err := openTaskSession(uiURL, id); err != nil {
				return attachOperation{note: err.Error()}
			}
			return attachOperation{note: "Opened the session in your browser."}
		}
	default:
		if m.session.Status == "suspended" {
			m.note = "Session is suspended. Use /resume first."
			m.input.SetValue(value)
			return nil
		}
		if len(value) > 128<<10 || m.sending {
			m.note = "Send limit reached or another send is pending."
			m.input.SetValue(value)
			return nil
		}
		m.sending = true
		m.note = "Sending…"
		return func() tea.Msg {
			err := sendTaskMessage(ctx, api, id, value)
			if err != nil {
				return attachOperation{note: err.Error(), sent: true}
			}
			return attachOperation{note: "Message accepted.", sent: true}
		}
	}
	return nil
}

func (m *attachModel) renderHistory() {
	if !m.ready {
		return
	}
	follow := m.history.AtBottom()
	var content bytes.Buffer
	history := attachHistory{seen: make(map[string]string), since: m.start}
	history.print(&content, m.messages)
	m.history.SetContent(ansi.Hardwrap(content.String(), m.history.Width, true))
	if follow {
		m.history.GotoBottom()
	}
}

func (m *attachModel) View() string {
	if !m.ready {
		return "Connecting…"
	}
	heading := fmt.Sprintf("Session %s  %s  %s  %s", m.session.SessionID, m.session.Scope, m.session.Status, m.connection)
	if m.taskID != "" {
		heading = m.taskID + "  " + heading
	}
	return ansi.Truncate(terminalText(heading), m.history.Width, "…") + "\n" + m.history.View() + "\n" + m.input.View() + "\n" +
		ansi.Truncate("Enter send · Ctrl+J newline · PgUp/PgDn scroll · Ctrl+D detach", m.history.Width, "…") + "\n" +
		ansi.Truncate(terminalText(m.note), m.history.Width, "…")
}
