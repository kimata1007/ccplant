package cmd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/takutakahashi/agentapi-proxy/pkg/client"
	"golang.org/x/term"
)

func newTaskAttachCommand() *cobra.Command {
	var follow, noInput, plain bool
	var since, tail int
	var uiURL string
	cmd := taskCLI("attach <task-id|session-id>", "Read and continue an existing session conversation", cobra.ExactArgs(1), func(cmd *cobra.Command, api *client.Client, args []string) error {
		if since < 0 || tail < 0 {
			return errors.New("--since and --tail must be nonnegative")
		}
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()
		session, err := resolveTaskSession(ctx, api, args[0], true, cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		in, terminalInput := cmd.InOrStdin().(*os.File)
		outFile, terminalOutput := out.(*os.File)
		interactive := follow && !noInput && terminalInput && terminalOutput && term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(outFile.Fd()))
		if interactive && !plain {
			return runAttachTUI(ctx, api, args[0], session, since, tail, uiURL, in, out)
		}
		fmt.Fprintf(out, "Session: %s  Scope: %s  Status: %s\n", session.SessionID, session.Scope, session.Status)
		if session.Status == "suspended" {
			fmt.Fprintln(out, "Session suspended. Use /resume to resume it explicitly.")
		}
		var readLine func() (string, error)
		if interactive {
			scanner := bufio.NewScanner(in)
			scanner.Buffer(make([]byte, 4096), 128<<10)
			readLine = func() (string, error) {
				if scanner.Scan() {
					return scanner.Text(), nil
				}
				if err := scanner.Err(); err != nil {
					return "", err
				}
				return "", io.EOF
			}
		}

		history := attachHistory{seen: make(map[string]string), since: since, tail: tail}
		var updates <-chan struct{}
		if follow {
			updates = watchAttachedSession(ctx, api, session.SessionID)
		}
		// Establish the event stream before the snapshot when the provider
		// supports it. Canonical polling also covers unavailable event streams.
		if updates != nil && session.Status != "suspended" {
			select {
			case <-ctx.Done():
				return nil
			case <-updates:
			case <-time.After(2 * time.Second):
			}
		}
		refresh := func() error {
			result, err := api.GetMessages(ctx, session.SessionID)
			if err != nil {
				return err
			}
			history.print(out, result.Messages)
			return nil
		}
		historyErr := refresh()
		if historyErr != nil {
			fmt.Fprintln(out, "History is currently unavailable.")
			if !follow && session.Status != "suspended" {
				return historyErr
			}
		}
		if !follow {
			return nil
		}

		var lines <-chan string
		var next chan struct{}
		if readLine != nil {
			fmt.Fprintln(out, "Enter sends. /help lists commands. /detach or Ctrl+D exits.")
			lineCh, readNext := make(chan string), make(chan struct{}, 1)
			lines, next = lineCh, readNext
			next <- struct{}{}
			go func() {
				defer close(lineCh)
				for {
					select {
					case <-ctx.Done():
						return
					case <-readNext:
					}
					line, err := readLine()
					if err != nil {
						return
					}
					select {
					case lineCh <- line:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		var draft []string
		draftSize := 0
		resumePending := false
		status := session.Status
		for {
			select {
			case <-ctx.Done():
				return nil
			case _, ok := <-updates:
				if !ok {
					updates = nil
				}
			case <-tick.C:
				if agent, err := api.GetStatus(ctx, session.SessionID); err == nil && status != agent.Status {
					status = agent.Status
					fmt.Fprintf(out, "Session status: %s\n", terminalText(status))
				}
			case line, ok := <-lines:
				if !ok || line == "/detach" {
					return nil
				}
				switch {
				case resumePending:
					resumePending = false
					if line == "resume" {
						if err := api.ResumeAttachedSession(ctx, session.SessionID); err != nil {
							fmt.Fprintln(out, "Resume request failed.")
						}
					}
				case line == "/help":
					fmt.Fprintln(out, "/history, /status, /resume, /open, /multiline, /send, /cancel-input, /detach")
				case line == "/status":
					fmt.Fprintf(out, "Session status: %s\n", terminalText(status))
				case line == "/history":
					history = attachHistory{seen: make(map[string]string), since: since, tail: tail}
				case line == "/resume":
					fmt.Fprintln(out, "Type resume to confirm.")
					resumePending = true
				case line == "/open":
					if err := openTaskSession(uiURL, session.SessionID); err != nil {
						fmt.Fprintln(out, err)
					}
				case line == "/multiline":
					draft, draftSize = []string{}, 0
					fmt.Fprintln(out, "Enter adds a line. Use /send to submit or /cancel-input to discard.")
				case line == "/cancel-input":
					draft, draftSize = nil, 0
				case draft != nil && line != "/send":
					if len(line)+1+draftSize > 128<<10 {
						fmt.Fprintln(out, "Draft exceeds the 128 KiB limit.")
					} else {
						draft = append(draft, line)
						draftSize += len(line) + 1
					}
				default:
					if line == "/send" {
						line = strings.Join(draft, "\n")
						draft, draftSize = nil, 0
					}
					if strings.TrimSpace(line) != "" && len(line) <= 128<<10 {
						if err := sendTaskMessage(ctx, api, session.SessionID, line); err != nil {
							fmt.Fprintln(out, err)
						}
					}
				}
				next <- struct{}{}
			}
			if err := refresh(); err != nil {
				if historyErr == nil {
					fmt.Fprintln(out, "History connection interrupted; retrying.")
				}
				historyErr = err
			} else if historyErr != nil {
				fmt.Fprintln(out, "History connection restored.")
				historyErr = nil
			}
		}
	})
	cmd.Flags().BoolVar(&follow, "follow", true, "Continue following new messages")
	cmd.Flags().BoolVar(&noInput, "no-input", false, "Read the conversation without sending")
	cmd.Flags().BoolVar(&plain, "plain", false, "Use line input without terminal editing")
	cmd.Flags().IntVar(&since, "since", 0, "Skip this many messages from the start")
	cmd.Flags().IntVar(&tail, "tail", 0, "Show the last N messages in the initial snapshot (0 means all)")
	cmd.Flags().StringVar(&uiURL, "ui-url", os.Getenv("CCPLANT_UI_URL"), "Web UI base URL used by /open")
	return cmd
}

type attachHistory struct {
	seen        map[string]string
	since, tail int
	initialized bool
}

func (h *attachHistory) print(out io.Writer, messages []client.Message) {
	first := min(h.since, len(messages))
	if !h.initialized && h.tail > 0 {
		first = max(first, len(messages)-h.tail)
	}
	occurrences := map[string]int{}
	for i, msg := range messages {
		role := msg.Role
		if role == "" {
			role = msg.Type
		}
		stamp := ""
		if t := msg.GetTimestamp(); t != nil {
			stamp = t.Format(time.RFC3339)
		}
		id := string(msg.ID)
		if id == "" || id == "null" || id == `""` {
			hash := sha256.Sum256([]byte(role + "\x00" + stamp + "\x00" + msg.Content))
			key := fmt.Sprintf("%x", hash)
			occurrences[key]++
			id = fmt.Sprintf("%s:%d", key, occurrences[key])
		} else {
			id = role + ":" + id
		}
		old, seen := h.seen[id]
		h.seen[id] = msg.Content
		if i < first || seen && old == msg.Content {
			continue
		}
		content := msg.Content
		if seen && strings.HasPrefix(content, old) {
			content = strings.TrimPrefix(content, old)
		}
		fmt.Fprintf(out, "[%s] %s: %s\n", stamp, terminalText(role), terminalText(content))
	}
	h.initialized = true
}

func terminalText(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, text)
}

func watchAttachedSession(ctx context.Context, api *client.Client, id string) <-chan struct{} {
	updates := make(chan struct{}, 1)
	go func() {
		defer close(updates)
		notify := func() {
			select {
			case updates <- struct{}{}:
			default:
			}
		}
		delay := time.Second
		for ctx.Err() == nil {
			stream, _ := api.StreamEvents(ctx, id)
			for range stream {
				delay = time.Second
				notify()
			}
			notify()
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay + time.Duration(rand.Int64N(int64(delay/2)))):
			}
			delay = min(2*delay, 30*time.Second)
		}
	}()
	return updates
}

func openTaskSession(base, id string) error {
	target, err := url.Parse(base)
	if err != nil || target.Host == "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return errors.New("Set --ui-url or CCPLANT_UI_URL to the ccplant web UI URL.")
	}
	target = target.JoinPath("sessions", id)
	target.RawQuery, target.Fragment = "", ""
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target.String())
	case "linux":
		command = exec.Command("xdg-open", target.String())
	default:
		return fmt.Errorf("Open %s", target.String())
	}
	if err := command.Run(); err != nil {
		return fmt.Errorf("Open %s", target.String())
	}
	return nil
}
