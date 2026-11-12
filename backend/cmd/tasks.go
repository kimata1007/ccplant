package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
	"github.com/takutakahashi/agentapi-proxy/pkg/client"
	"github.com/takutakahashi/agentapi-proxy/pkg/utils"
	"golang.org/x/term"
)

type taskCommand func(*cobra.Command, *taskCLIClient, []string) error

func taskCLI(use, short string, args cobra.PositionalArgs, run taskCommand) *cobra.Command {
	return taskCLIWithQueue(use, short, args, "server", run)
}

func taskCLIWithQueue(use, short string, args cobra.PositionalArgs, defaultQueue string, run taskCommand) *cobra.Command {
	var endpoint, queueMode, sqlitePath string
	if configured := os.Getenv("CCPLANT_TASK_QUEUE"); configured != "" {
		defaultQueue = configured
	}
	cmd := &cobra.Command{Use: use, Short: short, Args: args, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved := endpoint
			if resolved == "" {
				var err error
				resolved, err = client.EndpointFromEnv()
				if err != nil {
					return err
				}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cmd.SetContext(ctx)
			credential := os.Getenv("AGENTAPI_KEY")
			options := []client.ClientOption{client.WithAPIKeyAuth(credential)}
			switch queueMode {
			case "server":
				api := client.NewClient(resolved, options...)
				return run(cmd, &taskCLIClient{Client: api, tasks: api}, args)
			case "sqlite":
				resolved, err := normalizeLocalTaskEndpoint(resolved)
				if err != nil {
					return err
				}
				httpClient := utils.NewHTTPClient(utils.HTTPClientConfig{Timeout: task.StartTimeout})
				// A redirect must not replay a local worker's start request.
				httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				api := client.NewClient(resolved, append(options, client.WithHTTPClient(httpClient))...)
				local, err := openLocalTaskQueue(ctx, sqlitePath, resolved, credential, api)
				if err != nil {
					return err
				}
				defer local.kv.Close()
				return run(cmd, &taskCLIClient{Client: api, tasks: local, local: local}, args)
			default:
				return fmt.Errorf("unknown task queue %q (use server or sqlite)", queueMode)
			}
		}}
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "ccplant API endpoint")
	cmd.Flags().StringVar(&queueMode, "queue", defaultQueue, "Task queue storage: server or sqlite")
	cmd.Flags().StringVar(&sqlitePath, "sqlite-path", os.Getenv("CCPLANT_TASK_SQLITE_PATH"), "SQLite task database path")
	return cmd
}

func TaskCommands() []*cobra.Command {
	var submissionJSON bool
	var key string
	submit := taskCLI("submit <path.yaml>", "Submit a task for background session creation", cobra.ExactArgs(1), func(cmd *cobra.Command, api *taskCLIClient, args []string) error {
		file, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, entities.TaskBodyLimit+1))
		if err != nil {
			return err
		}
		spec, err := entities.DecodeTaskSpec(raw, true)
		if err != nil {
			return err
		}
		submissionKey := key
		if submissionKey == "" {
			submissionKey = uuid.NewString()
		}
		result, err := api.tasks.SubmitTask(cmd.Context(), spec, submissionKey)
		if err != nil {
			return fmt.Errorf("%w (retry with --idempotency-key %s)", err, submissionKey)
		}
		return printSubmission(cmd.OutOrStdout(), result, submissionJSON)
	})
	submit.Flags().BoolVar(&submissionJSON, "json", false, "Print JSON")
	submit.Flags().StringVar(&key, "idempotency-key", "", "Reuse this key to retry an uncertain submission")

	manage := &cobra.Command{Use: "task", Short: "Inspect and manage queued tasks"}
	var showJSON bool
	show := taskCLI("show <task-id>", "Show task state and its assigned session", cobra.ExactArgs(1), func(cmd *cobra.Command, api *taskCLIClient, args []string) error {
		result, err := api.tasks.ShowTask(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if showJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", result.ID, result.State, taskSessionID(result), result.Name, result.Reason)
		if result.SessionMissing {
			fmt.Fprintln(cmd.OutOrStdout(), "The session was removed.")
		}
		return err
	})
	show.Flags().BoolVar(&showJSON, "json", false, "Print JSON")

	var force bool
	cancel := taskCLI("cancel <task-id>", "Cancel a pending task", cobra.ExactArgs(1), func(cmd *cobra.Command, api *taskCLIClient, args []string) error {
		ctx := cmd.Context()
		if !force {
			result, err := api.tasks.CancelTask(ctx, args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", result.State, taskSessionID(result), result.Reason)
			return err
		}
		result, err := api.tasks.ShowTask(ctx, args[0])
		if err != nil {
			return err
		}
		if result.SessionID == nil || result.SessionMissing {
			return errors.New("task has no existing session to delete")
		}
		if _, err := findTaskSession(ctx, api.Client, *result.SessionID, string(result.Scope), result.TeamID); err != nil {
			return err
		}
		in, ok := cmd.InOrStdin().(*os.File)
		if !ok || !term.IsTerminal(int(in.Fd())) {
			return errors.New("--force-session-stop requires a terminal for confirmation")
		}
		reader := bufio.NewScanner(in)
		fmt.Fprintf(cmd.ErrOrStderr(), "Delete session %s? Type yes: ", *result.SessionID)
		if !reader.Scan() || reader.Text() != "yes" {
			return nil
		}
		fmt.Fprint(cmd.ErrOrStderr(), "Type the session ID to confirm deletion: ")
		if !reader.Scan() || reader.Text() != *result.SessionID {
			return nil
		}
		if result.State.Pending() {
			if _, err = api.tasks.CancelTask(ctx, args[0]); err != nil && !isTaskHTTP(err, http.StatusConflict) {
				return err
			}
		}
		_, err = api.DeleteSession(ctx, *result.SessionID)
		return err
	})
	cancel.Flags().BoolVar(&force, "force-session-stop", false, "Delete the existing session after two confirmations")

	retry := taskCLI("retry <task-id>", "Submit a new task from a failed, cancelled or expired task", cobra.ExactArgs(1), func(cmd *cobra.Command, api *taskCLIClient, args []string) error {
		result, err := api.tasks.RetryTask(cmd.Context(), args[0], "")
		if err != nil {
			return err
		}
		return printSubmission(cmd.OutOrStdout(), result, false)
	})
	manage.AddCommand(show, cancel, retry, newLocalTaskWorkerCommand())

	var wait bool
	send := taskCLI("send <task-id|session-id> <message>", "Send one message to an existing session", cobra.ExactArgs(2), func(cmd *cobra.Command, api *taskCLIClient, args []string) error {
		if strings.TrimSpace(args[1]) == "" || len(args[1]) > 128<<10 {
			return errors.New("message must contain 1 to 128 KiB of text")
		}
		session, err := resolveTaskSession(cmd.Context(), api, args[0], wait, cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		if session.Status == "suspended" {
			return errors.New("session is suspended; resume it before sending")
		}
		return sendTaskMessage(cmd.Context(), api.Client, session.SessionID, args[1])
	})
	send.Flags().BoolVar(&wait, "wait", false, "Wait for the session to be ready before sending once")
	return []*cobra.Command{submit, newTaskListCommand(), manage, newTaskAttachCommand(), send}
}

func printSubmission(out io.Writer, result client.TaskSubmission, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(out).Encode(result)
	}
	_, err := fmt.Fprintf(out, "Task submitted: %s\nState: %s\n", result.TaskID, result.State)
	if err == nil && result.SessionID != nil {
		_, err = fmt.Fprintf(out, "Session: %s\n", *result.SessionID)
	}
	return err
}

func taskSessionID(task entities.Task) string {
	if task.SessionID == nil {
		return "-"
	}
	return *task.SessionID
}

func isTaskHTTP(err error, status int) bool {
	var apiError *client.TaskAPIError
	return errors.As(err, &apiError) && apiError.Status == status
}

type taskListRow struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	State     string    `json:"state"`
	SessionID string    `json:"session_id,omitempty"`
	Title     string    `json:"title"`
	UpdatedAt time.Time `json:"updated_at"`
}

func newTaskListCommand() *cobra.Command {
	var scope, team, states string
	var watch, asJSON bool
	cmd := taskCLI("list", "List queued tasks and existing sessions", cobra.NoArgs, func(cmd *cobra.Command, api *taskCLIClient, _ []string) error {
		ctx := cmd.Context()
		query := make(url.Values)
		if scope != "" && scope != "user" && scope != "team" {
			return errors.New("scope must be user or team")
		}
		if scope != "" {
			query.Set("scope", scope)
		}
		if team != "" {
			query.Set("team_id", team)
		}
		var filters []string
		for _, s := range strings.Split(states, ",") {
			if s != "" {
				filters = append(filters, strings.ToUpper(strings.TrimSpace(s)))
			}
		}
		var previous string
		var updates <-chan struct{}
		if watch {
			updates, _ = api.tasks.WatchTaskChanges(ctx, query)
		}
		for {
			rows, err := collectTaskRows(ctx, api, query, filters)
			if err != nil {
				if !watch || previous == "" {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "List refresh failed; reconnecting.")
			} else {
				raw, _ := json.Marshal(rows)
				if string(raw) != previous {
					if err := printTaskRows(cmd.OutOrStdout(), rows, raw, asJSON, watch); err != nil {
						return err
					}
					previous = string(raw)
				}
			}
			if !watch {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case _, ok := <-updates:
				if !ok {
					updates = nil
				}
			case <-time.After(4 * time.Second):
				if updates == nil {
					updates, _ = api.tasks.WatchTaskChanges(ctx, query)
				}
			}
		}
	})
	cmd.Flags().StringVar(&states, "state", "", "Comma separated task or session states")
	cmd.Flags().StringVar(&scope, "scope", "", "Ownership scope (user or team)")
	cmd.Flags().StringVar(&team, "team-id", "", "Filter by team")
	cmd.Flags().BoolVar(&watch, "watch", false, "Refresh when the queue or sessions change")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return cmd
}

func collectTaskRows(ctx context.Context, api *taskCLIClient, query url.Values, filters []string) ([]taskListRow, error) {
	query.Set("limit", "200")
	query.Del("cursor")
	items := map[string]entities.Task{}
	rows := make([]taskListRow, 0)
	for {
		page, err := api.tasks.ListTasks(ctx, query)
		if isTaskHTTP(err, http.StatusNotFound) {
			break
		} // Older server or disabled queue.
		if err != nil {
			return nil, err
		}
		for _, task := range page.Items {
			items[task.ID] = task
		}
		if page.NextCursor == "" {
			break
		}
		query.Set("cursor", page.NextCursor)
	}
	query.Del("cursor")
	var sessions client.SearchResponse
	if api.local == nil {
		response, err := api.SearchScoped(ctx, "", nil, query.Get("scope"), query.Get("team_id"))
		if err != nil {
			return nil, err
		}
		sessions = *response
		if query.Get("scope") == "" && query.Get("team_id") == "" {
			teamSessions, err := api.SearchScoped(ctx, "", nil, "team", "")
			if err != nil {
				return nil, err
			}
			sessions.Sessions = append(sessions.Sessions, teamSessions.Sessions...)
		}
	}
	bySession := map[string]entities.Task{}
	for _, item := range items {
		if item.SessionID != nil {
			bySession[*item.SessionID] = item
		}
	}
	seen := map[string]bool{}
	for _, session := range sessions.Sessions {
		if seen[session.SessionID] {
			continue
		}
		seen[session.SessionID] = true
		row := taskListRow{ID: session.SessionID, SessionID: session.SessionID, Source: "manual", State: strings.ToUpper(session.Status),
			Title: session.Metadata.Description, UpdatedAt: session.UpdatedAt}
		if row.UpdatedAt.IsZero() {
			row.UpdatedAt = session.StartedAt
		}
		if session.Tags["schedule_id"] != "" {
			row.Source = "schedule"
		}
		if session.Tags["webhook_id"] != "" {
			row.Source = "webhook"
		}
		if id := session.Tags["task_id"]; id != "" {
			row.ID, row.Source = id, "task"
		}
		if item, ok := bySession[session.SessionID]; ok {
			row.ID, row.Source, row.Title = item.ID, "task", item.Name
			if item.State.Pending() || item.State != entities.TaskReady && slices.Contains(filters, string(item.State)) {
				row.State = string(item.State)
			}
			delete(items, item.ID)
		}
		rows = append(rows, row)
	}
	for _, item := range items {
		row := taskListRow{ID: item.ID, Source: "task", State: string(item.State), Title: item.Name, UpdatedAt: item.UpdatedAt}
		if item.SessionID != nil {
			row.SessionID = *item.SessionID
		}
		rows = append(rows, row)
	}
	rows = slices.DeleteFunc(rows, func(row taskListRow) bool {
		return len(filters) > 0 && !slices.Contains(filters, row.State) &&
			!(row.State == "ACTIVE" && slices.Contains(filters, "RUNNING")) &&
			!(row.State == "CLAIMED" && slices.Contains(filters, "STARTING"))
	})
	slices.SortFunc(rows, func(a, b taskListRow) int {
		if order := b.UpdatedAt.Compare(a.UpdatedAt); order != 0 {
			return order
		}
		return strings.Compare(a.ID, b.ID)
	})
	return rows, nil
}

func printTaskRows(out io.Writer, rows []taskListRow, raw []byte, asJSON, watch bool) error {
	if asJSON {
		_, err := fmt.Fprintln(out, string(raw))
		return err
	}
	if file, ok := out.(*os.File); watch && ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(out, "\x1b[H\x1b[2J")
	}
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tSOURCE\tSTATE\tSESSION ID\tTITLE\tUPDATED")
	for _, row := range rows {
		id := row.SessionID
		if id == "" {
			id = "-"
		}
		title := strings.Join(strings.Fields(terminalText(row.Title)), " ")
		if runes := []rune(title); len(runes) > 80 {
			title = string(runes[:80]) + "…"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", row.ID, row.Source, row.State, id, title, row.UpdatedAt.Format(time.RFC3339))
	}
	return table.Flush()
}

func findTaskSession(ctx context.Context, api *client.Client, id, scope, team string) (client.SessionInfo, error) {
	result, err := api.SearchScoped(ctx, "", nil, scope, team)
	if err != nil {
		return client.SessionInfo{}, err
	}
	for _, session := range result.Sessions {
		if session.SessionID == id {
			return session, nil
		}
	}
	if scope == "" {
		return findTaskSession(ctx, api, id, "team", "")
	}
	return client.SessionInfo{}, &client.TaskAPIError{Status: http.StatusNotFound, Message: "session not found"}
}

func resolveTaskSession(ctx context.Context, api *taskCLIClient, id string, wait bool, notice io.Writer) (client.SessionInfo, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !strings.HasPrefix(id, "tsk_") {
		for {
			session, err := findTaskSession(ctx, api.Client, id, "", "")
			if err != nil {
				return client.SessionInfo{}, err
			}
			switch session.Status {
			case "creating", "starting", "resuming", "restoring":
				if !wait {
					return client.SessionInfo{}, errors.New("NOT_READY: session is still provisioning")
				}
			case "error", "failed", "timeout":
				return client.SessionInfo{}, fmt.Errorf("session startup failed: %s", session.Status)
			default:
				return session, nil
			}
			select {
			case <-ctx.Done():
				return client.SessionInfo{}, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	var changes <-chan struct{}
	waiting := false
	backoff := time.Second
	for {
		record, err := api.tasks.ShowTask(ctx, id)
		if err != nil {
			return client.SessionInfo{}, err
		}
		switch record.State {
		case entities.TaskReady:
			if record.SessionMissing || record.SessionID == nil {
				return client.SessionInfo{}, errors.New("session was removed")
			}
			return findTaskSession(ctx, api.Client, *record.SessionID, string(record.Scope), record.TeamID)
		case entities.TaskFailed, entities.TaskCancelled, entities.TaskExpired:
			return client.SessionInfo{}, fmt.Errorf("task %s: %s %s", id, record.State, record.Reason)
		}
		if !wait {
			return client.SessionInfo{}, errors.New("NOT_READY: the task has no ready session")
		}
		if !waiting {
			fmt.Fprintln(notice, "Waiting for session allocation...")
			waiting = true
		}
		if changes == nil {
			query := url.Values{"scope": {string(record.Scope)}}
			if record.TeamID != "" {
				query.Set("team_id", record.TeamID)
			}
			changes, _ = api.tasks.WatchTaskChanges(ctx, query)
		}
		select {
		case <-ctx.Done():
			return client.SessionInfo{}, ctx.Err()
		case _, ok := <-changes:
			if !ok {
				changes = nil
				select {
				case <-ctx.Done():
					return client.SessionInfo{}, ctx.Err()
				case <-time.After(backoff):
					backoff = min(2*backoff, 8*time.Second)
				}
			}
		case <-time.After(backoff):
			backoff = min(2*backoff, 8*time.Second)
		}
	}
}

func sendTaskMessage(ctx context.Context, api *client.Client, id, message string) error {
	response, err := api.SendMessage(ctx, id, &client.Message{Content: message, Type: "user"})
	if err != nil || !response.OK {
		return errors.New("message delivery was not confirmed; check session history before sending again")
	}
	return nil
}
