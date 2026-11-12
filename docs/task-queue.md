# Task Queue and session attach

The task queue accepts a single initial message and starts a regular ccplant
Session in the background. A task is ready when its Session is available. The
agent can continue processing the first message or accept additional messages.

## Submit and attach

Set `AGENTAPI_PROXY_ENDPOINT` to the API base URL and `AGENTAPI_KEY` to your
existing user or team API credential. Copy [the example](../examples/repository-task.yaml)
and set `session_profile_id` to an accessible profile with the repository,
runtime, and credentials you need.

```sh
ccplant submit repository-task.yaml --idempotency-key review-001
ccplant list --watch
ccplant task show tsk_...
ccplant attach tsk_...
ccplant send tsk_... 'Focus on the session lifecycle.' --wait
```

A terminal can close immediately after submit. Use the same idempotency key
and definition if the response is lost. Reusing a key with a different
definition returns HTTP 409. A retry of a failed, cancelled, or expired task
has its own task and session IDs.

Use `attach --follow=false` for a history snapshot, `--no-input` to follow
without sending, or `--plain` for line input. `--since N` skips the first N
messages and `--tail N` limits the initial snapshot. The terminal interface
shows the Session and connection status, a scrollable transcript, and a
multiline editor. Enter sends, Ctrl+J inserts a line break, and Ctrl+C clears
the draft. In plain mode, `/multiline` starts a draft and `/send` submits it.
`/detach` or Ctrl+D disconnects the CLI. `/resume` requires confirmation.
Set `CCPLANT_UI_URL` for `/open`.

The terminal and browser share the Session message APIs. Concurrent sends
follow the ordering supported by that runtime. If a send result is uncertain,
check the shared history before resending. The CLI does not store a transcript.

## Task state and cancellation

| State | Meaning |
| --- | --- |
| QUEUED | Waiting for worker or available capacity |
| CLAIMED | A worker has reserved the startup slot and Session ID |
| STARTING | A startup request was dispatched or the Session is provisioning |
| SESSION_READY | The Session can be used |
| FAILED | Startup failed |
| CANCELLED | A cancellation was accepted |
| EXPIRED | The queue deadline elapsed before dispatch |

`task cancel` cancels queued work. If it races an in-flight start, the task
retains the ID of any resulting Session. To delete a Session, use the existing
Session controls or run `task cancel --force-session-stop` and confirm twice.
To send to an already assigned Session while the Task is still reconciling,
use its Session ID once the Session is available.

The persistent specification accepts `scope`, `team_id`, `session_profile_id`,
`workspace_id`, tags, and `params.message`, `params.pool`, and
`params.manager_id`. Environment overrides are limited to valid `TZ`, `LANG`,
and `LC_ALL` values. Keep secrets in a profile or ccplant Secret. The initial
message is stored as task input, so keep credentials out of prompts and tags.

## Rollout

1. Confirm that all API replicas share the same durable application KV
   namespace. Task records use the existing versioned Secret document
   format and work with the libSQL, encrypted libSQL, and Kubernetes KV
   adapters. The normal KV setup creates the schema.
2. Roll out the API and Worker binaries with the feature disabled. Roll out
   the web UI and distribute the CLI. The existing API remains usable.
3. Configure the API and Worker with the same existing worker control token
   and execution signing key. Enable `backend.taskQueue.enabled` in the
   umbrella chart or `taskQueue.enabled` in the backend chart. For non-Helm
   deployments set `AGENTAPI_TASK_QUEUE_ENABLED=true` on the API and Worker.
4. Submit a canary as a user and as a team. Verify queued visibility, repository
   checkout, shared CLI and browser history, suspend, detach, and reattach.
   Restart a Worker while provisioning and verify that the original Task
   resolves to one Session ID.

The queue accepts submissions regardless of the number of queued tasks or
active Sessions. The existing Session Pool binding quota applies to all
Session starts, including those from the queue. A task that cannot start
because the pool is full returns to the queue and retries when capacity is
available, subject to its own queue deadline.

Finished task records and their events are kept for 90 days. Session storage
follows the existing Session policies.

To disable the API and Worker integration, turn off the feature on both roles.
Persisted records remain available when the feature is reenabled.

## Troubleshoot

- Queue grows with no claims: check that the Worker is running and that its
  control endpoint and signing credentials match the API.
- `WAITING_CAPACITY`: check the binding quota and available capacity in the resolved Session Pool.
- `START_UNCERTAIN`: check the recorded Session ID, API logs, and runner
  allocation. The queue waits for the prior lease before trying another
  dispatch with the same Session ID.
- HTTP 422 at submission: move environment secrets to a profile or Secret.
- `SESSION_MISSING`: check the existing Session deletion or TTL policy.
- HTTP 503 on the Task API: check the configured application KV backend.

Scrape the API metrics port. Use `max by (scope)(task_queue_depth)` and
`max by (scope)(task_queue_oldest_seconds)` across replicas for shared queue
gauges. Alert when the oldest wait exceeds your SLA, when
`max by (scope)(task_starting_overdue)` stays above zero, or when
`sum by (reason)(rate(tasks_failed_total[5m]))` rises. Use
`task_claim_conflict_total`, `task_reconciliation_total`, and the wait/start
histograms to distinguish contention, recoveries, and slow provisioning.

## Run the queue on your computer with SQLite

Task commands default to the server queue. Select SQLite with
`--queue sqlite` or `CCPLANT_TASK_QUEUE=sqlite`. Keep the same API endpoint
and `AGENTAPI_KEY` for the task commands and the worker. The SQLite file
keeps separate queues for each endpoint and credential, so switching keys
selects a different queue. The credential itself is kept out of the file.

```sh
export CCPLANT_TASK_QUEUE=sqlite
# Set AGENTAPI_PROXY_ENDPOINT and AGENTAPI_KEY as for a normal ccplant session.
ccplant submit repository-task.yaml
ccplant list
# Run this in a terminal to process the local queue.
ccplant task worker
# Use another terminal with the same configuration to attach or cancel.
ccplant attach tsk_...
```

The database defaults to `ccplant/tasks.sqlite3` under your OS user configuration
directory. Set `CCPLANT_TASK_SQLITE_PATH` or pass `--sqlite-path` on each task
command to use a different file. The file contains task inputs and must have
private file permissions. The same file can be reopened after a process or
machine restart.

Local submission, listing, inspection and cancellation work offline. The
foreground worker needs the API to start and reconcile sessions. It uses the
ordinary `/start` and `/search` endpoints, so this mode works with the server
task queue disabled. Local tasks appear in the CLI for that SQLite queue.
Sessions they start appear in ccplant as ordinary sessions.

When the computer sleeps or shuts down, the local worker stops requesting new
sessions. Start it again to process pending tasks within their original queue
deadlines. Sessions already started on the server continue independently.
When the server returns HTTP 429, the worker requeues the task and tries again
after a delay. If it cannot connect, the task stays queued as
`WAITING_FOR_API`. If the server may have accepted a request but the response
was lost, the task shows `START_UNCERTAIN`. The worker looks for a matching
session by its dispatch tag. If the API never exposes a match, the task stays
in that state to avoid a duplicate session.
