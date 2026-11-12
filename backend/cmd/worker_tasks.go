package cmd

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/controlapi"
)

func runTaskWorker(ctx context.Context, api *controlapi.SessionManager) {
	worker := uuid.NewString()
	// Bound in-flight HTTP requests per worker. Session admission is handled by /start.
	const limit = 10
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	done := make(chan struct{}, limit)
	var running sync.WaitGroup
	defer running.Wait()
	active := 0
	nextPrune := time.Now()
	for ctx.Err() == nil {
		if active < limit {
			requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			jobs, err := api.ClaimTasks(requestCtx, worker, limit-active)
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Print("[TASK_QUEUE] claim request failed")
			}
			for _, job := range jobs {
				active++
				running.Add(1)
				go func() {
					defer running.Done()
					defer func() { done <- struct{}{} }()
					runTaskJob(ctx, api, worker, job)
				}()
			}
		}
		if time.Now().After(nextPrune) {
			requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := api.PruneTasks(requestCtx); err != nil && ctx.Err() == nil {
				log.Print("[TASK_QUEUE] retention cleanup failed")
			}
			cancel()
			nextPrune = time.Now().Add(time.Hour)
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
			active--
		case <-tick.C:
		}
	}
}

func runTaskJob(ctx context.Context, api *controlapi.SessionManager, worker string, job controlapi.TaskJob) {
	execution, cancel := context.WithCancel(ctx)
	defer cancel()
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		tick := time.NewTicker(45 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-execution.Done():
				return
			case <-tick.C:
				req, release := context.WithTimeout(execution, 10*time.Second)
				_ = api.HeartbeatTask(req, worker, job)
				release()
			}
		}
	}()
	status, err := api.StartTask(execution, job)
	cancel()
	<-heartbeatDone
	if err != nil && ctx.Err() == nil {
		log.Printf("[TASK_QUEUE] start response uncertain task_id=%s generation=%d", job.TaskID, job.Generation)
	}
	if ctx.Err() != nil {
		return
	}
	req, release := context.WithTimeout(ctx, 15*time.Second)
	defer release()
	if err := api.FinalizeTask(req, worker, job, status); err != nil {
		log.Printf("[TASK_QUEUE] finalize request failed task_id=%s generation=%d", job.TaskID, job.Generation)
	}
}
