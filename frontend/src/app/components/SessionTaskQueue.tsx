'use client'

import { useEffect, useMemo, useState } from 'react'
import useSWR from 'swr'
import { AgentAPIProxyClient, AgentAPIProxyError, SessionTask, SessionTaskScope } from '../../lib/agentapi-proxy-client'
import type { Session } from '../../types/agentapi'

const statusLabels = {
  QUEUED: '待機中',
  CLAIMED: '起動待ち',
  STARTING: '起動中',
  SESSION_READY: '起動済み',
  FAILED: '起動失敗',
  CANCELLED: 'キャンセル済み',
  EXPIRED: '待機期限切れ',
}

function taskReason(task: SessionTask): string | undefined {
  switch (task.reason) {
    case 'WAITING_CAPACITY': return '空き枠を待っています'
    case 'START_UNCERTAIN': return 'セッションの起動状況を確認しています'
    case 'CANCELLATION_REQUESTED': return 'キャンセルを処理しています'
    case 'SESSION_MISSING': return '起動したセッションが見つかりません'
    default: return task.reason
  }
}

interface Props {
  client: AgentAPIProxyClient
  team?: string | null
  sessions: Session[]
  refreshSessions: (silent?: boolean) => Promise<void>
}

export function SessionTaskQueue({ client, team, sessions, refreshSessions }: Props) {
  const scope = useMemo<SessionTaskScope>(() => team ? { scope: 'team', team_id: team } : { scope: 'user' }, [team])
  const [busy, setBusy] = useState<string>()
  const [operationError, setOperationError] = useState<string>()
  const [visible, setVisible] = useState(true)
  const { data, error, mutate } = useSWR<SessionTask[] | null, Error>(['session-task-queue', client, team ?? ''], async () => {
    try {
      return await client.listSessionTasks(scope)
    } catch (error) {
      if (error instanceof AgentAPIProxyError && error.status === 404) return null
      throw error
    }
  }, { refreshInterval: 30000, revalidateOnFocus: true, shouldRetryOnError: false })
  const enabled = data !== undefined && data !== null

  useEffect(() => {
    const visibility = () => setVisible(!document.hidden)
    visibility()
    document.addEventListener('visibilitychange', visibility)
    return () => document.removeEventListener('visibilitychange', visibility)
  }, [])

  useEffect(() => {
    if (!enabled || !visible) return
    let timer: ReturnType<typeof setTimeout> | undefined
    const stream = client.subscribeToSessionTaskChanges(scope, () => {
      clearTimeout(timer)
      timer = setTimeout(() => {
        void refreshSessions(true).finally(() => { void mutate() })
      }, 250)
    })
    return () => {
      clearTimeout(timer)
      stream.close()
    }
  }, [client, enabled, mutate, refreshSessions, scope, visible])

  const sessionIDs = new Set(sessions.map(session => session.session_id))
  const tasks = data?.filter(task => !task.session_id || !sessionIDs.has(task.session_id)) ?? []
  if (tasks.length === 0 && !error) return null

  async function change(task: SessionTask, retry: boolean) {
    setBusy(task.id)
    setOperationError(undefined)
    try {
      if (retry) await client.retrySessionTask(task.id)
      else await client.cancelSessionTask(task.id)
    } catch {
      setOperationError('タスクの操作に失敗しました。現在の状態を確認してください。')
    } finally {
      await mutate().catch(() => undefined)
      setBusy(undefined)
    }
  }

  return (
    <section aria-labelledby="session-task-queue-title" className="space-y-2">
      <h2 id="session-task-queue-title" className="text-sm font-semibold">タスクキュー</h2>
      {(error || operationError) && <p role="alert" className="text-sm text-red-600 dark:text-red-400">
        {operationError ?? 'タスクキューに接続できません。'}
      </p>}
      <ul className="divide-y divide-gray-200 rounded-md border border-gray-200 dark:divide-gray-700 dark:border-gray-700">
        {tasks.map(task => {
          const retry = task.state === 'FAILED' || task.state === 'EXPIRED'
          return (
            <li key={task.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
              <details className="min-w-0 text-sm">
                <summary className="cursor-pointer break-words"><strong>{task.name}</strong> · {statusLabels[task.state]}</summary>
                <p className="break-all text-xs text-gray-500 dark:text-gray-400">{task.id}</p>
                {taskReason(task) && <p className="text-xs text-gray-600 dark:text-gray-300">{taskReason(task)}</p>}
              </details>
              <button type="button" disabled={busy !== undefined || task.cancel_requested} onClick={() => void change(task, retry)}
                className="rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-100 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-800">
                {retry ? '再試行' : 'キャンセル'}
              </button>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
