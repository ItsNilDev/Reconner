import { create } from 'zustand'
import { dashboard, type DashboardCharts } from '../lib/api'
import type { DashboardStats } from '../types'

interface StatsState {
  badges: { targets: number; running_tasks: number }
  stats: DashboardStats | null
  charts: DashboardCharts | null
  chartsError: string
  statsError: string
  loading: boolean
  fetchBadges: () => Promise<void>
  fetchStats: () => Promise<void>
  reset: () => void
}

let generation = 0
let badgesInFlight: Promise<void> | null = null
let statsInFlight: Promise<void> | null = null

export const useStatsStore = create<StatsState>((set, get) => ({
  badges: { targets: 0, running_tasks: 0 },
  stats: null,
  charts: null,
  chartsError: '',
  statsError: '',
  loading: false,

  fetchBadges: () => {
    if (badgesInFlight) return badgesInFlight
    const gen = generation
    const p = dashboard.badges()
      .then(b => {
        if (gen !== generation) return
        set({ badges: { targets: b.targets || 0, running_tasks: b.running_tasks || 0 } })
      })
      .catch(() => { /* keep last known badges */ })
      .finally(() => {
        if (badgesInFlight === p) badgesInFlight = null
      })
    badgesInFlight = p
    return p
  },

  fetchStats: () => {
    if (statsInFlight) return statsInFlight
    const gen = generation
    if (!get().stats) set({ loading: true, statsError: '' })
    else set({ statsError: '' })
    const p = Promise.all([
      dashboard.stats(),
      dashboard.charts().then(
        data => ({ data, err: '' }),
        e => ({ data: null as DashboardCharts | null, err: e instanceof Error ? e.message : 'Could not load charts' }),
      ),
    ])
      .then(([s, cRes]) => {
        if (gen !== generation) return
        set({
          stats: s,
          badges: { targets: s.targets || 0, running_tasks: s.running_tasks || 0 },
          chartsError: cRes.err,
          ...(cRes.err ? {} : { charts: cRes.data }),
          statsError: '',
          loading: false,
        })
      })
      .catch(e => {
        if (gen !== generation) return
        set({
          statsError: e instanceof Error ? e.message : 'Failed to load dashboard statistics',
          loading: false,
        })
      })
      .finally(() => {
        if (statsInFlight === p) statsInFlight = null
      })
    statsInFlight = p
    return p
  },

  reset: () => {
    generation++
    badgesInFlight = null
    statsInFlight = null
    set({
      badges: { targets: 0, running_tasks: 0 },
      stats: null,
      charts: null,
      chartsError: '',
      statsError: '',
      loading: false,
    })
  },
}))
