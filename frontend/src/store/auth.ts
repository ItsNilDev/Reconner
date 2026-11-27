import { create } from 'zustand'
import { auth as authApi } from '../lib/api'
import { useStatsStore } from './stats'

interface AuthState {
  user: {id?: number; username: string; role: string; must_change_password?: boolean} | null
  initialized: boolean
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  checkAuth: () => Promise<void>
  refreshMe: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null, initialized: false, loading: false,
  login: async (username, password) => {
    set({ loading: true })
    try {
      await authApi.login(username, password)
      const user = await authApi.me()
      // A second login without an intervening logout (e.g. back navigation to
      // /login) must not leave the previous user's dashboard data or in-flight
      // single-flight fetches visible to the new user.
      useStatsStore.getState().reset()
      set({ user, loading: false })
    } catch (err) { set({ loading: false }); throw err }
  },
  logout: async () => {
    await authApi.logout().catch(() => {})
    useStatsStore.getState().reset()
    set({ user: null })
  },
  checkAuth: async () => {
    try { const user = await authApi.me(); set({ user, initialized: true }) }
    catch { set({ user: null, initialized: true }) }
  },
  refreshMe: async () => {
    try { const user = await authApi.me(); set({ user }) } catch { /* keep current */ }
  },
}))
