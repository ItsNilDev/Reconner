type Handler = (payload: unknown) => void

class WSClient {
  private ws: WebSocket | null = null
  private handlers = new Map<string, Set<Handler>>()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectDelay = 1000
  private shouldConnect = false
  private wasConnected = false
  private pingInterval: ReturnType<typeof setInterval> | null = null

  connect() { this.shouldConnect = true; this._connect() }

  disconnect() {
    this.shouldConnect = false
    this.wasConnected = false
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null }
    if (this.pingInterval) { clearInterval(this.pingInterval); this.pingInterval = null }
    const socket = this.ws
    this.ws = null
    if (socket) {
      try { socket.close() } catch { /**/ }
      this._emit('close', null)
    }
  }

  private _connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    let socket: WebSocket
    try { socket = new WebSocket(`${proto}//${window.location.host}/ws`) }
    catch { this._scheduleReconnect(); return }
    this.ws = socket
    socket.onopen = () => {
      if (this.ws !== socket) return
      const reconnected = this.wasConnected
      this.wasConnected = true
      this.reconnectDelay = 1000
      if (this.pingInterval) { clearInterval(this.pingInterval); this.pingInterval = null }
      this.pingInterval = setInterval(() => {
        if (this.ws === socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'ping' }))
        }
      }, 25000)
      this._emit('open', null)
      if (reconnected) this._emit('reconnected', null)
    }
    socket.onmessage = (ev) => {
      if (this.ws !== socket) return
      try {
        const msg = JSON.parse(ev.data as string) as {type: string; payload: unknown}
        this._emit(msg.type, msg.payload)
        this._emit('*', msg)
      } catch { /**/ }
    }
    socket.onclose = () => {
      if (this.ws !== socket) return
      if (this.pingInterval) { clearInterval(this.pingInterval); this.pingInterval = null }
      this._emit('close', null)
      if (this.shouldConnect) this._scheduleReconnect()
    }
    socket.onerror = () => {
      if (this.ws !== socket) return
      socket.close()
    }
  }

  private _scheduleReconnect() {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      if (this.shouldConnect) this._connect()
    }, this.reconnectDelay)
    this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, 30000)
  }

  private _emit(type: string, payload: unknown) {
    this.handlers.get(type)?.forEach(h => { try { h(payload) } catch { /**/ } })
  }

  on(type: string, handler: Handler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set())
    this.handlers.get(type)!.add(handler)
    return () => this.handlers.get(type)?.delete(handler)
  }

  get connected(): boolean { return this.ws?.readyState === WebSocket.OPEN }
}

export const ws = new WSClient()
