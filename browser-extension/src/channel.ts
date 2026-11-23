import { Noise, b64, unb64, hex } from './noise.js'
import { identity, pinPeer } from './identity.js'
import { nativeHost } from './config.js'
export type Message = Record<string, unknown>
export class Channel {
  private pending?: {resolve: (b: Uint8Array) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout>}
  private port: any
  private noise?: Noise
  private peer = ''
  fingerprint = ''
  welcome: Message = {}
  async open() {
    const record = await identity()
    try { this.noise = await Noise.create(record.privateKey) } finally { record.privateKey.fill(0) }
    this.port = chrome.runtime.connectNative(nativeHost)
    this.port.onMessage.addListener((envelope: unknown) => {
      try {
        const v = envelope as { version?: unknown; frame?: unknown }
        if (!v || Object.keys(v).length !== 2 || v.version !== 2 || typeof v.frame !== 'string' || !this.pending) throw new Error('Passerelle incompatible : mettez à jour FluXlock et le relais post-quantique')
        const pending = this.pending; this.pending = undefined; clearTimeout(pending.timer); pending.resolve(unb64(v.frame))
      } catch (e) { this.close(e instanceof Error ? e : new Error('Canal refusé')) }
    })
    this.port.onDisconnect.addListener(() => { const error = chrome.runtime.lastError; this.close(new Error(error?.message || 'Connexion FluXlock fermée')) })
    const second = await this.exchange(this.noise.run(1))
    this.noise.run(2, second)
    this.peer = hex(this.noise.run(3))
    if (record.peer && record.peer !== this.peer) { this.close(); throw new Error('Identité FluXlock différente. Révoquez puis réappairez le profil.') }
    const third = this.noise.run(1)
    this.fingerprint = new TextDecoder().decode(this.noise.run(4))
    this.noise.run(5)
    this.welcome = this.decode(await this.exchange(third))
    if (this.welcome.fingerprint !== this.fingerprint) throw new Error('Empreinte de connexion invalide')
    if (this.welcome.state === 'connected' && !record.peer) throw new Error('Appairage incomplet. Révoquez ce profil dans FluXlock puis reconnectez-le.')
  }
  private exchange(frame: Uint8Array): Promise<Uint8Array> {
    if (this.pending || !this.port) throw new Error('Canal occupé ou fermé')
    return new Promise((resolve, reject) => {
      this.pending = { resolve, reject, timer: setTimeout(() => this.close(new Error('La demande a expiré')), 12000) }
      try { this.port.postMessage({ version: 2, frame: b64(frame) }) } catch { this.close(new Error('Passerelle indisponible')) }
    })
  }
  private decode(frame: Uint8Array): Message {
    if (!this.noise) throw new Error('Canal fermé')
    const plaintext = this.noise.run(7, frame)
    try {
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext))
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Réponse invalide')
      return value as Message
    } finally { plaintext.fill(0) }
  }
  async request(message: Message): Promise<Message> {
    if (!this.noise) throw new Error('Canal fermé')
    const bytes = new TextEncoder().encode(JSON.stringify(message))
    if (bytes.length > 32768) throw new Error('Demande trop grande')
    try { return this.decode(await this.exchange(this.noise.run(6, bytes))) } finally { bytes.fill(0) }
  }
  async rememberPeer() { await pinPeer(this.peer) }
  close(error = new Error('Canal fermé')) {
    if (this.pending) { clearTimeout(this.pending.timer); this.pending.reject(error); this.pending = undefined }
    const port = this.port; this.port = undefined; this.noise?.clear(); this.noise = undefined
    try { port?.disconnect() } catch { /* already disconnected */ }
  }
}
