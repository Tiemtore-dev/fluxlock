export const hex = (b: Uint8Array) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('')
export const fromHex = (s: string) => {
  if (!/^[0-9a-f]{64}$/u.test(s)) throw new Error('Clé de profil invalide')
  return Uint8Array.from(s.match(/../gu)!, (v) => Number.parseInt(v, 16))
}
export const b64 = (bytes: Uint8Array) => {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192))
  }
  return btoa(binary)
}
export const unb64 = (s: string) => {
  if (s.length > 60000) throw new Error('Trame trop grande')
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
}
type Exports = {memory: WebAssembly.Memory; input_ptr(): number; output_ptr(): number; output_len(): number; execute(op: number, len: number): number; clear(): void}
export class Noise {
  private constructor(private readonly api: Exports) {}
  static async create(privateKey: Uint8Array): Promise<Noise> {
    let api: Exports
    const bytes = await (await fetch(chrome.runtime.getURL('noise.wasm'))).arrayBuffer()
    const result = await WebAssembly.instantiate(bytes, { fluxlock: { random_fill(ptr: number, len: number) {
      if (!api || len > 65536) return 0
      try { crypto.getRandomValues(new Uint8Array(api.memory.buffer, ptr, len)); return 1 } catch { return 0 }
    } } })
    api = result.instance.exports as unknown as Exports
    const noise = new Noise(api)
    noise.run(0, privateKey)
    return noise
  }
  run(op: number, input: Uint8Array = new Uint8Array()): Uint8Array {
    if (input.length > 65536) { this.clear(); throw new Error('Message trop grand') }
    // input_ptr initializes thread-local buffers and may grow WASM memory.
    // Obtain the pointer before reading memory.buffer (growth detaches old views).
    const inputPtr = this.api.input_ptr()
    new Uint8Array(this.api.memory.buffer, inputPtr, input.length).set(input)
    if (this.api.execute(op, input.length) !== 1) throw new Error('Canal chiffré refusé')
    const outputPtr = this.api.output_ptr(), length = this.api.output_len()
    const view = new Uint8Array(this.api.memory.buffer, outputPtr, length)
    const copy = view.slice()
    view.fill(0)
    return copy
  }
  clear() { this.api.clear() }
}
