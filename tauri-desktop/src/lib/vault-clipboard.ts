let timer: number | undefined
let copied = false
let generation = 0

/** Best effort: clipboard APIs can be denied when the application loses focus. */
export async function clearVaultClipboard() {
  generation += 1
  if (timer !== undefined) window.clearTimeout(timer)
  timer = undefined
  if (!copied) return
  copied = false
  try { await navigator.clipboard.writeText('') } catch { /* OS clipboard unavailable */ }
}

export async function copyVaultText(text: string, delay: number) {
  const started = generation
  await navigator.clipboard.writeText(text)
  copied = true
  // A native clipboard write may finish after the originating vault was locked.
  if (started !== generation) { await clearVaultClipboard(); return }
  if (timer !== undefined) window.clearTimeout(timer)
  timer = window.setTimeout(() => { void clearVaultClipboard() }, delay)
}
