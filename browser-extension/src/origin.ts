export function canonicalOrigin(value: string): string {
  if (value.length > 4096 || /[\u0000-\u001f\u007f\\]/u.test(value)) throw new Error('URL refusée')
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname || url.hostname.endsWith('.')) {
    throw new Error('Le remplissage exige une origine HTTPS exacte.')
  }
  if (/[^\x00-\x7f]/u.test(url.hostname)) throw new Error('Domaine non canonique')
  return url.origin
}
export function sameOrigin(stored: string, current: string) {
  try { return canonicalOrigin(stored) === canonicalOrigin(current) } catch { return false }
}
