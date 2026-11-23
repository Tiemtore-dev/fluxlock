type Identity = {key: CryptoKey; iv: Uint8Array; wrapped: ArrayBuffer; peer?: string}
async function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('fluxlock-browser-identity-v2', 1)
    request.onupgradeneeded = () => request.result.createObjectStore('identity')
    request.onerror = () => reject(new Error('Stockage du profil indisponible'))
    request.onsuccess = () => resolve(request.result)
  })
}
async function stored(): Promise<Identity | undefined> {
  const database = await db()
  try { return await new Promise((resolve, reject) => {
    const request = database.transaction('identity').objectStore('identity').get('local')
    request.onsuccess = () => resolve(request.result as Identity | undefined)
    request.onerror = () => reject(new Error('Profil illisible'))
  }) } finally { database.close() }
}
async function save(identity: Identity): Promise<void> {
  const database = await db()
  try { await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction('identity', 'readwrite')
    transaction.objectStore('identity').put(identity, 'local')
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new Error('Enregistrement du profil impossible'))
    transaction.onabort = () => reject(new Error('Enregistrement interrompu'))
  }) } finally { database.close() }
}
export async function identity(): Promise<{privateKey: Uint8Array; peer?: string}> {
  let record = await stored()
  if (!record) {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    const secret = crypto.getRandomValues(new Uint8Array(64))
    const iv = crypto.getRandomValues(new Uint8Array(12))
    try { record = { key, iv, wrapped: await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('fluxlock-profile-v2/ML-DSA-65/Noise') }, key, secret) }; await save(record) }
    finally { secret.fill(0) }
  }
  const privateKey = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(record.iv).buffer, additionalData: new TextEncoder().encode('fluxlock-profile-v2/ML-DSA-65/Noise') }, record.key, record.wrapped))
  if (privateKey.length !== 64) { privateKey.fill(0); throw new Error('Profil invalide : nouvel appairage post-quantique nécessaire') }
  // Legacy keys are never read or upgraded into trusted PQ identities.
  indexedDB.deleteDatabase('fluxlock-browser-identity')
  return { privateKey, peer: record.peer }
}
export async function pinPeer(peer: string) {
  if (!/^[0-9a-f]{64}$/u.test(peer)) throw new Error('Identité native invalide')
  const record = await stored()
  if (!record || record.peer && record.peer !== peer) throw new Error('Identité FluXlock différente')
  record.peer = peer; await save(record)
}
export async function resetIdentity() {
  const database = await db()
  try { await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction('identity', 'readwrite'); transaction.objectStore('identity').delete('local')
    transaction.oncomplete = () => resolve(); transaction.onerror = () => reject(new Error('Suppression impossible'))
  }) } finally { database.close() }
}
