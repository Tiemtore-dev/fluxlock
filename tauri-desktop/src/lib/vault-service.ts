/**
 * VaultService — typed abstraction over Tauri IPC calls.
 * All frontend components consume this service instead of invoking Tauri directly.
 */
import { invoke } from './vault-context'

/** VULN-020: Max length limits for user-supplied string fields */
const FIELD_MAX_LENGTHS: Record<string, number> = {
  title: 256,
  username: 256,
  password: 4096,
  url: 2048,
  notes: 10000,
  category: 128,
  email: 320,
  filename: 256,
  key_name: 256,
}

/** Convert empty strings to undefined so Rust receives null for Option<String> fields.
 *  Also enforces max-length on known fields (VULN-020). */
function clean<T extends object>(obj: T): T {
  const out = { ...obj } as any
  for (const k of Object.keys(out)) {
    if (out[k] === '') {
      out[k] = undefined
    } else if (typeof out[k] === 'string') {
      const maxLen = FIELD_MAX_LENGTHS[k]
      if (maxLen && out[k].length > maxLen) {
        out[k] = out[k].slice(0, maxLen)
      }
    }
  }
  return out as T
}

/* ─── Domain Types ─── */

export interface Password {
  id: number
  user_id: number
  title: string
  username?: string
  password: string
  url?: string
  notes?: string
  category?: string
  has_totp?: boolean
  created_at: string
  updated_at: string
}

export interface PasswordPayload {
  title: string
  username?: string
  password: string
  url?: string
  notes?: string
  category?: string
  totp_secret?: string
}

export interface TotpOutput {
  code: string
  period: number
  remaining_seconds: number
  digits: number
  algorithm: string
  issuer?: string
  account?: string
}

export interface TotpLiveItem {
  id: number
  source: 'standalone' | 'password'
  issuer: string
  account: string
  code: string
  period: number
  remaining_seconds: number
  digits: number
  algorithm: string
}

export interface CreateTotpPayload {
  issuer?: string
  account?: string
  secret_or_uri: string
  algorithm?: string
  digits?: number
  period?: number
}

export interface ImportTotpMigrationResponse {
  imported_count: number
  accounts: string[]
}

export interface PaymentCard {
  id: number
  user_id: number
  title: string
  cardholder_name: string
  card_number: string
  brand: string
  last4: string
  exp_month: string
  exp_year: string
  cvv: string
  notes?: string
  created_at: string
  updated_at: string
}

export interface PaymentCardPayload {
  title: string
  cardholder_name: string
  card_number: string
  exp_month: string
  exp_year: string
  cvv: string
  notes?: string
}

export interface IdentityDocument {
  id: number
  user_id: number
  doc_type: string
  title: string
  full_name: string
  document_number: string
  issuing_authority?: string
  issue_date?: string
  expiry_date?: string
  nationality?: string
  birth_date?: string
  notes?: string
  created_at: string
  updated_at: string
}

export interface IdentityDocumentPayload {
  doc_type: string
  title: string
  full_name: string
  document_number: string
  issuing_authority?: string
  issue_date?: string
  expiry_date?: string
  nationality?: string
  birth_date?: string
  notes?: string
}

export interface IssuedSdJwt {
  compact_sd_jwt: string
  issuer_public_key_b64url: string
  sd_digests: string[]
}

export interface PasskeyEntry {
  id: number
  user_id: number
  credential_id: string
  rp_id: string
  rp_name: string
  user_handle: string
  user_name: string
  user_display_name: string
  cose_algorithm: number
  public_key: string
  sign_count: number
  created_at: string
  last_used_at?: string
}

export interface CreatedPasskey {
  credential_id_b64url: string
  rp_id: string
  rp_name: string
  user_handle_b64url: string
  user_name: string
  user_display_name: string
  cose_algorithm: number
  public_key_b64url: string
  cose_public_key_b64url: string
  authenticator_data_b64url: string
  client_data_json_b64url: string
}

export interface PasskeyAssertion {
  credential_id_b64url: string
  rp_id: string
  authenticator_data_b64url: string
  client_data_json_b64url: string
  signature_b64url: string
  user_handle_b64url?: string
  new_sign_count: number
}

export interface VaultSyncStatus {
  sync_enabled: boolean
  paired_devices_count: number
  oplog_entries_count: number
  latest_hlc?: string | null
  merkle_root_blake3: string
}

export interface SecureFile {
  id: number
  user_id: number
  filename: string
  file_path: string
  file_size: number
  mime_type?: string
  created_at: string
}

export interface SecureKey {
  id: number
  user_id: number
  key_name: string
  key_type: string
  key_data: string
  algorithm: string
  created_at: string
}

export interface SecurityEvent {
  id: number
  user_id: number
  event_type: string
  description: string
  severity?: string
  ip_address?: string
  timestamp: string
}

export interface FileShare {
  id: number
  file_id: number
  owner_id: number
  recipient_email: string
  share_token: string
  encrypted_key: string
  expires_at: string
  accessed: boolean
  access_count: number
  created_at: string
  filename?: string
}

export interface AuthResponse {
  success: boolean
  token?: string
  message: string
  user_id?: number
  username?: string
  email?: string
}

export interface AutoLockStatus {
  locked: boolean
  reason?: string
  remaining_seconds?: number
  elapsed_minutes?: number
}

/* ─── Auth Service ───
 * M02 SECURITY NOTE — IPC Password Transport:
 * Le mot de passe est envoyé en clair via Tauri IPC (HTTPS localhost intra-processus).
 * Ceci est acceptable car :
 * 1. L'IPC Tauri ne quitte jamais le processus local (pas de réseau).
 * 2. Le WebView est sandboxé dans le processus Tauri.
 * 3. Un attaquant contrôlant le JS pourrait intercepter avant tout hash client.
 * 4. Le hashing Argon2id se fait côté Rust avec des paramètres sécurisés (64 MiB, t=3).
 * FUTURE: Implémenter SRP (Secure Remote Password) si l'architecture évolue vers client-serveur.
 */

export const auth = {
  hasExistingUser: () =>
    invoke<boolean>('has_existing_user'),

  register: (username: string, email: string, password: string) =>
    invoke<AuthResponse>('local_register', {
      credentials: { username, email, password },
    }),

  login: (password: string) =>
    invoke<AuthResponse>('local_login', {
      credentials: { password },
    }),

  logout: () => invoke<void>('local_logout'),

  checkLoginDelay: () => invoke<number>('check_login_delay'),
}

/* ─── Biometric ─── */

export interface BiometricStatus {
  available: boolean
  biometric_type: string
  enrolled: boolean
  enrolled_username?: string
  requires_password: boolean
  password_reason?: string
  unavailable_reason?: string
  compatibility_available?: boolean
  compatibility_enrolled?: boolean
  failed_attempts: number
}

export const biometric = {
  checkStatus: () =>
    invoke<BiometricStatus>('check_biometric').catch((err) => {
      console.error('[vault] check_biometric failed:', err)
      return {
        available: false,
        biometric_type: 'none',
        enrolled: false,
        requires_password: true,
        failed_attempts: 0,
        _error: String(err),
      } as BiometricStatus
    }),

  enable: (password: string, compatibility?: boolean) =>
    invoke<string>('enable_biometric', { password, compatibility }),

  disable: () => invoke<string>('disable_biometric'),

  login: () => invoke<AuthResponse>('biometric_login'),

  /** Android Keystore flow: frontend provides the key retrieved from TEE/StrongBox */
  loginWithKey: (keyB64: string) =>
    invoke<AuthResponse>('biometric_login_with_key', { keyB64 }),

  emergencyLock: () => invoke<string>('biometric_emergency_lock'),
}

/* ─── System ─── */

export const system = {
  checkBackend: () => invoke<string>('check_backend_status'),
  initDatabase: () => invoke<string>('init_local_db'),
  getVersion: () => invoke<string>('get_app_version').catch(() => 'unknown'),
}

/* ─── Passwords ─── */

export const passwords = {
  list: () => invoke<Password[]>('get_passwords').catch((e) => {
    console.error('[vault] get_passwords failed:', e)
    throw e
  }),

  get: (id: number) => invoke<Password | null>('get_password', { id }),

  create: (data: PasswordPayload) => {
    const payload = clean(data)
    // EXP-010: Ne pas logger le payload contenant des mots de passe
    return invoke<number>('create_password', { request: payload }).catch((e) => {
      console.error('[vault] create_password failed:', e)
      throw e
    })
  },

  update: (data: PasswordPayload & { id: number }) => {
    const payload = clean(data)
    // EXP-010: Ne pas logger le payload contenant des mots de passe
    return invoke<boolean>('update_password', { request: payload }).catch((e) => {
      console.error('[vault] update_password failed:', e)
      throw e
    })
  },

  delete: (id: number) => invoke<boolean>('delete_password', { id }),

  decrypt: (encrypted: string) =>
    invoke<string>('decrypt_password', { encrypted }),

  generateTotp: (id: number) =>
    invoke<TotpOutput>('generate_password_totp', { id }),
}

/* ─── Dedicated TOTP 2FA Authenticator (RFC 6238 / RFC 4226) ─── */

export const totpAuthenticator = {
  list: () => invoke<TotpLiveItem[]>('get_totp_authenticators'),
  create: (request: CreateTotpPayload) =>
    invoke<number>('create_totp_authenticator', { request: clean(request) }),
  importBatch: (request: { raw_input?: string; qr_image_base64?: string }) =>
    invoke<ImportTotpMigrationResponse>('import_totp_migration_batch', { request }),
  delete: (id: number, source: 'standalone' | 'password') =>
    invoke<boolean>('delete_totp_authenticator', { id, source }),
}

/* ─── Payment Cards (ISO/IEC 7812-1 Luhn + Lazy Decryption) ─── */

export const paymentCards = {
  list: () => invoke<PaymentCard[]>('get_payment_cards'),
  create: (request: PaymentCardPayload) =>
    invoke<number>('create_payment_card', { request: clean(request) }),
  update: (request: PaymentCardPayload & { id: number }) =>
    invoke<boolean>('update_payment_card', { request: clean(request) }),
  decryptSecret: (id: number) =>
    invoke<{ card_number: string; cvv: string }>('decrypt_payment_card_secret', { id }),
  delete: (id: number) =>
    invoke<boolean>('delete_payment_card', { id }),
}

/* ─── Identity Documents & IETF SD-JWT (EUDI Wallet / eIDAS 2.0) ─── */

export const identityDocuments = {
  list: () => invoke<IdentityDocument[]>('get_identity_documents'),
  create: (request: IdentityDocumentPayload) =>
    invoke<number>('create_identity_document', { request: clean(request) }),
  decryptNumber: (id: number) =>
    invoke<string>('decrypt_identity_document_number', { id }),
  generateSdJwt: (id: number, selectedClaims: string[]) =>
    invoke<IssuedSdJwt>('generate_identity_sd_jwt', { id, selectedClaims }),
  delete: (id: number) =>
    invoke<boolean>('delete_identity_document', { id }),
}

/* ─── Passkeys (W3C WebAuthn Level 3 Software Authenticator) ─── */

export const passkeys = {
  list: () => invoke<PasskeyEntry[]>('get_passkeys_list'),
  create: (request: {
    rp_id: string
    rp_name: string
    user_name: string
    user_display_name: string
    challenge_b64url?: string
    origin?: string
  }) => invoke<CreatedPasskey>('create_passkey_entry', { request }),
  authenticate: (request: { id: number; challenge_b64url: string; origin?: string }) =>
    invoke<PasskeyAssertion>('authenticate_passkey_entry', { request }),
  delete: (id: number) =>
    invoke<boolean>('delete_passkey_entry', { id }),
}

/* ─── Continuous P2P CRDT Sync Status ─── */

export const vaultSync = {
  getStatus: () => invoke<VaultSyncStatus>('get_vault_sync_status'),
}

/* ─── CSV Import/Export ─── */

export interface EntryAction {
  index: number
  action: 'import' | 'skip' | 'overwrite'
  overwrite_id?: number
}

export interface DuplicateMatch {
  id: number
  title: string
  username?: string
  url?: string
}

export interface ParsedCsvEntry {
  index: number
  title: string
  username?: string
  password_preview: string
  url?: string
  notes?: string
  category?: string
  is_duplicate: boolean
  existing_match?: DuplicateMatch
  parse_error?: string
}

export interface ImportCsvResponse {
  success: boolean
  mode: string
  detected_format: string
  total_parsed: number
  duplicate_count: number
  new_count: number
  error_count: number
  entries?: ParsedCsvEntry[]
  imported_count: number
  skipped_count: number
  overwritten_count: number
  errors: string[]
  message: string
}

export interface ExportCsvResponse {
  success: boolean
  csv_content: string
  count: number
  message: string
}

export const csvIO = {
  /**
   * Preview CSV import: parse file, detect format, find duplicates.
   * Requires re-authentication (password or biometric).
   */
  preview: (masterPassword: string | null, csvContent: string, sourceFormat?: string) =>
    invoke<ImportCsvResponse>('import_passwords_csv', {
      request: {
        master_password: masterPassword,
        csv_content: csvContent,
        source_format: sourceFormat ?? 'auto',
        mode: 'preview',
        entry_actions: null,
      },
    }),

  /**
   * Execute CSV import with conflict resolution decisions.
   * Requires re-authentication (password or biometric).
   */
  import: (masterPassword: string | null, csvContent: string, sourceFormat: string, entryActions: EntryAction[]) =>
    invoke<ImportCsvResponse>('import_passwords_csv', {
      request: {
        master_password: masterPassword,
        csv_content: csvContent,
        source_format: sourceFormat,
        mode: 'import',
        entry_actions: entryActions,
      },
    }),

  /**
   * Export all passwords as CSV.
   * Requires re-authentication (password or biometric).
   */
  export: (masterPassword: string | null) =>
    invoke<ExportCsvResponse>('export_passwords_csv', {
      request: { master_password: masterPassword },
    }),
}

/* ─── Secure Files ─── */

export interface NoteAttachment { id: number; filename: string; file_size: number }
export interface NoteSummary {
  id: number; title: string; revision: number; has_attachment: boolean; created_at: string; updated_at: string
}
export interface NoteDetail {
  id: number; title: string; body: string; revision: number; attachment: NoteAttachment | null
}
export interface NotePage { items: NoteSummary[]; total: number }
export interface NotePayload {
  id?: number; revision?: number; title: string; body: string;
  attachment_file_id?: number; attachment_path?: string; attachment_name?: string; attachment_data?: string
}
export const notes = {
  list: (search = '', offset = 0, limit = 50) => invoke<NotePage>('list_notes', { search, offset, limit }),
  get: (id: number) => invoke<NoteDetail>('get_note', { id }),
  save: (request: NotePayload) => invoke<number>('save_note', { request }),
  delete: (id: number, revision: number) => invoke<void>('delete_note', { id, revision }),
  exportAttachment: (id: number, revision: number, outputPath?: string) =>
    invoke<string>('export_note_attachment', { id, revision, outputPath }),
}

export const files = {
  list: () => invoke<SecureFile[]>('get_secure_files').catch((e) => {
    console.error('[vault] get_secure_files failed:', e)
    throw e
  }),

  create: (filename: string, fileData: string) =>
    invoke<number>('create_secure_file', { filename, fileData }),

  createFromPath: (filePath: string) => {
    console.log('[vault] create_secure_file_from_path →', filePath)
    return invoke<number>('create_secure_file_from_path', { filePath }).catch((e) => {
      console.error('[vault] create_secure_file_from_path failed:', e)
      throw e
    })
  },


  decryptToPath: (id: number, outputPath?: string) =>
    invoke<string>('decrypt_file_to_path', { id, outputPath }),

  delete: (id: number) => invoke<boolean>('delete_secure_file', { id }),
}

/* ─── Secure Keys ─── */

export const keys = {
  list: () => invoke<SecureKey[]>('get_secure_keys'),

  create: (data: { key_name: string; key_type: string; algorithm: string }) =>
    invoke<number>('create_secure_key', { request: data }),

  import: (data: {
    key_name: string
    key_type: string
    key_data: string
    algorithm: string
  }) => invoke<number>('import_secure_key', { request: data }),

  decrypt: (id: number) => invoke<string>('decrypt_key', { id }),

  delete: (id: number) => invoke<boolean>('delete_secure_key', { id }),
}

/* ─── Security ─── */

export const security = {
  getEvents: () =>
    invoke<SecurityEvent[]>('get_security_events').catch(() => []),

  analyzeBehavior: () => Promise.resolve(),

  disableReadonlyMode: () => invoke<string>('disable_readonly_mode'),
}

/* ─── Sharing ─── */

export const shares = {
  list: () => invoke<FileShare[]>('get_user_shares'),
  revoke: (shareId: number) => invoke<boolean>('revoke_share', { shareId }),
}

/* ─── Auto-lock ─── */

export const autoLock = {
  notifyActivity: () => invoke('notify_activity'),
  setTimeout: (minutes: number) =>
    invoke('set_auto_lock_timeout', { minutes }),
  check: () => invoke<AutoLockStatus>('check_auto_lock'),
}

/* ─── Enclave & Advanced Security ─── */

export interface EnclaveStatus {
  platform: string
  enclave_type: string
  hardware_backed: boolean
  sync_disabled: boolean
  notes: string
}

export const enclave = {
  getStatus: () => invoke<EnclaveStatus>('get_enclave_status'),
}

export const isolationMode = {
  get: () => invoke<boolean>('get_isolation_mode').catch(() => false),
  toggle: (enabled: boolean) => invoke<string>('toggle_isolation_mode', { enabled }),
}

export const signedLogging = {
  getStatus: () => invoke<boolean>('get_signed_logging_status').catch(() => false),
  toggle: (enabled: boolean) => invoke<string>('toggle_signed_logging', { enabled }),
}

/* ─── Vault Secure Transfer ─── */

export interface TransferOffer {
  transfer_id: string
  wormhole_code: string
  connection_method: string
}

export interface TransferConnection {
  transfer_id: string
  safety_number: string
  peer_name: string
  connection_method: string
  items: TransferItemInfo[]
  total_size: number
}

export interface TransferItemInfo {
  name: string
  item_type: string
  size: number
}

export interface TransferStatus {
  transfer_id: string
  state: TransferState
  connection_method: string
  safety_number?: string
  peer_name?: string
}

export type TransferState =
  | 'WaitingForPeer'
  | 'Handshaking'
  | 'ConfirmingSafetyNumber'
  | { Transferring: { progress_pct: number; bytes_sent: number; total_bytes: number } }
  | 'Completed'
  | { Failed: { reason: string } }

export interface DiscoveredPeer {
  name: string
  addr: string
  port: number
  method: string
  verified: boolean
}

export interface TrustedPeer {
  name: string
  fingerprint: string
  trusted_since: string
  last_seen: string
  transfer_count: number
}

export interface SyncDeviceInfo {
  name: string
  verifying_key: string
  added_at: string
  last_sync: string | null
}

export interface SyncSettings {
  enabled: boolean
  devices: SyncDeviceInfo[]
  device_verifying_key: string
}

export interface SyncPairingOffer {
  pairing_id: string
  wormhole_code: string
}

export interface SyncPairingResult {
  success: boolean
  device_name: string
}



export const transfer = {
  createOffer: (itemType: string, itemIds: number[], crossNetwork = false) =>
    invoke<TransferOffer>('transfer_create_offer', {
      request: { item_type: itemType, item_ids: itemIds, cross_network: crossNetwork },
    }),

  connect: (wormholeCode: string) =>
    invoke<TransferConnection>('transfer_connect', {
      request: { wormhole_code: wormholeCode },
    }),

  /** Connect to a discovered peer (from Peers tab) with a wormhole code */
  connectToPeer: (wormholeCode: string, peerAddr: string, peerPort: number) =>
    invoke<TransferConnection>('transfer_connect', {
      request: { wormhole_code: wormholeCode, peer_addr: peerAddr, peer_port: peerPort },
    }),

  confirmAndExecute: (transferId: string, confirmed: boolean) =>
    invoke<boolean>('transfer_confirm_and_execute', {
      transferId,
      confirmed,
    }),

  scanLocalNetwork: () =>
    invoke<DiscoveredPeer[]>('transfer_scan_local_network'),

  getTrustedPeers: () =>
    invoke<TrustedPeer[]>('transfer_get_trusted_peers'),

  revokeTrust: (fingerprint: string) =>
    invoke<boolean>('transfer_revoke_trust', { fingerprint }),

  addTrust: (name: string, fingerprint: string) =>
    invoke<boolean>('transfer_add_trusted_peer', { name, fingerprint }),

  getStatus: (transferId: string) =>
    invoke<TransferStatus | null>('transfer_get_status', { transferId }),

  cancel: (transferId: string) =>
    invoke<boolean>('transfer_cancel', { transferId }),

  setVisibility: (visible: boolean) =>
    invoke<boolean>('transfer_set_visibility', { visible }),

  getVisibility: () =>
    invoke<boolean>('transfer_get_visibility'),

  getSyncSettings: () =>
    invoke<SyncSettings>('transfer_get_sync_settings'),

  setSyncEnabled: (enabled: boolean) =>
    invoke<boolean>('transfer_set_sync_enabled', { enabled }),

  addSyncDevice: (name: string, verifyingKey: string) =>
    invoke<boolean>('transfer_add_sync_device', { name, verifyingKey }),

  removeSyncDevice: (verifyingKey: string) =>
    invoke<boolean>('transfer_remove_sync_device', { verifyingKey }),

  /** Démarre l'appairage sync — génère un wormhole code. Le handshake PQC et l'échange
   *  de clés ML-DSA-65 se font en background. Polling via getStatus(pairing_id). */
  startSyncPairing: (crossNetwork = false) =>
    invoke<SyncPairingOffer>('transfer_start_sync_pairing', { crossNetwork }),

  /** Rejoint un appairage sync — connexion + handshake PQC + échange de clés ML-DSA-65. */
  joinSyncPairing: (wormholeCode: string) =>
    invoke<SyncPairingResult>('transfer_join_sync_pairing', { wormholeCode }),

}


export type { VaultDescriptor } from './vault-context'
import type { VaultDescriptor } from './vault-context'

export interface VaultOverview {
  vaults: VaultDescriptor[]
  selected_vault_id: string | null
  unlocked_vault_id: string | null
}

export const vaults = {
  list: () => invoke<VaultOverview>('list_vaults'),
  select: (vaultId: string) => invoke<VaultDescriptor>('select_vault', { vaultId }),
  create: (request: { name: string; username: string; email: string; password: string }) =>
    invoke<{ vault: VaultDescriptor; auth: AuthResponse }>('create_vault', { request }),
  rename: (name: string) => invoke<VaultDescriptor>('rename_vault', { name }),
}
