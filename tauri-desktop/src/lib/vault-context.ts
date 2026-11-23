import { invoke as tauriInvoke, type InvokeArgs } from '@tauri-apps/api/core'

export interface VaultDescriptor {
  id: string
  name: string
  schema_version: number
  created_at: string
}

let selectedVault: VaultDescriptor | null = null
let sessionToken: string | null = null

export function setVaultContext(vault: VaultDescriptor | null, token: string | null = null) {
  if (selectedVault?.id !== vault?.id || token !== null) sessionToken = token
  selectedVault = vault
}

export function currentVault() { return selectedVault }
export function setVaultToken(token: string | null) { sessionToken = token }
export function vaultSettingKey(name: string) { return `vault:${selectedVault?.id || 'none'}:${name}` }

/** Bind multi-step operations (file pickers, file reads, hardware prompts) to their origin. */
export function captureVaultContext() {
  const id = selectedVault?.id
  const token = sessionToken
  return () => {
    if (!id || selectedVault?.id !== id || sessionToken !== token) {
      throw new Error('Le coffre ou la session a changé. Relancez cette action.')
    }
  }
}

const globalCommands = new Set([
  'init_local_db', 'list_vaults', 'select_vault', 'create_vault',
  'get_app_version', 'check_backend_status', 'get_enclave_status',
])

/** Capture the vault/session before invoking, and discard replies to an old view. */
export async function invoke<T>(command: string, args?: InvokeArgs): Promise<T> {
  if (globalCommands.has(command)) return tauriInvoke<T>(command, args)
  const vault = selectedVault
  const token = sessionToken
  if (!vault) throw new Error('Sélectionnez un coffre pour continuer.')
  const result = await tauriInvoke<T>(command, {
    ...args,
    context: { vault_id: vault.id, token },
  })
  if (selectedVault?.id !== vault.id || sessionToken !== token) {
    throw new Error('Le coffre ou la session a changé. Relancez cette action.')
  }
  return result
}
