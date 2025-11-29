import { invoke } from '@tauri-apps/api/tauri'

export interface Password {
  id: number
  user_id: number
  title: string
  username?: string
  password: string
  url?: string
  notes?: string
  category?: string
  created_at: string
  updated_at: string
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
  filename?: string // Optional pour enrichir les données côté frontend
}

export interface CreateSecureKeyRequest {
  key_name: string
  key_type: 'ssh' | 'api' | 'gpg' | 'encryption'
  algorithm: string
}

export interface ImportSecureKeyRequest {
  key_name: string
  key_type: 'ssh' | 'api' | 'gpg' | 'encryption'
  key_data: string
  algorithm: string
}

// Client API qui utilise les commandes Tauri IPC
export const tauriAPI = {
  // Authentification
  async hasExistingUser() {
    try {
      const exists = await invoke<boolean>('has_existing_user')
      return exists
    } catch (error) {
      console.error('Erreur vérification utilisateur:', error)
      return false
    }
  },

  async register(username: string, email: string, password: string) {
    try {
      const response = await invoke<{
        success: boolean
        token?: string
        message: string
        user_id?: number
      }>('local_register', {
        credentials: { username, email, password }
      })
      return response
    } catch (error) {
      throw new Error('Erreur d\'inscription: ' + error)
    }
  },

  async login(username: string, password: string) {
    try {
      const response = await invoke<{
        success: boolean
        token?: string
        message: string
        user_id?: number
        email?: string
      }>('local_login', {
        credentials: { username, password }
      })
      return response
    } catch (error) {
      throw new Error('Erreur de connexion: ' + error)
    }
  },

  // Vérifier le statut du backend
  async checkBackendStatus() {
    try {
      const status = await invoke<string>('check_backend_status')
      return { status }
    } catch (error) {
      throw new Error('Backend non disponible')
    }
  },

  // Initialiser la base de données locale
  async initDatabase(appHandle: any) {
    try {
      const result = await invoke<string>('init_local_db', { appHandle })
      return { success: true, message: result }
    } catch (error) {
      return { success: false, message: error as string }
    }
  },

  // Obtenir la version de l'app
  async getVersion() {
    try {
      const version = await invoke<string>('get_app_version')
      return version
    } catch (error) {
      return 'unknown'
    }
  },

  // Passwords
  async createPassword(data: {
    title: string
    username?: string
    password: string
    url?: string
    notes?: string
    category?: string
  }) {
    try {
      const id = await invoke<number>('create_password', { request: data })
      return { success: true, id }
    } catch (error) {
      throw new Error('Erreur création mot de passe: ' + error)
    }
  },

  async getPasswords() {
    try {
      const passwords = await invoke<Password[]>('get_passwords')
      return passwords
    } catch (error) {
      throw new Error('Erreur récupération mots de passe: ' + error)
    }
  },

  async getPassword(id: number) {
    try {
      const password = await invoke<Password | null>('get_password', { id })
      return password
    } catch (error) {
      throw new Error('Erreur récupération mot de passe: ' + error)
    }
  },

  async decryptPassword(encrypted: string) {
    try {
      const decrypted = await invoke<string>('decrypt_password', { encrypted })
      return decrypted
    } catch (error) {
      throw new Error('Erreur déchiffrement: ' + error)
    }
  },

  async updatePassword(data: {
    id: number
    title: string
    username?: string
    password: string
    url?: string
    notes?: string
    category?: string
  }) {
    try {
      const success = await invoke<boolean>('update_password', { request: data })
      return { success }
    } catch (error) {
      throw new Error('Erreur mise à jour mot de passe: ' + error)
    }
  },

  async deletePassword(id: number) {
    try {
      const success = await invoke<boolean>('delete_password', { id })
      return { success }
    } catch (error) {
      throw new Error('Erreur suppression mot de passe: ' + error)
    }
  },

  // Secure Files
  async createSecureFile(filename: string, fileData: string) {
    try {
      const id = await invoke<number>('create_secure_file', {
        filename,
        fileData
      })
      return { success: true, id }
    } catch (error) {
      throw new Error('Erreur création fichier: ' + error)
    }
  },

  async getSecureFiles() {
    try {
      const files = await invoke<SecureFile[]>('get_secure_files')
      return files
    } catch (error) {
      throw new Error('Erreur récupération fichiers: ' + error)
    }
  },

  async decryptFile(id: number) {
    try {
      const decryptedData = await invoke<string>('decrypt_file', { id })
      return decryptedData
    } catch (error) {
      throw new Error('Erreur déchiffrement fichier: ' + error)
    }
  },

  async deleteSecureFile(id: number) {
    try {
      const success = await invoke<boolean>('delete_secure_file', { id })
      return { success }
    } catch (error) {
      throw new Error('Erreur suppression fichier: ' + error)
    }
  },

  // Secure Keys
  async createSecureKey(data: CreateSecureKeyRequest) {
    try {
      const id = await invoke<number>('create_secure_key', { request: data })
      return id
    } catch (error) {
      throw new Error('Erreur création clé: ' + error)
    }
  },

  async importSecureKey(data: ImportSecureKeyRequest) {
    try {
      const id = await invoke<number>('import_secure_key', { request: data })
      return id
    } catch (error) {
      throw new Error('Erreur import clé: ' + error)
    }
  },

  async getSecureKeys() {
    try {
      const keys = await invoke<SecureKey[]>('get_secure_keys')
      return keys
    } catch (error) {
      throw new Error('Erreur récupération clés: ' + error)
    }
  },

  async decryptKey(id: number) {
    try {
      const decryptedKey = await invoke<string>('decrypt_key', { id })
      return decryptedKey
    } catch (error) {
      throw new Error('Erreur déchiffrement clé: ' + error)
    }
  },

  // Alias pour compatibilité
  async decryptSecureKey(id: number) {
    return this.decryptKey(id)
  },

  async deleteSecureKey(id: number) {
    try {
      const success = await invoke<boolean>('delete_secure_key', { id })
      return { success }
    } catch (error) {
      throw new Error('Erreur suppression clé: ' + error)
    }
  },

  // Security Events
  async getSecurityEvents() {
    try {
      const events = await invoke<SecurityEvent[]>('get_security_events')
      return events
    } catch (error) {
      console.warn('Erreur récupération événements sécurité:', error)
      return [] // Retourner un tableau vide si la fonction n'existe pas encore
    }
  },

  async analyzeUserBehavior() {
    try {
      await invoke('analyze_user_behavior')
      return { success: true }
    } catch (error) {
      console.warn('Erreur analyse comportement:', error)
      return { success: false }
    }
  },

  // File Sharing
  async getUserShares() {
    try {
      const shares = await invoke<FileShare[]>('get_user_shares')
      return shares
    } catch (error) {
      throw new Error('Erreur récupération partages: ' + error)
    }
  },

  async revokeShare(shareId: number) {
    try {
      const success = await invoke<boolean>('revoke_share', { shareId })
      return { success }
    } catch (error) {
      throw new Error('Erreur révocation partage: ' + error)
    }
  }
}
