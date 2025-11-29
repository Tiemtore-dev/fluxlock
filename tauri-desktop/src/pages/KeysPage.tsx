import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { 
  Key, 
  Plus, 
  Search, 
  Eye, 
  EyeOff, 
  Copy, 
  Trash2, 
  Shield, 
  Terminal,
  Lock,
  Fingerprint,
  X,
  Upload
} from 'lucide-react'
import { tauriAPI } from '../lib/tauri-api'
import type { SecureKey, CreateSecureKeyRequest, ImportSecureKeyRequest } from '../lib/tauri-api'
import DashboardLayout from '../components/DashboardLayout'

export default function KeysPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const [isImportModalOpen, setIsImportModalOpen] = useState(false)
  const [isViewGeneratedKeyOpen, setIsViewGeneratedKeyOpen] = useState(false)
  const [isViewKeyDetailOpen, setIsViewKeyDetailOpen] = useState(false)
  const [generatedKeyData, setGeneratedKeyData] = useState<{ keyName: string, keyData: string } | null>(null)
  const [viewingKeyDetail, setViewingKeyDetail] = useState<{ key: SecureKey, decryptedData: string } | null>(null)
  const [revealedKeys, setRevealedKeys] = useState<Set<number>>(new Set())
  const [decryptedKeys, setDecryptedKeys] = useState<Map<number, string>>(new Map())
  const queryClient = useQueryClient()

  // Form state
  const [formData, setFormData] = useState<CreateSecureKeyRequest>({
    key_name: '',
    key_type: 'api',
    algorithm: 'AES-256-GCM'
  })

  // Import form state
  const [importData, setImportData] = useState<ImportSecureKeyRequest>({
    key_name: '',
    key_type: 'api',
    key_data: '',
    algorithm: 'AES-256-GCM'
  })

  // Fetch secure keys
  const { data: keys = [], isLoading } = useQuery({
    queryKey: ['secureKeys'],
    queryFn: async () => {
      console.log('🔍 Fetching secure keys...')
      const fetchedKeys = await tauriAPI.getSecureKeys()
      console.log('✅ Fetched keys:', fetchedKeys.length, 'keys')
      console.log('📋 Keys:', fetchedKeys)
      return fetchedKeys
    }
  })

  // Create key mutation
  const createKeyMutation = useMutation({
    mutationFn: async (request: CreateSecureKeyRequest) => {
      console.log('🔧 Creating key...', request)
      const id = await tauriAPI.createSecureKey(request)
      console.log('✅ Key created with ID:', id)
      // Récupérer immédiatement la clé déchiffrée pour l'afficher
      const decryptedKey = await tauriAPI.decryptSecureKey(id)
      console.log('🔓 Key decrypted, length:', decryptedKey.length)
      return { id, decryptedKey, keyName: request.key_name }
    },
    onSuccess: async (data) => {
      console.log('🎉 Success! Data received:', { keyName: data.keyName, keyLength: data.decryptedKey.length })
      
      // Rafraîchir la liste des clés
      console.log('🔄 Invalidating queries...')
      await queryClient.invalidateQueries({ queryKey: ['secureKeys'] })
      console.log('🔄 Refetching queries...')
      await queryClient.refetchQueries({ queryKey: ['secureKeys'] })
      console.log('✅ Queries refreshed')
      
      // Fermer le modal de création
      setIsCreateModalOpen(false)
      
      // Afficher la clé générée
      console.log('📋 Setting generated key data...')
      setGeneratedKeyData({ keyName: data.keyName, keyData: data.decryptedKey })
      console.log('🔓 Opening view modal...')
      setIsViewGeneratedKeyOpen(true)
      console.log('✅ Modal state updated. isViewGeneratedKeyOpen should be true')
      
      resetForm()
    },
    onError: (error) => {
      console.error('❌ Failed to create key:', error)
      alert('Failed to create key: ' + error)
    }
  })

  // Import key mutation
  const importKeyMutation = useMutation({
    mutationFn: (request: ImportSecureKeyRequest) => tauriAPI.importSecureKey(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secureKeys'] })
      setIsImportModalOpen(false)
      resetImportForm()
    },
    onError: (error) => {
      console.error('Failed to import key:', error)
      alert('Failed to import key. Please try again.')
    }
  })

  // Delete key mutation
  const deleteKeyMutation = useMutation({
    mutationFn: (id: number) => tauriAPI.deleteSecureKey(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secureKeys'] })
    },
    onError: (error) => {
      console.error('Failed to delete key:', error)
      alert('Failed to delete key. Please try again.')
    }
  })

  // Decrypt key mutation
  const decryptKeyMutation = useMutation({
    mutationFn: (id: number) => tauriAPI.decryptSecureKey(id),
    onSuccess: (decryptedData, id) => {
      setDecryptedKeys(prev => new Map(prev).set(id, decryptedData))
      setRevealedKeys(prev => new Set(prev).add(id))
    },
    onError: (error) => {
      console.error('Failed to decrypt key:', error)
      alert('Failed to decrypt key. Please try again.')
    }
  })

  const handleCreateKey = (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.key_name.trim()) {
      alert('Please enter a key name')
      return
    }
    createKeyMutation.mutate(formData)
  }

  const handleImportKey = (e: React.FormEvent) => {
    e.preventDefault()
    if (!importData.key_name.trim() || !importData.key_data.trim()) {
      alert('Please enter key name and key data')
      return
    }
    importKeyMutation.mutate(importData)
  }

  const resetForm = () => {
    setFormData({
      key_name: '',
      key_type: 'api',
      algorithm: 'AES-256-GCM'
    })
  }

  const resetImportForm = () => {
    setImportData({
      key_name: '',
      key_type: 'api',
      key_data: '',
      algorithm: 'AES-256-GCM'
    })
  }

  const handleDeleteKey = (id: number, keyName: string) => {
    if (confirm(`Are you sure you want to delete the key "${keyName}"?`)) {
      deleteKeyMutation.mutate(id)
      // Clean up local state
      setRevealedKeys(prev => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
      setDecryptedKeys(prev => {
        const next = new Map(prev)
        next.delete(id)
        return next
      })
    }
  }

  const toggleRevealKey = async (key: SecureKey) => {
    if (revealedKeys.has(key.id)) {
      // Hide the key
      setRevealedKeys(prev => {
        const next = new Set(prev)
        next.delete(key.id)
        return next
      })
    } else {
      // Decrypt and reveal the key
      let decryptedData = decryptedKeys.get(key.id)
      if (!decryptedData) {
        decryptedData = await decryptKeyMutation.mutateAsync(key.id)
      }
      setRevealedKeys(prev => new Set(prev).add(key.id))
      
      // Ouvrir le modal détaillé pour afficher toute la clé
      if (decryptedData) {
        setViewingKeyDetail({ key, decryptedData })
        setIsViewKeyDetailOpen(true)
      }
    }
  }

  const copyToClipboard = async (text: string, keyName: string) => {
    try {
      await navigator.clipboard.writeText(text)
      alert(`✅ Clé "${keyName}" copiée dans le presse-papiers!`)
    } catch (error) {
      console.error('Failed to copy:', error)
      alert('❌ Erreur lors de la copie: ' + error)
    }
  }

  const getKeyIcon = (keyType: string) => {
    switch (keyType.toLowerCase()) {
      case 'ssh':
        return <Terminal className="w-5 h-5" />
      case 'api':
        return <Key className="w-5 h-5" />
      case 'gpg':
        return <Fingerprint className="w-5 h-5" />
      case 'encryption':
        return <Lock className="w-5 h-5" />
      default:
        return <Shield className="w-5 h-5" />
    }
  }

  const getKeyTypeColor = (keyType: string) => {
    switch (keyType.toLowerCase()) {
      case 'ssh':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
      case 'api':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200'
      case 'gpg':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
      case 'encryption':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
    }
  }

  // Filter keys based on search query
  const filteredKeys = keys.filter(key => 
    key.key_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    key.key_type.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  return (
    <DashboardLayout>
      <div className="p-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Shield className="w-8 h-8 text-indigo-600" />
            Secure Keys
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Manage your SSH, API, GPG, and encryption keys securely
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
          >
            <Plus className="w-5 h-5" />
            New Key
          </button>
          <button
            onClick={() => setIsImportModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
          >
            <Upload className="w-5 h-5" />
            Import Key
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="text"
            placeholder="Search keys by name or type..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
      </div>

      {/* Keys Grid */}
      {isLoading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
          <p className="mt-2 text-gray-600 dark:text-gray-400">Loading keys...</p>
        </div>
      ) : filteredKeys.length === 0 ? (
        <div className="text-center py-12 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            {searchQuery ? 'No keys found' : 'No keys yet'}
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            {searchQuery 
              ? 'Try adjusting your search terms' 
              : 'Create your first secure key to get started'}
          </p>
          {!searchQuery && (
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
            >
              <Plus className="w-5 h-5" />
              Create Key
            </button>
          )}
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Key Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Algorithm
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Key Data
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredKeys.map((key) => {
                  const isRevealed = revealedKeys.has(key.id)
                  const decryptedData = decryptedKeys.get(key.id) || ''
                  
                  return (
                    <tr key={key.id} className="hover:bg-gray-50 dark:hover:bg-gray-900/50 transition-colors">
                      {/* Type Icon */}
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <div className={`p-2 rounded-lg ${getKeyTypeColor(key.key_type)}`}>
                            {getKeyIcon(key.key_type)}
                          </div>
                          <span className="text-xs font-medium text-gray-700 dark:text-gray-300">
                            {key.key_type.toUpperCase()}
                          </span>
                        </div>
                      </td>

                      {/* Key Name */}
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900 dark:text-white">
                          {key.key_name}
                        </div>
                      </td>

                      {/* Algorithm */}
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                          {key.algorithm}
                        </span>
                      </td>

                      {/* Created Date */}
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {formatDate(key.created_at)}
                      </td>

                      {/* Key Data - toujours masqué */}
                      <td className="px-6 py-4">
                        <div className="max-w-xs">
                          <div className="bg-gray-50 dark:bg-gray-900 rounded px-3 py-2 font-mono text-xs break-all">
                            <span className="text-gray-400">••••••••••••••••••••</span>
                          </div>
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => toggleRevealKey(key)}
                            disabled={decryptKeyMutation.isPending}
                            className="p-2 text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 rounded transition-colors disabled:opacity-50"
                            title={isRevealed ? 'Hide key' : 'Reveal key'}
                          >
                            {isRevealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                          <button
                            onClick={async () => {
                              // Déchiffrer si nécessaire et copier
                              let dataToCopy = decryptedKeys.get(key.id)
                              if (!dataToCopy) {
                                dataToCopy = await decryptKeyMutation.mutateAsync(key.id)
                              }
                              if (dataToCopy) {
                                copyToClipboard(dataToCopy, key.key_name)
                              }
                            }}
                            disabled={decryptKeyMutation.isPending}
                            className="p-2 text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-200 hover:bg-indigo-50 dark:hover:bg-indigo-900/50 rounded transition-colors disabled:opacity-50"
                            title="Copy key"
                          >
                            <Copy className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteKey(key.id, key.key_name)}
                            className="p-2 text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-200 hover:bg-red-50 dark:hover:bg-red-900/50 rounded transition-colors"
                            title="Delete key"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create Key Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-md w-full p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                Create New Key
              </h2>
              <button
                onClick={() => {
                  setIsCreateModalOpen(false)
                  resetForm()
                }}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <form onSubmit={handleCreateKey} className="space-y-4">
              {/* Key Name */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Name
                </label>
                <input
                  type="text"
                  value={formData.key_name}
                  onChange={(e) => setFormData({ ...formData, key_name: e.target.value })}
                  placeholder="e.g., GitHub SSH Key"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  required
                />
              </div>

              {/* Key Type */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Type
                </label>
                <select
                  value={formData.key_type}
                  onChange={(e) => setFormData({ ...formData, key_type: e.target.value as CreateSecureKeyRequest['key_type'] })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                >
                  <option value="api">API Key</option>
                  <option value="ssh">SSH Key</option>
                  <option value="gpg">GPG Key</option>
                  <option value="encryption">Encryption Key</option>
                </select>
              </div>

              {/* Algorithm */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Algorithm
                </label>
                <select
                  value={formData.algorithm}
                  onChange={(e) => setFormData({ ...formData, algorithm: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  required
                >
                  <option value="AES-256-GCM">AES-256-GCM (Recommended)</option>
                  <option value="AES-256-CBC">AES-256-CBC</option>
                  <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
                </select>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  All keys are encrypted with AES-256-GCM internally
                </p>
              </div>

              {/* Info Message */}
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                <p className="text-sm text-blue-800 dark:text-blue-200">
                  The key will be generated automatically using secure cryptographic algorithms.
                </p>
              </div>

              {/* Buttons */}
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setIsCreateModalOpen(false)
                    resetForm()
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createKeyMutation.isPending}
                  className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {createKeyMutation.isPending ? 'Creating...' : 'Create Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import Key Modal */}
      {isImportModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-md w-full p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                Import Existing Key
              </h2>
              <button
                onClick={() => {
                  setIsImportModalOpen(false)
                  resetImportForm()
                }}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <form onSubmit={handleImportKey} className="space-y-4">
              {/* Key Name */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Name
                </label>
                <input
                  type="text"
                  value={importData.key_name}
                  onChange={(e) => setImportData({ ...importData, key_name: e.target.value })}
                  placeholder="e.g., My Personal SSH Key"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-green-500 focus:border-transparent"
                  required
                />
              </div>

              {/* Key Type */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Type
                </label>
                <select
                  value={importData.key_type}
                  onChange={(e) => setImportData({ ...importData, key_type: e.target.value as ImportSecureKeyRequest['key_type'] })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-green-500 focus:border-transparent"
                >
                  <option value="api">API Key</option>
                  <option value="ssh">SSH Key</option>
                  <option value="gpg">GPG Key</option>
                  <option value="encryption">Encryption Key</option>
                </select>
              </div>

              {/* Algorithm */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Algorithm
                </label>
                <select
                  value={importData.algorithm}
                  onChange={(e) => setImportData({ ...importData, algorithm: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-green-500 focus:border-transparent"
                  required
                >
                  <optgroup label="Symmetric Encryption">
                    <option value="AES-256-GCM">AES-256-GCM</option>
                    <option value="AES-256-CBC">AES-256-CBC</option>
                    <option value="AES-192-GCM">AES-192-GCM</option>
                    <option value="AES-128-GCM">AES-128-GCM</option>
                    <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
                  </optgroup>
                  <optgroup label="Asymmetric Encryption">
                    <option value="RSA-4096">RSA-4096</option>
                    <option value="RSA-2048">RSA-2048</option>
                    <option value="Ed25519">Ed25519</option>
                    <option value="ECDSA-P256">ECDSA-P256</option>
                    <option value="ECDSA-P384">ECDSA-P384</option>
                  </optgroup>
                  <optgroup label="SSH Key Algorithms">
                    <option value="ssh-rsa">ssh-rsa</option>
                    <option value="ssh-ed25519">ssh-ed25519</option>
                    <option value="ecdsa-sha2-nistp256">ecdsa-sha2-nistp256</option>
                    <option value="ecdsa-sha2-nistp384">ecdsa-sha2-nistp384</option>
                  </optgroup>
                  <optgroup label="Other">
                    <option value="Custom">Custom / Other</option>
                  </optgroup>
                </select>
              </div>

              {/* Key Data */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Data
                </label>
                <textarea
                  value={importData.key_data}
                  onChange={(e) => setImportData({ ...importData, key_data: e.target.value })}
                  placeholder="Paste your key here..."
                  rows={6}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-green-500 focus:border-transparent font-mono text-sm"
                  required
                />
              </div>

              {/* Info Message */}
              <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                <p className="text-sm text-green-800 dark:text-green-200">
                  Your key will be encrypted and stored securely.
                </p>
              </div>

              {/* Buttons */}
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setIsImportModalOpen(false)
                    resetImportForm()
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={importKeyMutation.isPending}
                  className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {importKeyMutation.isPending ? 'Importing...' : 'Import Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View Generated Key Modal */}
      {isViewGeneratedKeyOpen && generatedKeyData && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-2xl w-full p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <Shield className="w-6 h-6 text-green-600" />
                Key Generated Successfully
              </h2>
              <button
                onClick={() => {
                  setIsViewGeneratedKeyOpen(false)
                  setGeneratedKeyData(null)
                }}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Key Name */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Name
                </label>
                <div className="px-3 py-2 bg-gray-50 dark:bg-gray-900 rounded-lg text-gray-900 dark:text-white font-medium">
                  {generatedKeyData.keyName}
                </div>
              </div>

              {/* Détecter si c'est une clé SSH pour séparer publique/privée */}
              {generatedKeyData.keyData.includes('|||') ? (
                <>
                  {/* Clé Privée SSH */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Private Key
                    </label>
                    <div className="relative">
                      <textarea
                        value={generatedKeyData.keyData.split('|||')[0]}
                        readOnly
                        rows={6}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                      />
                      <button
                        onClick={() => copyToClipboard(generatedKeyData.keyData.split('|||')[0], generatedKeyData.keyName + ' (Private)')}
                        className="absolute top-2 right-2 p-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors flex items-center gap-2"
                      >
                        <Copy className="w-4 h-4" />
                        Copy
                      </button>
                    </div>
                  </div>

                  {/* Clé Publique SSH */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Public Key
                    </label>
                    <div className="relative">
                      <textarea
                        value={generatedKeyData.keyData.split('|||')[1]}
                        readOnly
                        rows={3}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                      />
                      <button
                        onClick={() => copyToClipboard(generatedKeyData.keyData.split('|||')[1], generatedKeyData.keyName + ' (Public)')}
                        className="absolute top-2 right-2 p-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2"
                      >
                        <Copy className="w-4 h-4" />
                        Copy
                      </button>
                    </div>
                  </div>
                </>
              ) : (
                /* Generated Key (autres types) */
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Generated Key
                  </label>
                  <div className="relative">
                    <textarea
                      value={generatedKeyData.keyData}
                      readOnly
                      rows={8}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                    />
                    <button
                      onClick={() => copyToClipboard(generatedKeyData.keyData, generatedKeyData.keyName)}
                      className="absolute top-2 right-2 p-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors flex items-center gap-2"
                    >
                      <Copy className="w-4 h-4" />
                      Copy
                    </button>
                  </div>
                </div>
              )}

              {/* Warning Message */}
              <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                <div className="flex gap-3">
                  <Shield className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200 mb-1">
                      Important Security Notice
                    </h3>
                    <p className="text-sm text-yellow-700 dark:text-yellow-300">
                      Please save this key now. For security reasons, this is the only time the key will be displayed in plaintext.
                      You can view it later from the keys list, but you'll need to decrypt it first.
                    </p>
                  </div>
                </div>
              </div>

              {/* Close Button */}
              <div className="flex justify-end pt-2">
                <button
                  onClick={() => {
                    setIsViewGeneratedKeyOpen(false)
                    setGeneratedKeyData(null)
                  }}
                  className="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                >
                  I've Saved My Key
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* View Key Detail Modal (pour toutes les clés depuis le tableau) */}
      {isViewKeyDetailOpen && viewingKeyDetail && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-2xl w-full p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                {viewingKeyDetail.key.key_type === 'ssh' ? (
                  <><Terminal className="w-6 h-6 text-indigo-600" /> SSH Key Details</>
                ) : (
                  <><Key className="w-6 h-6 text-indigo-600" /> Key Details</>
                )}
              </h2>
              <button
                onClick={() => {
                  setIsViewKeyDetailOpen(false)
                  setViewingKeyDetail(null)
                }}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Key Name */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Name
                </label>
                <div className="px-3 py-2 bg-gray-50 dark:bg-gray-900 rounded-lg text-gray-900 dark:text-white font-medium">
                  {viewingKeyDetail.key.key_name}
                </div>
              </div>

              {/* Type et Algorithm */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Type
                  </label>
                  <div className="px-3 py-2 bg-gray-50 dark:bg-gray-900 rounded-lg text-gray-900 dark:text-white">
                    {viewingKeyDetail.key.key_type.toUpperCase()}
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Algorithm
                  </label>
                  <div className="px-3 py-2 bg-gray-50 dark:bg-gray-900 rounded-lg text-gray-900 dark:text-white">
                    {viewingKeyDetail.key.algorithm}
                  </div>
                </div>
              </div>

              {/* Si c'est une clé SSH, séparer privée et publique */}
              {viewingKeyDetail.decryptedData.includes('|||') ? (
                <>
                  {/* Clé Privée SSH */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Private Key
                    </label>
                    <div className="relative">
                      <textarea
                        value={viewingKeyDetail.decryptedData.split('|||')[0]}
                        readOnly
                        rows={6}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                      />
                      <button
                        onClick={() => copyToClipboard(viewingKeyDetail.decryptedData.split('|||')[0], viewingKeyDetail.key.key_name + ' (Private)')}
                        className="absolute top-2 right-2 p-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors flex items-center gap-2"
                      >
                        <Copy className="w-4 h-4" />
                        Copy
                      </button>
                    </div>
                  </div>

                  {/* Clé Publique SSH */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Public Key
                    </label>
                    <div className="relative">
                      <textarea
                        value={viewingKeyDetail.decryptedData.split('|||')[1]}
                        readOnly
                        rows={3}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                      />
                      <button
                        onClick={() => copyToClipboard(viewingKeyDetail.decryptedData.split('|||')[1], viewingKeyDetail.key.key_name + ' (Public)')}
                        className="absolute top-2 right-2 p-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2"
                      >
                        <Copy className="w-4 h-4" />
                        Copy
                      </button>
                    </div>
                  </div>
                </>
              ) : (
                /* Clé standard (API, GPG, Encryption) */
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Key Data
                  </label>
                  <div className="relative">
                    <textarea
                      value={viewingKeyDetail.decryptedData}
                      readOnly
                      rows={8}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                    />
                    <button
                      onClick={() => copyToClipboard(viewingKeyDetail.decryptedData, viewingKeyDetail.key.key_name)}
                      className="absolute top-2 right-2 p-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors flex items-center gap-2"
                    >
                      <Copy className="w-4 h-4" />
                      Copy
                    </button>
                  </div>
                </div>
              )}

              {/* Close Button */}
              <div className="flex justify-end pt-2">
                <button
                  onClick={() => {
                    setIsViewKeyDetailOpen(false)
                    setViewingKeyDetail(null)
                  }}
                  className="px-6 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      </div>
    </DashboardLayout>
  )
}
