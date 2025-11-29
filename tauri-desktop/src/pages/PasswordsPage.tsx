import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Plus, 
  Eye, 
  EyeOff, 
  Copy, 
  Edit2, 
  Trash2, 
  Search,
  RefreshCw,
  Lock,
  X
} from 'lucide-react'
import { tauriAPI, type Password } from '../lib/tauri-api'
import DashboardLayout from '../components/DashboardLayout'

export default function PasswordsPage() {
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editingPassword, setEditingPassword] = useState<Password | null>(null)
  const [revealedPasswords, setRevealedPasswords] = useState<Set<number>>(new Set())
  const [copyFeedback, setCopyFeedback] = useState<number | null>(null)
  
  // Form state
  const [formData, setFormData] = useState({
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    category: '',
  })

  // Query pour récupérer les mots de passe
  const { data: passwords = [], isLoading, refetch } = useQuery({
    queryKey: ['passwords'],
    queryFn: async () => {
      return await tauriAPI.getPasswords()
    },
  })

  // Mutation pour créer un mot de passe
  const createMutation = useMutation({
    mutationFn: (data: typeof formData) => tauriAPI.createPassword(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passwords'] })
      setShowModal(false)
      resetForm()
      showNotification('Mot de passe créé avec succès', 'success')
    },
    onError: (error) => {
      showNotification('Erreur lors de la création: ' + error, 'error')
    },
  })

  // Mutation pour mettre à jour un mot de passe
  const updateMutation = useMutation({
    mutationFn: (data: typeof formData & { id: number }) => 
      tauriAPI.updatePassword(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passwords'] })
      setShowModal(false)
      setEditingPassword(null)
      resetForm()
      showNotification('Mot de passe modifié avec succès', 'success')
    },
    onError: (error) => {
      showNotification('Erreur lors de la modification: ' + error, 'error')
    },
  })

  // Mutation pour supprimer un mot de passe
  const deleteMutation = useMutation({
    mutationFn: (id: number) => tauriAPI.deletePassword(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passwords'] })
      showNotification('Mot de passe supprimé avec succès', 'success')
    },
    onError: (error) => {
      showNotification('Erreur lors de la suppression: ' + error, 'error')
    },
  })

  // Filtrer les mots de passe
  const filteredPasswords = passwords.filter((password) => {
    const search = searchTerm.toLowerCase()
    return (
      password.title.toLowerCase().includes(search) ||
      (password.username?.toLowerCase() || '').includes(search) ||
      (password.url?.toLowerCase() || '').includes(search) ||
      (password.category?.toLowerCase() || '').includes(search)
    )
  })

  // Réinitialiser le formulaire
  const resetForm = () => {
    setFormData({
      title: '',
      username: '',
      password: '',
      url: '',
      notes: '',
      category: '',
    })
    setEditingPassword(null)
  }

  // Ouvrir le modal pour créer
  const handleCreate = () => {
    resetForm()
    setShowModal(true)
  }

  // Ouvrir le modal pour éditer
  const handleEdit = (password: Password) => {
    setEditingPassword(password)
    setFormData({
      title: password.title,
      username: password.username || '',
      password: password.password,
      url: password.url || '',
      notes: password.notes || '',
      category: password.category || '',
    })
    setShowModal(true)
  }

  // Soumettre le formulaire
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!formData.title || !formData.password) {
      showNotification('Titre et mot de passe sont requis', 'error')
      return
    }

    if (editingPassword) {
      updateMutation.mutate({ ...formData, id: editingPassword.id })
    } else {
      createMutation.mutate(formData)
    }
  }

  // Supprimer un mot de passe
  const handleDelete = (id: number, title: string) => {
    if (confirm(`Êtes-vous sûr de vouloir supprimer "${title}" ?`)) {
      deleteMutation.mutate(id)
    }
  }

  // Générer un mot de passe aléatoire
  const generatePassword = () => {
    const length = 16
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
    let password = ''
    
    // Assurer au moins un de chaque type
    password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)]
    password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]
    password += '0123456789'[Math.floor(Math.random() * 10)]
    password += '!@#$%^&*()_+-='[Math.floor(Math.random() * 14)]
    
    // Remplir le reste
    for (let i = password.length; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)]
    }
    
    // Mélanger
    password = password.split('').sort(() => Math.random() - 0.5).join('')
    
    setFormData({ ...formData, password })
  }

  // Révéler/cacher un mot de passe
  const toggleReveal = (id: number) => {
    setRevealedPasswords((prev) => {
      const newSet = new Set(prev)
      if (newSet.has(id)) {
        newSet.delete(id)
      } else {
        newSet.add(id)
      }
      return newSet
    })
  }

  // Copier dans le presse-papier
  const copyToClipboard = async (text: string, id: number) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopyFeedback(id)
      setTimeout(() => setCopyFeedback(null), 2000)
      showNotification('Copié dans le presse-papier', 'success')
    } catch (error) {
      showNotification('Erreur lors de la copie', 'error')
    }
  }

  // Notification simple (à remplacer par une vraie bibliothèque de toast si nécessaire)
  const showNotification = (message: string, type: 'success' | 'error') => {
    console.log(`[${type.toUpperCase()}] ${message}`)
    // Vous pouvez intégrer une bibliothèque comme react-hot-toast ou sonner ici
  }

  if (isLoading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-full">
          <div className="animate-spin">
            <RefreshCw className="w-8 h-8 text-blue-500" />
          </div>
        </div>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout>
      <div className="p-6 max-w-7xl mx-auto">
      {/* En-tête */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Lock className="w-8 h-8" />
          Mots de passe
        </h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Gérez vos mots de passe en toute sécurité
        </p>
      </div>

      {/* Barre d'actions */}
      <div className="flex gap-4 mb-6">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="text"
            placeholder="Rechercher un mot de passe..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
          />
        </div>
        <button
          onClick={handleCreate}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors"
        >
          <Plus className="w-5 h-5" />
          Nouveau
        </button>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg flex items-center gap-2 transition-colors"
        >
          <RefreshCw className="w-5 h-5" />
        </button>
      </div>

      {/* Liste des mots de passe */}
      {filteredPasswords.length === 0 ? (
        <div className="text-center py-12">
          <Lock className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            {searchTerm ? 'Aucun mot de passe trouvé' : 'Aucun mot de passe enregistré'}
          </p>
          {!searchTerm && (
            <button
              onClick={handleCreate}
              className="mt-4 px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg inline-flex items-center gap-2 transition-colors"
            >
              <Plus className="w-5 h-5" />
              Créer votre premier mot de passe
            </button>
          )}
        </div>
      ) : (
        <div className="grid gap-4">
          {filteredPasswords.map((password) => (
            <div
              key={password.id}
              className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-md transition-shadow"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {password.title}
                  </h3>
                  {password.username && (
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      <span className="font-medium">Utilisateur:</span> {password.username}
                    </p>
                  )}
                  {password.url && (
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      <span className="font-medium">URL:</span>{' '}
                      <a
                        href={password.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-500 hover:underline"
                      >
                        {password.url}
                      </a>
                    </p>
                  )}
                  {password.category && (
                    <span className="inline-block mt-2 px-2 py-1 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">
                      {password.category}
                    </span>
                  )}
                  
                  {/* Mot de passe */}
                  <div className="mt-3 flex items-center gap-2">
                    <input
                      type={revealedPasswords.has(password.id) ? 'text' : 'password'}
                      value={password.password}
                      readOnly
                      className="flex-1 px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded text-sm font-mono"
                    />
                    <button
                      onClick={() => toggleReveal(password.id)}
                      className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
                      title={revealedPasswords.has(password.id) ? 'Masquer' : 'Révéler'}
                    >
                      {revealedPasswords.has(password.id) ? (
                        <EyeOff className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                      ) : (
                        <Eye className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                      )}
                    </button>
                    <button
                      onClick={() => copyToClipboard(password.password, password.id)}
                      className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
                      title="Copier"
                    >
                      <Copy 
                        className={`w-5 h-5 ${
                          copyFeedback === password.id 
                            ? 'text-green-500' 
                            : 'text-gray-600 dark:text-gray-400'
                        }`} 
                      />
                    </button>
                  </div>

                  {password.notes && (
                    <p className="mt-3 text-sm text-gray-600 dark:text-gray-400 italic">
                      {password.notes}
                    </p>
                  )}
                  
                  <p className="mt-2 text-xs text-gray-500 dark:text-gray-500">
                    Créé le {new Date(password.created_at).toLocaleDateString('fr-FR')}
                  </p>
                </div>

                {/* Actions */}
                <div className="flex gap-2 ml-4">
                  <button
                    onClick={() => handleEdit(password)}
                    className="p-2 hover:bg-blue-50 dark:hover:bg-blue-900 text-blue-600 dark:text-blue-400 rounded transition-colors"
                    title="Modifier"
                  >
                    <Edit2 className="w-5 h-5" />
                  </button>
                  <button
                    onClick={() => handleDelete(password.id, password.title)}
                    className="p-2 hover:bg-red-50 dark:hover:bg-red-900 text-red-600 dark:text-red-400 rounded transition-colors"
                    title="Supprimer"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Modal de formulaire */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                {editingPassword ? 'Modifier le mot de passe' : 'Nouveau mot de passe'}
              </h2>
              <button
                onClick={() => {
                  setShowModal(false)
                  resetForm()
                }}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
              >
                <X className="w-6 h-6 text-gray-600 dark:text-gray-400" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              {/* Titre */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Titre <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="Ex: Gmail, Facebook, etc."
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                />
              </div>

              {/* Nom d'utilisateur */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Nom d'utilisateur / Email
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  placeholder="user@example.com"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                />
              </div>

              {/* Mot de passe */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Mot de passe <span className="text-red-500">*</span>
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    required
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    placeholder="Mot de passe"
                    className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-mono"
                  />
                  <button
                    type="button"
                    onClick={generatePassword}
                    className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg flex items-center gap-2 transition-colors"
                    title="Générer un mot de passe"
                  >
                    <RefreshCw className="w-5 h-5" />
                    Générer
                  </button>
                </div>
              </div>

              {/* URL */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  URL
                </label>
                <input
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  placeholder="https://example.com"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                />
              </div>

              {/* Catégorie */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Catégorie
                </label>
                <input
                  type="text"
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  placeholder="Ex: Social, Email, Travail, etc."
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                />
              </div>

              {/* Notes */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Notes
                </label>
                <textarea
                  value={formData.notes}
                  onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                  placeholder="Notes additionnelles..."
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-900 text-gray-900 dark:text-white resize-none"
                />
              </div>

              {/* Boutons */}
              <div className="flex gap-3 pt-4">
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-lg font-medium transition-colors"
                >
                  {createMutation.isPending || updateMutation.isPending
                    ? 'Enregistrement...'
                    : editingPassword
                    ? 'Modifier'
                    : 'Créer'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowModal(false)
                    resetForm()
                  }}
                  className="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-medium transition-colors"
                >
                  Annuler
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
    </DashboardLayout>
  )
}
