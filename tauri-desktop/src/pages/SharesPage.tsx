import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Share2, 
  Search, 
  Trash2, 
  Clock, 
  Mail, 
  FileText,
  CheckCircle,
  XCircle,
  Calendar,
  Eye
} from 'lucide-react'
import { tauriAPI, FileShare } from '../lib/tauri-api'
import DashboardLayout from '../components/DashboardLayout'

export default function SharesPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const queryClient = useQueryClient()

  // Récupérer tous les partages
  const { data: shares = [], isLoading } = useQuery({
    queryKey: ['userShares'],
    queryFn: async () => {
      return await tauriAPI.getUserShares()
    }
  })

  // Mutation pour révoquer un partage
  const revokeShareMutation = useMutation({
    mutationFn: (shareId: number) => tauriAPI.revokeShare(shareId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['userShares'] })
      alert('✅ Partage révoqué avec succès!')
    },
    onError: (error) => {
      console.error('Erreur révocation partage:', error)
      alert('❌ Erreur lors de la révocation du partage')
    }
  })

  // Révoquer un partage avec confirmation
  const handleRevoke = (share: FileShare) => {
    if (confirm(`Voulez-vous vraiment révoquer le partage avec ${share.recipient_email} ?`)) {
      revokeShareMutation.mutate(share.id)
    }
  }

  // Copier le lien de partage
  const copyShareLink = async (token: string) => {
    try {
      const link = `securevault://share/${token}`
      await navigator.clipboard.writeText(link)
      alert('✅ Lien de partage copié!')
    } catch (error) {
      console.error('Erreur copie:', error)
      alert('❌ Erreur lors de la copie')
    }
  }

  // Filtrer les partages
  const filteredShares = shares.filter(share => 
    share.recipient_email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (share.filename && share.filename.toLowerCase().includes(searchQuery.toLowerCase()))
  )

  // Vérifier si un partage est expiré
  const isExpired = (expiresAt: string): boolean => {
    return new Date(expiresAt) < new Date()
  }

  // Formater la date
  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  // Calculer le temps restant
  const getTimeRemaining = (expiresAt: string): string => {
    const now = new Date()
    const expires = new Date(expiresAt)
    const diff = expires.getTime() - now.getTime()
    
    if (diff < 0) return 'Expiré'
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))
    
    if (days > 0) return `${days} jour${days > 1 ? 's' : ''}`
    if (hours > 0) return `${hours} heure${hours > 1 ? 's' : ''}`
    return 'Moins d\'1 heure'
  }

  return (
    <DashboardLayout>
      <div className="p-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
              <Share2 className="w-8 h-8 text-blue-600" />
              Mes Partages
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Gérez les fichiers que vous avez partagés
            </p>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {filteredShares.length}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              {filteredShares.length === 1 ? 'Partage actif' : 'Partages actifs'}
            </div>
          </div>
        </div>

        {/* Search Bar */}
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Rechercher par email ou nom de fichier..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>

        {/* Shares List */}
        {isLoading ? (
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <p className="mt-2 text-gray-600 dark:text-gray-400">Chargement...</p>
          </div>
        ) : filteredShares.length === 0 ? (
          <div className="text-center py-12 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <Share2 className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              {searchQuery ? 'Aucun partage trouvé' : 'Aucun partage actif'}
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              {searchQuery 
                ? 'Essayez avec d\'autres termes de recherche' 
                : 'Partagez un fichier depuis la page Fichiers pour commencer'}
            </p>
          </div>
        ) : (
          <div className="grid gap-4">
            {filteredShares.map((share) => {
              const expired = isExpired(share.expires_at)
              
              return (
                <div 
                  key={share.id}
                  className={`bg-white dark:bg-gray-800 rounded-lg border ${
                    expired 
                      ? 'border-red-200 dark:border-red-800' 
                      : 'border-gray-200 dark:border-gray-700'
                  } p-6 hover:shadow-md transition-shadow`}
                >
                  <div className="flex items-start justify-between">
                    {/* Left side - Info */}
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <FileText className="w-5 h-5 text-blue-600" />
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                          {share.filename || `Fichier #${share.file_id}`}
                        </h3>
                        {expired ? (
                          <span className="px-2 py-1 bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 text-xs font-medium rounded-full flex items-center gap-1">
                            <XCircle className="w-3 h-3" />
                            Expiré
                          </span>
                        ) : (
                          <span className="px-2 py-1 bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 text-xs font-medium rounded-full flex items-center gap-1">
                            <CheckCircle className="w-3 h-3" />
                            Actif
                          </span>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-4 text-sm">
                        {/* Destinataire */}
                        <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                          <Mail className="w-4 h-4" />
                          <span className="font-medium">Destinataire:</span>
                          <span>{share.recipient_email}</span>
                        </div>

                        {/* Accès */}
                        <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                          <Eye className="w-4 h-4" />
                          <span className="font-medium">Accès:</span>
                          <span>{share.access_count} fois {share.accessed ? '✓' : ''}</span>
                        </div>

                        {/* Date de création */}
                        <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                          <Calendar className="w-4 h-4" />
                          <span className="font-medium">Créé:</span>
                          <span>{formatDate(share.created_at)}</span>
                        </div>

                        {/* Expiration */}
                        <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                          <Clock className="w-4 h-4" />
                          <span className="font-medium">
                            {expired ? 'Expiré' : 'Expire'} dans:
                          </span>
                          <span className={expired ? 'text-red-600 dark:text-red-400 font-semibold' : ''}>
                            {getTimeRemaining(share.expires_at)}
                          </span>
                        </div>
                      </div>

                      {/* Token (masqué) */}
                      <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-500 dark:text-gray-400">Token:</span>
                          <code className="text-xs bg-gray-100 dark:bg-gray-900 px-2 py-1 rounded font-mono text-gray-700 dark:text-gray-300">
                            {share.share_token.substring(0, 20)}...
                          </code>
                          <button
                            onClick={() => copyShareLink(share.share_token)}
                            className="text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                          >
                            Copier le lien
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Right side - Actions */}
                    <div className="ml-4">
                      <button
                        onClick={() => handleRevoke(share)}
                        disabled={revokeShareMutation.isPending}
                        className="p-2 text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-200 hover:bg-red-50 dark:hover:bg-red-900/50 rounded transition-colors disabled:opacity-50"
                        title="Révoquer le partage"
                      >
                        <Trash2 className="w-5 h-5" />
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </DashboardLayout>
  )
}
