import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { open } from '@tauri-apps/api/dialog'
import { readBinaryFile } from '@tauri-apps/api/fs'
import { 
  Upload, 
  Download, 
  Trash2, 
  Search, 
  X, 
  FileText, 
  Image, 
  Film, 
  Music, 
  Archive, 
  File as FileIcon,
  AlertCircle,
  Share2
} from 'lucide-react'
import { tauriAPI, SecureFile } from '../lib/tauri-api'
import DashboardLayout from '../components/DashboardLayout'

const FilesPage = () => {
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [showShareModal, setShowShareModal] = useState(false)
  const [fileToShare, setFileToShare] = useState<SecureFile | null>(null)
  const [shareEmail, setShareEmail] = useState('')
  const [shareExpiration, setShareExpiration] = useState('7')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [uploadError, setUploadError] = useState('')
  const [isUploading, setIsUploading] = useState(false)

  // Récupérer la liste des fichiers
  const { data: files = [], isLoading } = useQuery({
    queryKey: ['secureFiles'],
    queryFn: tauriAPI.getSecureFiles
  })

  // Mutation pour créer un fichier
  const createFileMutation = useMutation({
    mutationFn: ({ filename, fileData }: { filename: string; fileData: string }) =>
      tauriAPI.createSecureFile(filename, fileData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secureFiles'] })
      setShowUploadModal(false)
      setSelectedFile(null)
      setUploadError('')
    },
    onError: (error: Error) => {
      setUploadError(error.message || 'Erreur lors du téléchargement du fichier')
    }
  })

  // Mutation pour supprimer un fichier
  const deleteFileMutation = useMutation({
    mutationFn: (id: number) => tauriAPI.deleteSecureFile(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secureFiles'] })
    }
  })

  // Convertir un fichier en Base64
  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.readAsDataURL(file)
      reader.onload = () => {
        const result = reader.result as string
        // Retirer le préfixe "data:mime/type;base64,"
        const base64 = result.split(',')[1]
        resolve(base64)
      }
      reader.onerror = (error) => reject(error)
    })
  }

  // Gérer la sélection d'un fichier avec Tauri Dialog API
  const handleFileSelect = async () => {
    try {
      const selected = await open({
        multiple: false,
        // Pas de filtre - accepte tous les fichiers
        // L'utilisateur peut naviguer librement dans ses fichiers
      })

      if (!selected || Array.isArray(selected)) return

      // Lire le fichier
      const fileData = await readBinaryFile(selected)
      const fileName = selected.split('/').pop() || selected.split('\\').pop() || 'fichier'
      
      // Créer un objet File-like (convertir Uint8Array en ArrayBuffer propre)
      const arrayBuffer = new ArrayBuffer(fileData.length)
      const uint8Array = new Uint8Array(arrayBuffer)
      uint8Array.set(fileData)
      const file = new File([arrayBuffer], fileName, { type: 'application/octet-stream' })
      setSelectedFile(file)
      setUploadError('')
    } catch (error) {
      console.error('Erreur sélection fichier:', error)
      setUploadError('Erreur lors de la sélection du fichier')
    }
  }

  // Upload du fichier
  const handleUpload = async () => {
    if (!selectedFile) return

    setIsUploading(true)
    setUploadError('')

    try {
      const base64Data = await fileToBase64(selectedFile)
      await createFileMutation.mutateAsync({
        filename: selectedFile.name,
        fileData: base64Data
      })
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : 'Erreur lors du téléchargement')
    } finally {
      setIsUploading(false)
    }
  }

  // Télécharger un fichier (déchiffrer et télécharger)
  const handleDownload = async (file: SecureFile) => {
    try {
      const decryptedData = await tauriAPI.decryptFile(file.id)
      
      // Convertir Base64 en Uint8Array
      const byteCharacters = atob(decryptedData)
      const byteNumbers = new Array(byteCharacters.length)
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i)
      }
      const byteArray = new Uint8Array(byteNumbers)

      // Utiliser Tauri save dialog au lieu de blob URL
      const { save } = await import('@tauri-apps/api/dialog')
      const { writeBinaryFile } = await import('@tauri-apps/api/fs')
      
      const savePath = await save({
        defaultPath: file.filename,
        filters: [{
          name: 'All Files',
          extensions: ['*']
        }]
      })

      if (savePath) {
        await writeBinaryFile(savePath, byteArray)
        alert(`✅ Fichier "${file.filename}" téléchargé avec succès!`)
      }
    } catch (error) {
      console.error('Erreur lors du téléchargement:', error)
      alert('❌ Erreur lors du téléchargement du fichier: ' + error)
    }
  }

  // Supprimer un fichier avec confirmation
  const handleDelete = async (id: number, filename: string) => {
    if (window.confirm(`Êtes-vous sûr de vouloir supprimer "${filename}" ?`)) {
      try {
        await deleteFileMutation.mutateAsync(id)
      } catch (error) {
        console.error('Erreur lors de la suppression:', error)
        alert('Erreur lors de la suppression du fichier')
      }
    }
  }

  // Gérer le partage d'un fichier
  const handleShare = (file: SecureFile) => {
    setFileToShare(file)
    setShowShareModal(true)
  }

  // Soumettre le partage
  const handleShareSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!fileToShare || !shareEmail.trim()) {
      alert('Veuillez entrer une adresse email valide')
      return
    }

    try {
      // Appeler la commande Tauri pour partager le fichier
      const { invoke } = await import('@tauri-apps/api/tauri')
      const response = await invoke<{
        success: boolean
        share_token: string
        share_link: string
        expires_at: string
      }>('share_file', {
        request: {
          file_id: fileToShare.id,
          recipient_email: shareEmail,
          expiration_days: parseInt(shareExpiration)
        }
      })

      if (response.success) {
        // Copier le lien de partage dans le presse-papiers
        const { writeText } = await import('@tauri-apps/api/clipboard')
        await writeText(response.share_link)
        
        alert(
          `✅ Fichier "${fileToShare.filename}" partagé avec succès!\n\n` +
          `📧 Destinataire: ${shareEmail}\n` +
          `⏰ Expire le: ${new Date(response.expires_at).toLocaleString()}\n` +
          `🔗 Lien: ${response.share_link}\n\n` +
          `Le lien a été copié dans le presse-papiers.`
        )
      }
      
      setShowShareModal(false)
      setFileToShare(null)
      setShareEmail('')
      setShareExpiration('7')
    } catch (error) {
      console.error('Erreur de partage:', error)
      alert('Erreur lors du partage du fichier: ' + error)
    }
  }

  // Formater la taille du fichier
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
  }

  // Obtenir l'icône selon le type MIME
  const getFileIcon = (mimeType?: string) => {
    if (!mimeType) return <FileIcon className="w-8 h-8 text-gray-400" />

    if (mimeType.startsWith('image/')) {
      return <Image className="w-8 h-8 text-blue-500" />
    } else if (mimeType.startsWith('video/')) {
      return <Film className="w-8 h-8 text-purple-500" />
    } else if (mimeType.startsWith('audio/')) {
      return <Music className="w-8 h-8 text-green-500" />
    } else if (mimeType.includes('zip') || mimeType.includes('compressed')) {
      return <Archive className="w-8 h-8 text-yellow-500" />
    } else if (mimeType.startsWith('text/') || mimeType.includes('pdf')) {
      return <FileText className="w-8 h-8 text-red-500" />
    }

    return <FileIcon className="w-8 h-8 text-gray-400" />
  }

  // Formater la date
  const formatDate = (dateString: string): string => {
    const date = new Date(dateString)
    return date.toLocaleDateString('fr-FR', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  // Filtrer les fichiers par recherche
  const filteredFiles = files.filter((file) =>
    file.filename.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <DashboardLayout>
      <div className="p-6">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-800 dark:text-white mb-2">
          Fichiers Sécurisés
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Gérez vos fichiers chiffrés en toute sécurité
        </p>
      </div>

      {/* Barre de recherche et bouton d'ajout */}
      <div className="flex gap-4 mb-6">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="text"
            placeholder="Rechercher un fichier..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
          />
        </div>
        <button
          onClick={() => setShowUploadModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Upload className="w-5 h-5" />
          Télécharger un fichier
        </button>
      </div>

      {/* Liste des fichiers */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : filteredFiles.length === 0 ? (
        <div className="text-center py-12 text-gray-500 dark:text-gray-400">
          {searchTerm ? 'Aucun fichier trouvé' : 'Aucun fichier. Commencez par en télécharger un !'}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredFiles.map((file) => (
            <div
              key={file.id}
              className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4 hover:shadow-lg transition-shadow"
            >
              <div className="flex items-start gap-3 mb-3">
                {getFileIcon(file.mime_type)}
                <div className="flex-1 min-w-0">
                  <h3 className="font-semibold text-gray-800 dark:text-white truncate" title={file.filename}>
                    {file.filename}
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {formatFileSize(file.file_size)}
                  </p>
                </div>
              </div>

              <div className="text-xs text-gray-500 dark:text-gray-400 mb-3">
                {formatDate(file.created_at)}
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => handleDownload(file)}
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors text-sm"
                >
                  <Download className="w-4 h-4" />
                  Télécharger
                </button>
                <button
                  onClick={() => handleShare(file)}
                  className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  title="Partager"
                >
                  <Share2 className="w-4 h-4" />
                </button>
                <button
                  onClick={() => handleDelete(file.id, file.filename)}
                  disabled={deleteFileMutation.isPending}
                  className="px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      </div>

      {/* Modal d'upload */}
      {showUploadModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold text-gray-800 dark:text-white">
                Télécharger un fichier
              </h2>
              <button
                onClick={() => {
                  setShowUploadModal(false)
                  setSelectedFile(null)
                  setUploadError('')
                }}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Bouton de sélection de fichier */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Sélectionner un fichier
                </label>
                <button
                  onClick={handleFileSelect}
                  className="w-full py-3 px-4 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg
                    hover:border-blue-500 dark:hover:border-blue-400 transition-colors
                    flex items-center justify-center gap-2 text-gray-700 dark:text-gray-300"
                >
                  <Upload className="w-5 h-5" />
                  <span>Cliquer pour choisir un fichier</span>
                </button>
                {selectedFile && (
                  <p className="mt-2 text-sm text-green-600 dark:text-green-400">
                    ✓ {selectedFile.name} ({formatFileSize(selectedFile.size)})
                  </p>
                )}
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Fichiers stockés chiffrés sur disque (aucune limite de taille)
                </p>
              </div>

              {/* Fichier sélectionné */}
              {selectedFile && (
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3">
                  <div className="flex items-center gap-2">
                    {getFileIcon(selectedFile.type)}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-800 dark:text-white truncate">
                        {selectedFile.name}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {formatFileSize(selectedFile.size)}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Erreur */}
              {uploadError && (
                <div className="flex items-start gap-2 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-red-600 dark:text-red-400">{uploadError}</p>
                </div>
              )}

              {/* Boutons */}
              <div className="flex gap-3 pt-2">
                <button
                  onClick={() => {
                    setShowUploadModal(false)
                    setSelectedFile(null)
                    setUploadError('')
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                >
                  Annuler
                </button>
                <button
                  onClick={handleUpload}
                  disabled={!selectedFile || isUploading}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isUploading ? 'Téléchargement...' : 'Télécharger'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal de partage */}
      {showShareModal && fileToShare && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold text-gray-800 dark:text-white flex items-center gap-2">
                <Share2 className="w-6 h-6 text-blue-600" />
                Partager le fichier
              </h2>
              <button
                onClick={() => {
                  setShowShareModal(false)
                  setFileToShare(null)
                  setShareEmail('')
                  setShareExpiration('7')
                }}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Nom du fichier */}
            <div className="mb-4 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <div className="flex items-center gap-2">
                {getFileIcon(fileToShare.mime_type)}
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-gray-800 dark:text-white truncate">
                    {fileToShare.filename}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {formatFileSize(fileToShare.file_size)}
                  </p>
                </div>
              </div>
            </div>

            <form onSubmit={handleShareSubmit} className="space-y-4">
              {/* Email du destinataire */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Email du destinataire
                </label>
                <input
                  type="email"
                  value={shareEmail}
                  onChange={(e) => setShareEmail(e.target.value)}
                  placeholder="exemple@email.com"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                  required
                />
              </div>

              {/* Durée d'expiration */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Expiration du lien
                </label>
                <select
                  value={shareExpiration}
                  onChange={(e) => setShareExpiration(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                >
                  <option value="1">1 jour</option>
                  <option value="3">3 jours</option>
                  <option value="7">7 jours</option>
                  <option value="14">14 jours</option>
                  <option value="30">30 jours</option>
                </select>
              </div>

              {/* Information de sécurité */}
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                <div className="flex gap-2">
                  <AlertCircle className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    Le fichier sera partagé via un lien sécurisé chiffré. Le destinataire devra s'authentifier pour y accéder.
                  </p>
                </div>
              </div>

              {/* Boutons */}
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowShareModal(false)
                    setFileToShare(null)
                    setShareEmail('')
                    setShareExpiration('7')
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Partager
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </DashboardLayout>
  )
}

export default FilesPage
