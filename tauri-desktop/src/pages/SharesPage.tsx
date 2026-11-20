import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Copy, FileText, Trash2 } from 'lucide-react'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Badge, Spinner } from '../design-system/atoms'
import { SearchBar } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { useClipboard } from '../hooks/useClipboard'
import { shares } from '../lib/vault-service'

export default function SharesPage() {
  const { toast } = useToast()
  const copy = useClipboard()
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<'all' | 'active' | 'expired'>('all')
  const client = useQueryClient()
  const query = useQuery({ queryKey: ['userShares'], queryFn: shares.list })

  const revoke = useMutation({
    mutationFn: shares.revoke,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['userShares'] })
      toast('Partage révoqué', 'success')
    },
  })

  const term = search.trim().toLocaleLowerCase()
  const now = Date.now()
  const entries = (query.data ?? []).map((share) => ({ share, expired: Date.parse(share.expires_at) <= now }))
  const filtered = entries.filter(({ share, expired }) =>
    (filter === 'all' || (filter === 'expired') === expired) &&
    (share.recipient_email.toLocaleLowerCase().includes(term) || share.filename?.toLocaleLowerCase().includes(term))
  )

  return (
    <WorkspacePage title="Fichiers partagés" description="Vérifiez qui a accès à un document et révoquez les liens devenus inutiles."
      actions={<Link to="/files" className="workspace-link">Retour aux fichiers</Link>}>
      <section className="workspace-panel workspace-stack" aria-labelledby="share-list">
        <h2 id="share-list">Liens de partage</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher par document ou destinataire…" />
        <div className="workspace-segments" role="group" aria-label="État des liens">
          <button type="button" aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>Tous</button>
          <button type="button" aria-pressed={filter === 'active'} onClick={() => setFilter('active')}>Actifs</button>
          <button type="button" aria-pressed={filter === 'expired'} onClick={() => setFilter('expired')}>Expirés</button>
        </div>
        {query.isPending ? <p role="status" className="workspace-label"><Spinner size={18} /> Chargement…</p> :
          query.isError ? <div className="workspace-actions">
            <p role="alert" className="workspace-error">Impossible de charger les partages.</p>
            <Button variant="secondary" onClick={() => void query.refetch()}>Réessayer</Button>
          </div> : filtered.length === 0 ? (
          <p className="workspace-empty">{entries.length ? 'Aucun lien ne correspond à ce filtre.' : 'Aucun lien de partage enregistré.'}</p>
        ) : (
          <ul className="workspace-list">
            {filtered.map(({ share, expired }) => <li key={share.id} className="workspace-row">
              <span className="workspace-icon" aria-hidden="true"><FileText size={18} /></span>
              <div className="workspace-row-copy">
                <strong>{share.filename || `Fichier n° ${share.file_id}`}</strong>
                <span>{share.recipient_email}</span>
                <span>{expired ? 'Expiré le' : 'Expire le'} {new Date(share.expires_at).toLocaleString('fr-FR')} · {share.access_count} accès</span>
              </div>
              <Badge variant={expired ? 'warning' : 'success'}>{expired ? 'Expiré' : 'Actif'}</Badge>
              <div className="workspace-actions">
                {!expired && <Button size="sm" variant="secondary" icon={Copy} onClick={async () => {
                  try {
                    await copy(`securevault://share/${share.share_token}`)
                    toast('Lien copié', 'success')
                  } catch {
                    toast('Impossible de copier le lien', 'error')
                  }
                }}>Copier le lien</Button>}
                <Button size="sm" variant="ghost" icon={Trash2} disabled={revoke.isPending}
                  onClick={() => {
                    if (confirm(`Révoquer le partage avec ${share.recipient_email} ?`)) revoke.mutate(share.id)
                  }}>Révoquer</Button>
              </div>
            </li>)}
          </ul>
        )}
        {revoke.isError && <p role="alert" className="workspace-error">Impossible de révoquer le partage.</p>}
      </section>
    </WorkspacePage>
  )
}
