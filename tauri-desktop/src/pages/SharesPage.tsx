import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Share2, Trash2, Clock, Mail, FileText, Eye, Calendar, Copy } from 'lucide-react'
import { AppShell } from '../design-system/layouts'
import { Button, Badge, Spinner } from '../design-system/atoms'
import { SearchBar, EmptyState } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { shares as sharesService, type FileShare } from '../lib/vault-service'

const fmt = (d: string) => new Date(d).toLocaleDateString('fr-FR', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
const isExpired = (d: string) => new Date(d) < new Date()
const remaining = (d: string) => {
  const diff = new Date(d).getTime() - Date.now()
  if (diff < 0) return 'Expiré'
  const days = Math.floor(diff / 864e5)
  const hours = Math.floor((diff % 864e5) / 36e5)
  if (days > 0) return `${days} jour${days > 1 ? 's' : ''}`
  if (hours > 0) return `${hours} heure${hours > 1 ? 's' : ''}`
  return "Moins d'1 heure"
}

export default function SharesPage() {
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const qc = useQueryClient()

  const { data: allShares = [], isLoading } = useQuery({
    queryKey: ['userShares'],
    queryFn: sharesService.list,
  })

  const revokeMut = useMutation({
    mutationFn: (id: number) => sharesService.revoke(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['userShares'] }); toast('Partage révoqué', 'success') },
    onError: () => toast('Erreur lors de la révocation', 'error'),
  })

  const handleRevoke = (s: FileShare) => { if (confirm(`Révoquer le partage avec ${s.recipient_email} ?`)) revokeMut.mutate(s.id) }
  const copyLink = async (token: string) => { try { await navigator.clipboard.writeText(`securevault://share/${token}`); toast('Lien copié', 'success') } catch { toast('Erreur copie', 'error') } }

  const filtered = allShares.filter(s =>
    s.recipient_email.toLowerCase().includes(search.toLowerCase()) ||
    (s.filename && s.filename.toLowerCase().includes(search.toLowerCase()))
  )

  const card: React.CSSProperties = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 'var(--space-5)' }
  const meta: React.CSSProperties = { display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} className="page-header">
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)', margin: 0 }}>
              <Share2 size={28} style={{ color: 'var(--accent)' }} /> Mes Partages
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)' }}>Gérez les fichiers partagés</p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>{filtered.length}</p>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>{filtered.length === 1 ? 'Partage actif' : 'Partages actifs'}</p>
          </div>
        </div>

        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher par email ou nom de fichier…" />

        {isLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--space-12)' }}><Spinner size={32} /></div>
        ) : filtered.length === 0 ? (
          <EmptyState icon={Share2} title={search ? 'Aucun partage trouvé' : 'Aucun partage actif'} description={search ? "Essayez d'autres termes" : 'Partagez un fichier depuis la page Fichiers'} />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {filtered.map(s => {
              const exp = isExpired(s.expires_at)
              return (
                <div key={s.id} style={{ ...card, borderColor: exp ? 'var(--danger)' : 'var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ flex: 1 }}>
                      {/* Title row */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
                        <FileText size={18} style={{ color: 'var(--accent)' }} />
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)' }}>
                          {s.filename || `Fichier #${s.file_id}`}
                        </span>
                        <Badge variant={exp ? 'danger' : 'success'} size="sm">{exp ? 'Expiré' : 'Actif'}</Badge>
                      </div>

                      {/* Meta grid */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 'var(--space-3)' }}>
                        <div style={meta}><Mail size={14} /> <strong>Dest.:</strong> {s.recipient_email}</div>
                        <div style={meta}><Eye size={14} /> <strong>Accès:</strong> {s.access_count} fois</div>
                        <div style={meta}><Calendar size={14} /> <strong>Créé:</strong> {fmt(s.created_at)}</div>
                        <div style={{ ...meta, color: exp ? 'var(--danger)' : undefined }}><Clock size={14} /> <strong>{exp ? 'Expiré' : 'Expire'}:</strong> {remaining(s.expires_at)}</div>
                      </div>

                      {/* Token */}
                      <div style={{ marginTop: 'var(--space-3)', paddingTop: 'var(--space-3)', borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Token:</span>
                        <code style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', background: 'var(--bg-elevated)', padding: '2px 6px', borderRadius: 'var(--radius-sm)' }}>
                          {s.share_token.substring(0, 20)}…
                        </code>
                        <button onClick={() => copyLink(s.share_token)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 'var(--text-xs)' }}>
                          <Copy size={12} /> Copier
                        </button>
                      </div>
                    </div>

                    {/* Revoke */}
                    <button onClick={() => handleRevoke(s)} disabled={revokeMut.isPending} title="Révoquer" style={{
                      background: 'none', border: 'none', cursor: 'pointer', color: 'var(--danger)', padding: 'var(--space-2)', borderRadius: 'var(--radius-md)',
                      opacity: revokeMut.isPending ? 0.5 : 1,
                    }}>
                      <Trash2 size={18} />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </AppShell>
  )
}
