import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, ShieldCheck, Eye, EyeOff, Copy } from 'lucide-react'
import { identityDocuments, type IdentityDocument, type IssuedSdJwt } from '../lib/vault-service'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { useClipboard } from '../hooks/useClipboard'

const DOC_TYPES: Record<string, string> = {
  cni: 'Carte Nationale d’Identité (CNI)',
  passport: 'Passeport biométrique',
  driver_license: 'Permis de conduire',
  eudi_pid: 'Identité Européenne EUDI Wallet (eIDAS 2.0)',
  health_card: 'Carte Vitale / Santé',
  tax_id: 'Identifiant Fiscal',
}

export default function IdentitiesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const copy = useClipboard()
  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [docType, setDocType] = useState('cni')
  const [title, setTitle] = useState('')
  const [fullName, setFullName] = useState('')
  const [documentNumber, setDocumentNumber] = useState('')
  const [issuingAuthority, setIssuingAuthority] = useState('')
  const [issueDate, setIssueDate] = useState('')
  const [expiryDate, setExpiryDate] = useState('')
  const [nationality, setNationality] = useState('')
  const [birthDate, setBirthDate] = useState('')
  const [notes, setNotes] = useState('')

  const [revealedNumbers, setRevealedNumbers] = useState<Map<number, string>>(new Map())
  const [sdJwtResult, setSdJwtResult] = useState<IssuedSdJwt | null>(null)

  const { data: docs = [], isLoading } = useQuery({
    queryKey: ['identity-documents'],
    queryFn: identityDocuments.list,
  })

  const createMut = useMutation({
    mutationFn: () =>
      identityDocuments.create({
        doc_type: docType,
        title,
        full_name: fullName,
        document_number: documentNumber,
        issuing_authority: issuingAuthority,
        issue_date: issueDate,
        expiry_date: expiryDate,
        nationality,
        birth_date: birthDate,
        notes,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-documents'] })
      setShowModal(false)
      setTitle(''); setFullName(''); setDocumentNumber(''); setIssuingAuthority(''); setIssueDate(''); setExpiryDate(''); setNationality(''); setBirthDate(''); setNotes('')
      toast('Document d’identité chiffré et enregistré', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => identityDocuments.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-documents'] })
      toast('Document supprimé', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const toggleNumber = async (doc: IdentityDocument) => {
    if (revealedNumbers.has(doc.id)) {
      setRevealedNumbers((prev) => {
        const next = new Map(prev)
        next.delete(doc.id)
        return next
      })
      return
    }
    try {
      const plain = await identityDocuments.decryptNumber(doc.id)
      setRevealedNumbers((prev) => new Map(prev).set(doc.id, plain))
    } catch (err) {
      toast('Erreur déchiffrement : ' + String(err), 'error')
    }
  }

  const issueSelectiveDisclosure = async (doc: IdentityDocument) => {
    try {
      const res = await identityDocuments.generateSdJwt(doc.id, ['full_name', 'nationality', 'expiry_date'])
      setSdJwtResult(res)
      toast('Justificatif IETF SD-JWT à divulgation sélective généré', 'success')
    } catch (err) {
      toast('Erreur SD-JWT : ' + String(err), 'error')
    }
  }

  const filtered = docs.filter((d) => {
    const q = search.toLowerCase()
    return d.title.toLowerCase().includes(q) || d.full_name.toLowerCase().includes(q) || d.doc_type.toLowerCase().includes(q)
  })

  return (
    <WorkspacePage
      title="Documents d’identité"
      description="Coffre d’identité souveraine (Self-Sovereign Identity) & divulgation sélective IETF SD-JWT (eIDAS 2.0)"
      actions={
        <Button icon={Plus} onClick={() => setShowModal(true)}>
          Nouveau document
        </Button>
      }
    >
      <section className="workspace-panel workspace-stack" aria-labelledby="identities-list">
        <h2 id="identities-list">Pièces d’identité</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher par titre, nom ou type de document…" />
        {isLoading ? (
          <p role="status" className="workspace-label">
            <Spinner size={18} /> Chargement…
          </p>
        ) : filtered.length === 0 ? (
          <p className="workspace-empty">Aucun document d’identité enregistré.</p>
        ) : (
          <ul className="workspace-list">
            {filtered.map((doc) => {
              const num = revealedNumbers.get(doc.id)
              return (
                <li key={doc.id} className="workspace-row">
                  <div className="workspace-row-copy">
                    <strong>{doc.title}</strong>
                    <span>
                      <Badge>{DOC_TYPES[doc.doc_type] || doc.doc_type}</Badge> · {doc.full_name}
                      {doc.nationality ? ` (${doc.nationality})` : ''}
                    </span>
                    <span className="font-mono">
                      N° : {num ?? '••••••••••••'} {doc.expiry_date ? `· Exp. ${doc.expiry_date}` : ''}
                    </span>
                  </div>
                  <div className="workspace-actions">
                    <Button variant="secondary" size="sm" icon={num ? EyeOff : Eye} onClick={() => void toggleNumber(doc)}>
                      {num ? 'Masquer N°' : 'Révéler N°'}
                    </Button>
                    <Button variant="secondary" size="sm" icon={ShieldCheck} onClick={() => void issueSelectiveDisclosure(doc)}>
                      Preuve SD-JWT
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={Trash2}
                      aria-label={`Supprimer ${doc.title}`}
                      onClick={() => {
                        if (confirm(`Supprimer « ${doc.title} » ?`)) deleteMut.mutate(doc.id)
                      }}
                    />
                  </div>
                </li>
              )
            })}
          </ul>
        )}
      </section>

      <Modal open={showModal} onClose={() => setShowModal(false)} title="Nouveau document d’identité">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            createMut.mutate()
          }}
          className="flex flex-col gap-4"
        >
          <label className="workspace-field">
            Type de document
            <select value={docType} onChange={(e) => setDocType(e.target.value)}>
              {Object.entries(DOC_TYPES).map(([k, label]) => (
                <option key={k} value={k}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <Input label="Titre" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ex: Passeport Français" required />
          <Input label="Nom complet du titulaire" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Marie Curie" required />
          <Input label="Numéro officiel du document (chiffré AAD)" value={documentNumber} onChange={(e) => setDocumentNumber(e.target.value)} placeholder="24FR998877" required />
          <div className="grid grid-cols-2 gap-3">
            <Input label="Nationalité" value={nationality} onChange={(e) => setNationality(e.target.value)} placeholder="FRA" />
            <Input label="Date de naissance" value={birthDate} onChange={(e) => setBirthDate(e.target.value)} placeholder="1990-05-14" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Input label="Date d’émission" value={issueDate} onChange={(e) => setIssueDate(e.target.value)} placeholder="2024-01-10" />
            <Input label="Date d’expiration" value={expiryDate} onChange={(e) => setExpiryDate(e.target.value)} placeholder="2034-01-10" />
          </div>
          <Input label="Autorité émettrice" value={issuingAuthority} onChange={(e) => setIssuingAuthority(e.target.value)} placeholder="Préfecture de Paris" />
          <Input label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Notes additionnelles…" />
          <div className="flex gap-3 pt-2">
            <Button type="submit" fullWidth loading={createMut.isPending}>
              Enregistrer
            </Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setShowModal(false)}>
              Annuler
            </Button>
          </div>
        </form>
      </Modal>

      <Modal open={!!sdJwtResult} onClose={() => setSdJwtResult(null)} title="Justificatif IETF SD-JWT (Divulgation Sélective)">
        {sdJwtResult && (
          <div className="workspace-stack">
            <p className="text-sm">
              Jeton signé <code>EdDSA</code> conforme <code>draft-ietf-oauth-selective-disclosure-jwt</code> (chaque attribut est salé avec 128 bits CSPRNG et haché avec <code>SHA-256</code>).
            </p>
            <code className="p-3 rounded-lg bg-input border border-bd text-xs break-all block">
              {sdJwtResult.compact_sd_jwt}
            </code>
            <Button
              icon={Copy}
              onClick={() => {
                copy(sdJwtResult.compact_sd_jwt)
                toast('Jeton SD-JWT copié', 'success')
              }}
            >
              Copier le justificatif SD-JWT
            </Button>
          </div>
        )}
      </Modal>
    </WorkspacePage>
  )
}
