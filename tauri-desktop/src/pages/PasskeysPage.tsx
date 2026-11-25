import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, KeyRound, ShieldCheck, Copy } from 'lucide-react'
import { passkeys, type PasskeyEntry, type PasskeyAssertion } from '../lib/vault-service'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { useClipboard } from '../hooks/useClipboard'

export default function PasskeysPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const copy = useClipboard()
  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [rpId, setRpId] = useState('')
  const [rpName, setRpName] = useState('')
  const [userName, setUserName] = useState('')
  const [userDisplayName, setUserDisplayName] = useState('')
  const [assertionResult, setAssertionResult] = useState<PasskeyAssertion | null>(null)

  const { data: list = [], isLoading } = useQuery({
    queryKey: ['passkeys'],
    queryFn: passkeys.list,
  })

  const createMut = useMutation({
    mutationFn: () =>
      passkeys.create({
        rp_id: rpId,
        rp_name: rpName || rpId,
        user_name: userName,
        user_display_name: userDisplayName || userName,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passkeys'] })
      setShowModal(false)
      setRpId(''); setRpName(''); setUserName(''); setUserDisplayName('')
      toast('Passkey WebAuthn Level 3 (COSE EdDSA -8) générée', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => passkeys.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passkeys'] })
      toast('Passkey supprimée', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const signAssertion = async (pk: PasskeyEntry) => {
    try {
      const challenge = btoa(`fluxlock-webauthn-${Date.now()}`).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
      const res = await passkeys.authenticate({ id: pk.id, challenge_b64url: challenge })
      setAssertionResult(res)
      queryClient.invalidateQueries({ queryKey: ['passkeys'] })
      toast(`Assertion WebAuthn signée (compteur = ${res.new_sign_count})`, 'success')
    } catch (err) {
      toast('Erreur WebAuthn : ' + String(err), 'error')
    }
  }

  const filtered = list.filter((p) => {
    const q = search.toLowerCase()
    return p.rp_id.toLowerCase().includes(q) || p.rp_name.toLowerCase().includes(q) || p.user_name.toLowerCase().includes(q)
  })

  return (
    <WorkspacePage
      title="Passkeys (WebAuthn Level 3)"
      description="Authentificateur logiciel FIDO2 / CTAP2 (Discoverable Credentials COSE EdDSA -8 résistants au phishing)"
      actions={
        <Button icon={Plus} onClick={() => setShowModal(true)}>
          Nouvelle Passkey
        </Button>
      }
    >
      <section className="workspace-panel workspace-stack" aria-labelledby="passkeys-list">
        <h2 id="passkeys-list">Passkeys résidentes</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher par domaine Relying Party (rp_id) ou compte…" />
        {isLoading ? (
          <p role="status" className="workspace-label">
            <Spinner size={18} /> Chargement…
          </p>
        ) : filtered.length === 0 ? (
          <p className="workspace-empty">Aucune Passkey WebAuthn enregistrée dans ce coffre.</p>
        ) : (
          <ul className="workspace-list">
            {filtered.map((pk) => (
              <li key={pk.id} className="workspace-row">
                <div className="workspace-row-copy">
                  <strong>{pk.rp_name} ({pk.rp_id})</strong>
                  <span>
                    <Badge>COSE EdDSA ({pk.cose_algorithm})</Badge> · {pk.user_name} · Compteur d’assertions : {pk.sign_count}
                  </span>
                  <span className="font-mono text-xs">Credential ID : {pk.credential_id.slice(0, 24)}…</span>
                </div>
                <div className="workspace-actions">
                  <Button variant="secondary" size="sm" icon={ShieldCheck} onClick={() => void signAssertion(pk)}>
                    Signer assertion WebAuthn
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={Trash2}
                    aria-label={`Supprimer ${pk.rp_id}`}
                    onClick={() => {
                      if (confirm(`Supprimer la Passkey « ${pk.rp_id} (${pk.user_name}) » ?`)) deleteMut.mutate(pk.id)
                    }}
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <Modal open={showModal} onClose={() => setShowModal(false)} title="Créer une Passkey WebAuthn Level 3">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            createMut.mutate()
          }}
          className="flex flex-col gap-4"
        >
          <Input label="Domaine Relying Party (rp_id)" value={rpId} onChange={(e) => setRpId(e.target.value)} placeholder="github.com" required />
          <Input label="Nom du service (rp_name)" value={rpName} onChange={(e) => setRpName(e.target.value)} placeholder="GitHub" required />
          <Input label="Identifiant utilisateur (user.name)" value={userName} onChange={(e) => setUserName(e.target.value)} placeholder="alice@example.com" required />
          <Input label="Nom d’affichage (user.displayName)" value={userDisplayName} onChange={(e) => setUserDisplayName(e.target.value)} placeholder="Alice" />
          <div className="flex gap-3 pt-2">
            <Button type="submit" fullWidth icon={KeyRound} loading={createMut.isPending}>
              Générer la paire COSE Ed25519
            </Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setShowModal(false)}>
              Annuler
            </Button>
          </div>
        </form>
      </Modal>

      <Modal open={!!assertionResult} onClose={() => setAssertionResult(null)} title="Assertion WebAuthn Level 3 (navigator.credentials.get)">
        {assertionResult && (
          <div className="workspace-stack">
            <p className="text-sm">
              Signature cryptographique sur <code>authenticatorData || SHA-256(clientDataJSON)</code> pour <strong>{assertionResult.rp_id}</strong> (compteur = {assertionResult.new_sign_count}).
            </p>
            <code className="p-3 rounded-lg bg-input border border-bd text-xs break-all block">
              {JSON.stringify(assertionResult, null, 2)}
            </code>
            <Button
              icon={Copy}
              onClick={() => {
                copy(JSON.stringify(assertionResult))
                toast('Assertion WebAuthn copiée', 'success')
              }}
            >
              Copier l’assertion JSON
            </Button>
          </div>
        )}
      </Modal>
    </WorkspacePage>
  )
}
