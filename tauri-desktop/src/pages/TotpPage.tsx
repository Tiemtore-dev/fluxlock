import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Clock, Copy, ShieldCheck, RefreshCw, QrCode, Upload } from 'lucide-react'
import { totpAuthenticator, type TotpLiveItem } from '../lib/vault-service'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { useClipboard } from '../hooks/useClipboard'

function formatOtpCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`
  return code
}

export default function TotpPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const copy = useClipboard()

  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [inputMode, setInputMode] = useState<'manual' | 'uri' | 'migration'>('manual')
  const [issuer, setIssuer] = useState('')
  const [account, setAccount] = useState('')
  const [secretOrUri, setSecretOrUri] = useState('')
  const [algorithm, setAlgorithm] = useState('SHA1')
  const [digits, setDigits] = useState(6)
  const [period, setPeriod] = useState(30)
  const [migrationText, setMigrationText] = useState('')
  const [qrImageBase64, setQrImageBase64] = useState('')
  const [qrFileName, setQrFileName] = useState('')
  const qrInputRef = useRef<HTMLInputElement>(null)
  const [tick, setTick] = useState(0)

  const { data: items = [], isLoading, refetch } = useQuery({
    queryKey: ['totp-authenticators'],
    queryFn: totpAuthenticator.list,
    refetchInterval: 5000,
  })

  // Décrémente le compte à rebours chaque seconde et rafraîchit dès qu'une fenêtre de 30s expire
  useEffect(() => {
    const timer = setInterval(() => {
      setTick((t) => t + 1)
      const nowSec = Math.floor(Date.now() / 1000)
      if (nowSec % 30 === 0) {
        void refetch()
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [refetch])

  const createMut = useMutation({
    mutationFn: () =>
      totpAuthenticator.create({
        issuer: inputMode === 'manual' ? issuer : undefined,
        account: inputMode === 'manual' ? account : undefined,
        secret_or_uri: secretOrUri.trim(),
        algorithm: inputMode === 'manual' ? algorithm : undefined,
        digits: inputMode === 'manual' ? digits : undefined,
        period: inputMode === 'manual' ? period : undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['totp-authenticators'] })
      queryClient.invalidateQueries({ queryKey: ['passwords'] })
      setShowModal(false)
      setIssuer(''); setAccount(''); setSecretOrUri(''); setAlgorithm('SHA1'); setDigits(6); setPeriod(30)
      toast('Code 2FA TOTP (RFC 6238) enregistré et chiffré', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const migrationMut = useMutation({
    mutationFn: () =>
      totpAuthenticator.importBatch({
        raw_input: migrationText.trim() || undefined,
        qr_image_base64: qrImageBase64 || undefined,
      }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['totp-authenticators'] })
      queryClient.invalidateQueries({ queryKey: ['passwords'] })
      setShowModal(false)
      setMigrationText(''); setQrImageBase64(''); setQrFileName('')
      toast(`${res.imported_count} compte(s) 2FA migré(s) et chiffré(s) en Rust`, 'success')
    },
    onError: (err) => toast('Erreur migration : ' + String(err), 'error'),
  })

  const deleteMut = useMutation({
    mutationFn: ({ id, source }: { id: number; source: 'standalone' | 'password' }) =>
      totpAuthenticator.delete(id, source),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['totp-authenticators'] })
      queryClient.invalidateQueries({ queryKey: ['passwords'] })
      toast('Authentificateur TOTP supprimé', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const handleQrFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (file.size > 15 * 1024 * 1024) {
      toast('L’image dépasse la limite de 15 Mo', 'error')
      return
    }
    setQrFileName(file.name)
    const reader = new FileReader()
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setQrImageBase64(reader.result)
      }
    }
    reader.readAsDataURL(file)
  }

  const filtered = items.filter((item) => {
    const q = search.toLowerCase()
    return item.issuer.toLowerCase().includes(q) || item.account.toLowerCase().includes(q)
  })

  const computeRemaining = (item: TotpLiveItem) => {
    void tick
    const p = item.period || 30
    const nowSec = Math.floor(Date.now() / 1000)
    return p - (nowSec % p)
  }

  return (
    <WorkspacePage
      title="Authentificateur 2FA (TOTP)"
      description="Générateur de codes temporels RFC 6238 / RFC 4226 & Analyseur de QR Code / Migration Google Authenticator 100 % local en Rust"
      actions={
        <>
          <Button variant="secondary" icon={RefreshCw} onClick={() => void refetch()}>
            Actualiser
          </Button>
          <Button
            variant="secondary"
            icon={QrCode}
            onClick={() => {
              setInputMode('migration')
              setShowModal(true)
            }}
          >
            Migrer / Scanner QR Code
          </Button>
          <Button
            icon={Plus}
            onClick={() => {
              setInputMode('manual')
              setShowModal(true)
            }}
          >
            Ajouter un code 2FA
          </Button>
        </>
      }
    >
      <section className="workspace-panel workspace-stack" aria-labelledby="totp-guide-title">
        <details className="workspace-details">
          <summary id="totp-guide-title">
            Guide : Migrer depuis Google Authenticator ou ajouter une graine 2FA (QR Code, URI ou clé Base32)
          </summary>
          <div className="workspace-stack text-sm mt-2">
            <p>
              <strong>Option 1 — Migrer tous vos comptes depuis Google Authenticator en une seule fois :</strong> Dans Google Authenticator, ouvrez <em>Menu → Transférer des comptes → Exporter des comptes</em>. Prenez une capture d’écran du QR Code affiché (ou copiez le lien <code>otpauth-migration://offline?data=...</code>), puis cliquez sur <strong>Migrer / Scanner QR Code</strong> ci-dessus. Notre moteur Rust décode l’image et le flux Protobuf <strong>100 % en mémoire vive locale</strong> sans jamais quitter votre coffre.
            </p>
            <p>
              <strong>Option 2 — Scanner le QR Code d’un site web (GitHub, AWS, Google…) :</strong> Faites une capture d’écran du QR Code 2FA affiché par le site et chargez-la dans l’onglet <strong>Migrer / Scanner QR Code</strong>, ou collez directement l’URL <code>otpauth://totp/...</code> ou la clé Base32 (ex. <code>JBSWY3DPEHPK3PXP</code>).
            </p>
          </div>
        </details>
      </section>

      <section className="workspace-panel workspace-stack" aria-labelledby="totp-list">
        <h2 id="totp-list">Codes 2FA actifs ({items.length})</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher un service (GitHub, AWS, Google) ou un compte…" />
        {isLoading ? (
          <p role="status" className="workspace-label">
            <Spinner size={18} /> Calcul des codes RFC 6238…
          </p>
        ) : filtered.length === 0 ? (
          <p className="workspace-empty">
            Aucun code 2FA TOTP configuré. Cliquez sur « Migrer / Scanner QR Code » ou « Ajouter un code 2FA ».
          </p>
        ) : (
          <ul className="workspace-list">
            {filtered.map((item) => {
              const remaining = computeRemaining(item)
              const urgent = remaining <= 5
              return (
                <li key={`${item.source}-${item.id}`} className="workspace-row">
                  <div className="workspace-row-copy">
                    <strong>{item.issuer}</strong>
                    {item.account && <span>{item.account}</span>}
                    <span>
                      <Badge>{item.algorithm}</Badge> · {item.digits} chiffres ·{' '}
                      {item.source === 'password' ? 'Lié à un identifiant du coffre' : 'Authentificateur dédié'}
                    </span>
                  </div>
                  <div className="workspace-secret flex items-center gap-3">
                    <code
                      className="font-mono text-xl font-bold tracking-wider px-3 py-1.5 rounded-lg border border-bd bg-input"
                      style={{ color: urgent ? 'var(--warning)' : 'var(--accent-text)' }}
                    >
                      {formatOtpCode(item.code)}
                    </code>
                    <span
                      className="font-mono text-xs flex items-center gap-1"
                      style={{ color: urgent ? 'var(--warning)' : 'var(--text-secondary)' }}
                      title="Secondes restantes avant rotation RFC 6238"
                    >
                      <Clock size={14} /> {remaining}s
                    </span>
                  </div>
                  <div className="workspace-actions">
                    <Button
                      variant="secondary"
                      size="sm"
                      icon={Copy}
                      onClick={() => {
                        copy(item.code)
                        toast(`Code ${item.issuer} (${item.code}) copié — effacé dans 30 s`, 'success')
                      }}
                    >
                      Copier le code
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={Trash2}
                      aria-label={`Supprimer ${item.issuer}`}
                      onClick={() => {
                        if (confirm(`Supprimer le code 2FA pour « ${item.issuer} » ?`)) {
                          deleteMut.mutate({ id: item.id, source: item.source })
                        }
                      }}
                    />
                  </div>
                </li>
              )
            })}
          </ul>
        )}
      </section>

      <Modal open={showModal} onClose={() => setShowModal(false)} title="Ajouter ou Migrer des codes 2FA (TOTP — RFC 6238)" width={620}>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (inputMode === 'migration') {
              migrationMut.mutate()
            } else {
              createMut.mutate()
            }
          }}
          className="flex flex-col gap-4"
        >
          <div className="workspace-segments" role="group" aria-label="Mode de saisie de la graine TOTP">
            <button
              type="button"
              aria-pressed={inputMode === 'manual'}
              onClick={() => setInputMode('manual')}
            >
              Clé Base32
            </button>
            <button
              type="button"
              aria-pressed={inputMode === 'uri'}
              onClick={() => setInputMode('uri')}
            >
              URL otpauth://
            </button>
            <button
              type="button"
              aria-pressed={inputMode === 'migration'}
              onClick={() => setInputMode('migration')}
            >
              QR Code / Migration Google Auth
            </button>
          </div>

          {inputMode === 'manual' ? (
            <>
              <Input
                label="Service / Émetteur (Issuer)"
                value={issuer}
                onChange={(e) => setIssuer(e.target.value)}
                placeholder="Ex: GitHub, Google, AWS, Binance…"
                required
              />
              <Input
                label="Compte / Email"
                value={account}
                onChange={(e) => setAccount(e.target.value)}
                placeholder="Ex: alice@example.com"
              />
              <Input
                label="Clé secrète Base32 (affichée par le site sous le QR Code)"
                value={secretOrUri}
                onChange={(e) => setSecretOrUri(e.target.value)}
                placeholder="Ex: JBSWY3DPEHPK3PXP"
                required
              />
              <div className="grid grid-cols-3 gap-3">
                <label className="workspace-field">
                  Algorithme HMAC
                  <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
                    <option value="SHA1">SHA-1 (Standard)</option>
                    <option value="SHA256">SHA-256</option>
                    <option value="SHA512">SHA-512</option>
                  </select>
                </label>
                <label className="workspace-field">
                  Chiffres
                  <select value={digits} onChange={(e) => setDigits(Number(e.target.value))}>
                    <option value={6}>6 chiffres</option>
                    <option value={8}>8 chiffres</option>
                  </select>
                </label>
                <Input
                  label="Période (sec)"
                  type="number"
                  value={String(period)}
                  onChange={(e) => setPeriod(Number(e.target.value) || 30)}
                />
              </div>
            </>
          ) : inputMode === 'uri' ? (
            <Input
              label="Collez toute l’URL otpauth://totp/…"
              value={secretOrUri}
              onChange={(e) => setSecretOrUri(e.target.value)}
              placeholder="otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
              required
            />
          ) : (
            <div className="workspace-stack">
              <div className="rounded-lg p-3 border border-bd bg-input flex flex-col gap-2">
                <p className="text-xs font-medium uppercase tracking-wide text-tx-secondary">
                  1. Analyseur d’image QR Code 100 % local en Rust (Zéro réseau, Zéro disque)
                </p>
                <div className="flex items-center gap-3 flex-wrap">
                  <Button
                    type="button"
                    variant="secondary"
                    icon={Upload}
                    onClick={() => qrInputRef.current?.click()}
                  >
                    Choisir une capture d’écran / image QR Code
                  </Button>
                  <input
                    ref={qrInputRef}
                    type="file"
                    accept="image/png,image/jpeg,image/webp,image/heic,image/bmp,image/tiff"
                    onChange={handleQrFileChange}
                    hidden
                  />
                  {qrFileName && <span className="text-xs font-mono">{qrFileName} (prêt à décoder en RAM)</span>}
                </div>
              </div>

              <div>
                <label htmlFor="totp-migration-textarea" className="block text-xs font-medium text-tx-secondary uppercase mb-1">
                  2. Ou collez une URL de lot Google Authenticator (otpauth-migration://offline?data=…) ou plusieurs lignes otpauth://
                </label>
                <textarea
                  id="totp-migration-textarea"
                  rows={4}
                  value={migrationText}
                  onChange={(e) => setMigrationText(e.target.value)}
                  placeholder={"otpauth-migration://offline?data=...\nou\notpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"}
                  className="w-full bg-input border border-bd rounded-lg px-3 py-2.5 text-tx-primary font-mono text-xs outline-none resize-y focus:border-accent"
                />
              </div>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <Button
              type="submit"
              fullWidth
              icon={ShieldCheck}
              loading={createMut.isPending || migrationMut.isPending}
              disabled={inputMode === 'migration' && !qrImageBase64 && !migrationText.trim()}
            >
              {inputMode === 'migration'
                ? 'Décoder en Rust et importer dans le coffre'
                : 'Chiffrer la graine et activer le TOTP'}
            </Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setShowModal(false)}>
              Annuler
            </Button>
          </div>
        </form>
      </Modal>
    </WorkspacePage>
  )
}
