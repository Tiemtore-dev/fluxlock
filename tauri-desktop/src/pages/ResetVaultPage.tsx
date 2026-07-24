import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { AlertTriangle, Shield, ArrowLeft, Trash2, Lock, ShieldOff, Database, Key, FileWarning, History } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'
import { Button, Input, Spinner } from '../design-system/atoms'

const deletedItems = [
  { icon: Key, label: 'Tous vos mots de passe enregistrés' },
  { icon: FileWarning, label: 'Tous vos fichiers chiffrés' },
  { icon: Lock, label: 'Toutes vos clés cryptographiques' },
  { icon: Shield, label: 'Votre compte et vos paramètres' },
  { icon: History, label: "L'historique de sécurité complet" },
  { icon: Database, label: 'La base de données intégrale' },
]

export default function ResetVaultPage() {
  const navigate = useNavigate()
  const [step, setStep] = useState<'warning' | 'confirmation'>('warning')
  const [confirmText, setConfirmText] = useState('')
  const [password, setPassword] = useState('')
  const [isResetting, setIsResetting] = useState(false)
  const [error, setError] = useState('')

  const handleReset = async () => {
    if (confirmText !== 'SUPPRIMER TOUT') { setError('Veuillez saisir exactement "SUPPRIMER TOUT"'); return }
    if (!password) { setError('Veuillez saisir votre mot de passe'); return }
    setIsResetting(true); setError('')
    try {
      await invoke('reset_vault_completely', { password })
      localStorage.clear(); sessionStorage.clear()
      navigate('/register')
    } catch (e: any) { setError('Erreur : ' + e.toString()) }
    finally { setIsResetting(false) }
  }

  return (
    <div className="auth-page">
      <div className="auth-page-inner animate-fade-in" style={{ maxWidth: 520 }}>
        {/* Brand header */}
        <div style={{ textAlign: 'center', marginBottom: 'var(--space-8)' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 64,
            height: 64,
            borderRadius: 'var(--radius-xl)',
            background: 'var(--danger)',
            boxShadow: '0 0 30px rgba(239,68,68,.3)',
            marginBottom: 'var(--space-4)',
          }}>
            <ShieldOff size={32} style={{ color: 'white' }} />
          </div>
          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: 'var(--text-2xl)',
            color: 'var(--text-primary)',
            letterSpacing: 'var(--tracking-tight)',
            margin: 0,
          }}>
            Réinitialisation du coffre-fort
          </h1>
          <p style={{
            fontSize: 'var(--text-sm)',
            color: 'var(--danger)',
            fontFamily: 'var(--font-body)',
            marginTop: 'var(--space-2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 'var(--space-2)',
            fontWeight: 500,
          }}>
            <AlertTriangle size={14} /> Action irréversible et définitive
          </p>
        </div>

        {/* Card */}
        <div className="auth-card" style={{
          position: 'relative',
          overflow: 'hidden',
        }}>
          {/* Subtle danger accent line at top */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: 3,
            background: 'linear-gradient(90deg, var(--danger), transparent)',
          }} />

          {step === 'warning' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
              {/* Danger callout */}
              <div style={{
                background: 'var(--danger-muted)',
                borderRadius: 'var(--radius-lg)',
                padding: 'var(--space-5)',
              }}>
                <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start' }}>
                  <AlertTriangle size={22} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 2 }} />
                  <div>
                    <h2 style={{ fontWeight: 700, color: 'var(--danger)', margin: '0 0 var(--space-2) 0', fontSize: 'var(--text-base)' }}>
                      Suppression totale et irréversible
                    </h2>
                    <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: 0, lineHeight: 1.6 }}>
                      Cette opération détruira <strong style={{ color: 'var(--text-primary)' }}>l'intégralité de vos données</strong>.
                      Aucune récupération ne sera possible après confirmation.
                    </p>
                  </div>
                </div>
              </div>

              {/* Items list */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                gap: 'var(--space-3)',
              }}>
                {deletedItems.map((item) => {
                  const Icon = item.icon
                  return (
                    <div key={item.label} style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 'var(--space-3)',
                      padding: 'var(--space-3)',
                      borderRadius: 'var(--radius-md)',
                      background: 'var(--bg-elevated)',
                      border: '1px solid var(--border)',
                    }}>
                      <Icon size={16} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)' }}>
                        {item.label}
                      </span>
                    </div>
                  )
                })}
              </div>

              {/* Use cases */}
              <div style={{
                background: 'color-mix(in srgb, var(--warning) 8%, transparent)',
                border: '1px solid color-mix(in srgb, var(--warning) 30%, transparent)',
                borderRadius: 'var(--radius-lg)',
                padding: 'var(--space-4)',
              }}>
                <p style={{ fontWeight: 600, color: 'var(--warning)', fontSize: 'var(--text-sm)', margin: '0 0 var(--space-2) 0' }}>
                  Cas d'utilisation
                </p>
                <ul style={{ margin: 0, paddingLeft: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                  <li>Mot de passe maître oublié définitivement</li>
                  <li>Repartir à zéro avec un nouveau coffre-fort</li>
                  <li>Effacer toute trace avant cession de l'appareil</li>
                </ul>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
                <Link to="/login" style={{ flex: 1, textDecoration: 'none' }}>
                  <Button variant="secondary" icon={ArrowLeft} fullWidth>Retour</Button>
                </Link>
                <div style={{ flex: 1 }}>
                  <Button variant="danger" icon={AlertTriangle} onClick={() => setStep('confirmation')} fullWidth>
                    Je comprends, continuer
                  </Button>
                </div>
              </div>
            </div>
          )}

          {step === 'confirmation' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
              <div style={{ textAlign: 'center' }}>
                <h2 style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: 'var(--text-xl)', margin: '0 0 var(--space-2) 0' }}>
                  Confirmation finale
                </h2>
                <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', margin: 0 }}>
                  Pour confirmer, saisissez exactement le texte ci-dessous
                </p>
              </div>

              {/* Code to type */}
              <div style={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-lg)',
                padding: 'var(--space-4)',
                textAlign: 'center',
              }}>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xl)',
                  fontWeight: 700,
                  color: 'var(--danger)',
                  letterSpacing: 'var(--tracking-wide)',
                }}>
                  SUPPRIMER TOUT
                </span>
              </div>

              <Input
                value={confirmText}
                onChange={(e) => { setConfirmText(e.target.value); setError('') }}
                placeholder="Saisissez ici…"
                autoFocus
                error={error || undefined}
              />

              {/* CFG-003: Mot de passe requis pour confirmer la réinitialisation */}
              <Input
                type="password"
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError('') }}
                placeholder="Votre mot de passe maître"
              />

              {/* Progress indicator — visual feedback */}
              <div style={{
                height: 3,
                borderRadius: 'var(--radius-full)',
                background: 'var(--bg-hover)',
                overflow: 'hidden',
              }}>
                <div style={{
                  height: '100%',
                  width: `${Math.min((confirmText.length / 14) * 100, 100)}%`,
                  background: confirmText === 'SUPPRIMER TOUT' ? 'var(--danger)' : 'var(--accent)',
                  transition: 'width 0.2s ease, background 0.2s ease',
                }} />
              </div>

              <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
                <div style={{ flex: 1 }}>
                  <Button variant="secondary" fullWidth onClick={() => { setStep('warning'); setConfirmText(''); setError('') }} disabled={isResetting}>
                    Retour
                  </Button>
                </div>
                <div style={{ flex: 1 }}>
                  <Button variant="danger" icon={isResetting ? undefined : Trash2} fullWidth onClick={handleReset} disabled={isResetting || confirmText !== 'SUPPRIMER TOUT' || !password}>
                    {isResetting ? <><Spinner size={16} /> Suppression…</> : 'Supprimer'}
                  </Button>
                </div>
              </div>

              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textAlign: 'center', margin: 0 }}>
                Cette action est définitive. Aucune récupération possible.
              </p>
            </div>
          )}
        </div>

        {/* Footer link */}
        <div style={{ textAlign: 'center', marginTop: 'var(--space-5)' }}>
          <Link to="/login" style={{
            color: 'var(--text-muted)',
            fontSize: 'var(--text-sm)',
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 'var(--space-2)',
            fontFamily: 'var(--font-body)',
          }}>
            <Shield size={14} /> Retour à la connexion
          </Link>
        </div>
      </div>
    </div>
  )
}
