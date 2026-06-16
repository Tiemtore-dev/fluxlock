import { useEffect, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { Shield, AlertTriangle, Lock, Unlock, RefreshCw, Activity, HardDrive } from 'lucide-react'
import { AppShell } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'

interface SecurityState {
  is_locked: boolean
  is_readonly: boolean
  threat_level: 'none' | 'low' | 'medium' | 'high' | 'critical'
  active_threats: string[]
}

interface FilesystemStats {
  total_events: number
  modifications: number
  creations: number
  deletions: number
  renames: number
  suspicious_extensions: number
  rapid_changes: number
  monitored_paths: string[]
  active_threats: string[]
  threat_level: string
  monitoring_enabled: boolean
}

/* helpers */
const threatColor = (l: string) =>
  l === 'critical' || l === 'high' ? 'var(--danger)' : l === 'medium' ? 'var(--warning)' : 'var(--success)'
const threatBadge = (l: string): 'danger' | 'warning' | 'success' =>
  l === 'critical' || l === 'high' ? 'danger' : l === 'medium' ? 'warning' : 'success'

export default function SystemSecurityPage() {
  const { toast } = useToast()
  const [sec, setSec] = useState<SecurityState | null>(null)
  const [fs, setFs] = useState<FilesystemStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [showPwDialog, setShowPwDialog] = useState(false)
  const [pwInput, setPwInput] = useState('')

  const load = async () => {
    try {
      const state = await invoke<SecurityState>('get_security_status')
      setSec(state)
      const stats = await invoke<FilesystemStats>('get_filesystem_stats')
      setFs(stats)
    } catch { /* ignore load errors */ }
    finally { setLoading(false) }
  }

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t) }, [])

  const confirmDisableReadonly = async () => {
    if (!pwInput) return
    try {
      const result = await invoke<string>('disable_readonly_mode', { password: pwInput })
      setShowPwDialog(false); setPwInput(''); await load()
      toast(result, 'success')
    } catch (e: any) { toast('Erreur : ' + e.toString(), 'error') }
  }

  const toggleMonitoring = async (enable: boolean) => {
    if (!confirm(`${enable ? 'Activer' : 'Désactiver'} la surveillance ?`)) return
    try {
      const r = await invoke<string>(enable ? 'enable_filesystem_monitoring' : 'disable_filesystem_monitoring')
      toast(r, 'success'); await load()
    } catch (e: any) { toast('Erreur : ' + e.toString(), 'error') }
  }

  /* reusable style objects */
  const card: React.CSSProperties = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 'var(--space-6)' }
  const statBox = (color: string): React.CSSProperties => ({ background: `color-mix(in srgb, ${color} 10%, transparent)`, borderRadius: 'var(--radius-md)', padding: 'var(--space-4)' })

  if (loading) return <AppShell><div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--space-16)' }}><Spinner size={32} /></div></AppShell>

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} className="page-header">
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)', margin: 0 }}>
              <Shield size={28} style={{ color: 'var(--accent)' }} /> Sécurité Système
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)' }}>Anti-brute force et détection ransomware</p>
          </div>
          <Button icon={RefreshCw} onClick={load}>Actualiser</Button>
        </div>

        {sec && (
          <>
            {/* Status cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 'var(--space-4)' }}>
              {/* Threat level */}
              <div style={card}>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 'var(--tracking-wide)', marginBottom: 'var(--space-2)' }}>Niveau de menace</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                  <AlertTriangle size={28} style={{ color: threatColor(sec.threat_level) }} />
                  <Badge variant={threatBadge(sec.threat_level)} size="sm">{sec.threat_level.toUpperCase()}</Badge>
                </div>
              </div>
              {/* Readonly */}
              <div style={card}>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 'var(--tracking-wide)', marginBottom: 'var(--space-2)' }}>Mode lecture seule</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                  {sec.is_readonly ? <Lock size={28} style={{ color: 'var(--danger)' }} /> : <Unlock size={28} style={{ color: 'var(--success)' }} />}
                  <span style={{ fontWeight: 600, color: sec.is_readonly ? 'var(--danger)' : 'var(--success)', fontSize: 'var(--text-sm)' }}>
                    {sec.is_readonly ? 'ACTIVÉ' : 'DÉSACTIVÉ'}
                  </span>
                </div>
              </div>
              {/* Lock state */}
              <div style={card}>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 'var(--tracking-wide)', marginBottom: 'var(--space-2)' }}>Verrouillage</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                  <Shield size={28} style={{ color: sec.is_locked ? 'var(--danger)' : 'var(--success)' }} />
                  <span style={{ fontWeight: 600, color: sec.is_locked ? 'var(--danger)' : 'var(--success)', fontSize: 'var(--text-sm)' }}>
                    {sec.is_locked ? 'VERROUILLÉ' : 'DÉVERROUILLÉ'}
                  </span>
                </div>
              </div>
            </div>

            {/* Active threats */}
            {sec.active_threats.length > 0 && (
              <div style={{ background: 'var(--danger-muted)', borderLeft: '4px solid var(--danger)', borderRadius: 'var(--radius-md)', padding: 'var(--space-5)' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}>
                  <AlertTriangle size={20} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 2 }} />
                  <div>
                    <h3 style={{ fontWeight: 700, color: 'var(--danger)', marginBottom: 'var(--space-2)' }}>Menaces actives détectées</h3>
                    <ul style={{ margin: 0, paddingLeft: 'var(--space-4)', color: 'var(--text-primary)', fontSize: 'var(--text-sm)' }}>
                      {sec.active_threats.map((t, i) => <li key={i} style={{ marginBottom: 'var(--space-1)' }}>{t}</li>)}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Actions */}
            <div style={card}>
              <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', marginBottom: 'var(--space-4)' }}>Actions de sécurité</h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 'var(--space-4)' }}>
                {/* File monitoring toggle */}
                <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 'var(--space-4)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <Activity size={18} style={{ color: 'var(--accent)' }} />
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-sm)' }}>Surveillance fichiers</span>
                    </div>
                    <button onClick={() => toggleMonitoring(!fs?.monitoring_enabled)} style={{
                      position: 'relative', width: 44, height: 24, borderRadius: 12, border: 'none', cursor: 'pointer',
                      background: fs?.monitoring_enabled ? 'var(--accent)' : 'var(--bg-hover)', transition: 'background var(--transition-fast)',
                    }}>
                      <span style={{
                        position: 'absolute', top: 2, left: fs?.monitoring_enabled ? 22 : 2,
                        width: 20, height: 20, borderRadius: '50%', background: 'white', transition: 'left var(--transition-fast)',
                      }} />
                    </button>
                  </div>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    {fs?.monitoring_enabled ? 'Détection ransomware active' : 'Surveillance désactivée'}
                  </p>
                </div>
                {/* Disable readonly */}
                <Button variant="danger" icon={Unlock} onClick={() => setShowPwDialog(true)} disabled={!sec.is_readonly} fullWidth>
                  Désactiver lecture seule
                </Button>
              </div>
            </div>

            {/* Filesystem stats */}
            {fs && (
              <div style={card}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
                  <HardDrive size={20} style={{ color: 'var(--accent)' }} />
                  <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Surveillance temps réel</h2>
                </div>

                {/* Threat level bar */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-3)', background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', marginBottom: 'var(--space-4)' }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>Menace système</span>
                  <Badge variant={threatBadge(fs.threat_level.toLowerCase())}>{fs.threat_level}</Badge>
                </div>

                {/* Event counters */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
                  {[
                    { label: 'Événements', value: fs.total_events, color: 'var(--info)' },
                    { label: 'Modifications', value: fs.modifications, color: 'var(--success)' },
                    { label: 'Créations', value: fs.creations, color: '#a78bfa' },
                    { label: 'Suppressions', value: fs.deletions, color: 'var(--danger)' },
                  ].map(({ label, value, color }) => (
                    <div key={label} style={statBox(color)}>
                      <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color, margin: 0 }}>{value.toLocaleString()}</p>
                      <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>{label}</p>
                    </div>
                  ))}
                </div>

                {/* Suspicious counters */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
                  <div style={statBox('var(--warning)')}>
                    <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--warning)', margin: 0 }}>{fs.suspicious_extensions}</p>
                    <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Extensions suspectes</p>
                  </div>
                  <div style={statBox('var(--warning)')}>
                    <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--warning)', margin: 0 }}>{fs.rapid_changes}</p>
                    <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Modifications rapides</p>
                  </div>
                </div>

                {/* Monitored paths */}
                <div style={{ marginBottom: 'var(--space-4)' }}>
                  <h3 style={{ fontWeight: 600, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginBottom: 'var(--space-2)' }}>
                    Répertoires surveillés ({fs.monitored_paths.length})
                  </h3>
                  <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)', maxHeight: 160, overflowY: 'auto' }}>
                    {fs.monitored_paths.map((p, i) => (
                      <p key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: '2px 0' }}>{p}</p>
                    ))}
                  </div>
                </div>

                {/* FS active threats */}
                {fs.active_threats.length > 0 && (
                  <div style={{ background: 'var(--danger-muted)', borderLeft: '4px solid var(--danger)', borderRadius: 'var(--radius-md)', padding: 'var(--space-4)' }}>
                    <h3 style={{ fontWeight: 700, color: 'var(--danger)', fontSize: 'var(--text-sm)', marginBottom: 'var(--space-2)' }}>Menaces système actives</h3>
                    <ul style={{ margin: 0, paddingLeft: 'var(--space-4)', fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                      {fs.active_threats.map((t, i) => <li key={i}>{t}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* Password dialog for disabling readonly */}
      <Modal open={showPwDialog} onClose={() => { setShowPwDialog(false); setPwInput('') }} title="Désactiver le mode lecture seule">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>Entrez votre mot de passe pour confirmer.</p>
          <Input type="password" value={pwInput} onChange={(e) => setPwInput(e.target.value)} onKeyDown={(e: React.KeyboardEvent) => e.key === 'Enter' && confirmDisableReadonly()} placeholder="Mot de passe" autoFocus />
          <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
            <Button fullWidth onClick={confirmDisableReadonly}>Confirmer</Button>
            <Button fullWidth variant="secondary" onClick={() => { setShowPwDialog(false); setPwInput('') }}>Annuler</Button>
          </div>
        </div>
      </Modal>
    </AppShell>
  )
}
