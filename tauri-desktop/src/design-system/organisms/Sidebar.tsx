import { Link, NavLink, useLocation } from 'react-router-dom'
import { useEffect, useRef } from 'react'
import {
  Archive, ArrowLeftRight, MoreHorizontal, Files, KeyRound, LayoutDashboard,
  LockKeyhole, Settings, ShieldCheck, Fingerprint, FileText, CreditCard, UserCheck, Clock, X,
} from 'lucide-react'
import { useAuthStore } from '../../stores/authStore'

const vaultLinks = [
  { label: 'Vue d’ensemble', to: '/', icon: LayoutDashboard },
  { label: 'Mots de passe', to: '/passwords', icon: KeyRound },
  { label: 'Fichiers', to: '/files', icon: Files },
  { label: 'Notes', to: '/notes', icon: FileText },
  { label: 'Clés cryptographiques', to: '/keys', icon: Fingerprint },
  { label: 'Codes 2FA (TOTP)', to: '/totp', icon: Clock },
  { label: 'Cartes bancaires', to: '/cards', icon: CreditCard },
  { label: 'Documents d’identité', to: '/identities', icon: UserCheck },
  { label: 'Passkeys WebAuthn', to: '/passkeys', icon: ShieldCheck },
]

const settingsLinks = [
  { label: 'Transferts', to: '/transfer', icon: ArrowLeftRight },
  { label: 'Sauvegardes', to: '/backup', icon: Archive },
  { label: 'Sécurité', to: '/system-security', icon: ShieldCheck },
  { label: 'Paramètres', to: '/settings', icon: Settings },
]

export function Sidebar() {
  const location = useLocation()
  const selectedVault = useAuthStore((state) => state.selectedVault)
  const clearAuth = useAuthStore((state) => state.clearAuth)
  const drawer = useRef<HTMLDialogElement>(null)
  const more = useRef<HTMLButtonElement>(null)

  useEffect(() => { drawer.current?.close() }, [location.pathname])
  const openDrawer = () => drawer.current?.showModal()
  const closeDrawer = () => drawer.current?.close()
  const groups = (
    <>
      <div className="vault-nav-group">
        <p className="vault-active-name" title={selectedVault?.name}>{selectedVault?.name || 'Coffre'}</p>
        {vaultLinks.map(({ icon: Icon, label, to }) => (
          <NavLink key={to} to={to} end className="vault-nav-item" onClick={closeDrawer}>
            <Icon size={19} aria-hidden="true" />{label}
          </NavLink>
        ))}
      </div>
      <div className="vault-nav-group">
        <p>Appareils et protection</p>
        {settingsLinks.map(({ icon: Icon, label, to }) => (
          <NavLink key={to} to={to} end className="vault-nav-item" onClick={closeDrawer}>
            <Icon size={19} aria-hidden="true" />{label}
          </NavLink>
        ))}
      </div>
    </>
  )

  return (
    <>
      <aside className="sidebar-desktop vault-sidebar">
        <Link to="/" className="vault-brand"><img src="/fluxlock-mark.png" alt="" width={40} height={40} />FluXlock</Link>
        <nav aria-label="Navigation principale" className="vault-nav">{groups}</nav>
        <button type="button" className="vault-lock-button" onClick={() => void clearAuth().catch(() => {})}>
          <ArrowLeftRight size={17} aria-hidden="true" /> Changer de coffre
        </button>
        <button type="button" className="vault-lock-button" onClick={() => void clearAuth().catch(() => {})}>
          <LockKeyhole size={17} aria-hidden="true" /> Verrouiller le coffre
        </button>
      </aside>

      <header className="vault-mobile-header">
        <Link to="/" className="vault-brand"><img src="/fluxlock-mark.png" alt="" width={36} height={36} />FluXlock</Link>
        <button type="button" className="vault-icon-button" onClick={() => void clearAuth().catch(() => {})} aria-label="Verrouiller le coffre">
          <LockKeyhole size={20} aria-hidden="true" />
        </button>
      </header>
      <nav className="mobile-bottom-nav vault-tabs" aria-label="Navigation mobile">
        <div className="vault-tabs-inner">
          {[
            { ...vaultLinks[0], label: 'Accueil' },
            { ...vaultLinks[1], label: 'Identifiants' },
            vaultLinks[2],
            settingsLinks[0],
          ].map(({ icon: Icon, label, to }) => (
            <NavLink key={to} to={to} end><Icon size={20} aria-hidden="true" />{label}</NavLink>
          ))}
          <button type="button" ref={more} aria-haspopup="dialog" onClick={openDrawer}>
            <MoreHorizontal size={20} aria-hidden="true" />Plus
          </button>
        </div>
      </nav>

      <dialog ref={drawer} className="mobile-more-drawer vault-drawer"
        aria-labelledby="vault-menu-title" onClose={() => more.current?.focus()}>
        <header>
          <h2 id="vault-menu-title">Navigation</h2>
          <button type="button" className="vault-icon-button" onClick={closeDrawer} aria-label="Fermer le menu">
            <X size={22} aria-hidden="true" />
          </button>
        </header>
        <nav aria-label="Toutes les pages" className="vault-nav">{groups}</nav>
        <button type="button" className="vault-lock-button" onClick={() => void clearAuth().catch(() => {})}>
          <ArrowLeftRight size={17} aria-hidden="true" /> Changer de coffre
        </button>
      </dialog>
    </>
  )
}
