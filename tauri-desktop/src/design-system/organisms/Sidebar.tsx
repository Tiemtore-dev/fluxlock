import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  KeyRound,
  Files,
  ShieldCheck,
  Download,
  Settings,
  LogOut,
  Lock,
  ArrowLeftRight,
  Menu,
  X,
} from 'lucide-react'
import { useAuthStore } from '../../stores/authStore'

const navItems = [
  { label: 'Tableau de bord', href: '/', icon: LayoutDashboard },
  { label: 'Mots de passe', href: '/passwords', icon: KeyRound },
  { label: 'Fichiers', href: '/files', icon: Files },
  { label: 'Clés crypto', href: '/keys', icon: Lock },
  { label: 'Sécurité', href: '/system-security', icon: ShieldCheck },
  { label: 'Transfert', href: '/transfer', icon: ArrowLeftRight },
  { label: 'Backup', href: '/backup', icon: Download },
  { label: 'Paramètres', href: '/settings', icon: Settings },
]

// Bottom tab bar shows a subset for mobile
const mobileNavItems = [
  { label: 'Accueil', href: '/', icon: LayoutDashboard },
  { label: 'Mots de passe', href: '/passwords', icon: KeyRound },
  { label: 'Fichiers', href: '/files', icon: Files },
  { label: 'Sécurité', href: '/system-security', icon: ShieldCheck },
  { label: 'Plus', href: '__more__', icon: Menu },
]

export function Sidebar() {
  const location = useLocation()
  const { user, clearAuth } = useAuthStore()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const handleMobileNav = (href: string) => {
    if (href === '__more__') {
      setMobileMenuOpen(true)
    } else {
      setMobileMenuOpen(false)
    }
  }

  return (
    <>
      {/* ── Desktop sidebar (hidden on mobile) ── */}
      <aside className="sidebar-desktop" style={{
        position: 'fixed',
        inset: '0 auto 0 0',
        width: 'var(--sidebar-width)',
        background: 'var(--bg-surface)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 'var(--z-sidebar)' as any,
      }}>
        {/* Brand */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          padding: 'var(--space-5) var(--space-5)',
          borderBottom: '1px solid var(--border)',
        }}>
          <div style={{
            width: 32,
            height: 32,
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--shadow-glow)',
          }}>
            <Lock size={16} style={{ color: 'var(--text-inverse)' }} />
          </div>
          <span style={{
            fontFamily: 'var(--font-display)',
            fontSize: 'var(--text-xl)',
            color: 'var(--text-primary)',
            letterSpacing: 'var(--tracking-tight)',
          }}>
            FluXlock
          </span>
        </div>

        {/* Navigation */}
        <nav style={{
          flex: 1,
          padding: 'var(--space-3)',
          display: 'flex',
          flexDirection: 'column',
          gap: '2px',
          overflowY: 'auto',
        }}>
          {navItems.map((item) => {
            const isActive = location.pathname === item.href
            const Icon = item.icon
            return (
              <Link
                key={item.href}
                to={item.href}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-3)',
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-md)',
                  textDecoration: 'none',
                  fontSize: 'var(--text-sm)',
                  fontFamily: 'var(--font-body)',
                  fontWeight: isActive ? 500 : 400,
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  background: isActive ? 'var(--bg-hover)' : 'transparent',
                  transition: `all var(--transition-fast)`,
                }}
              >
                <Icon size={18} style={{
                  color: isActive ? 'var(--accent)' : 'var(--text-muted)',
                  transition: `color var(--transition-fast)`,
                }} />
                {item.label}
                {isActive && (
                  <div style={{
                    width: 4,
                    height: 4,
                    borderRadius: 'var(--radius-full)',
                    background: 'var(--accent)',
                    marginLeft: 'auto',
                  }} />
                )}
              </Link>
            )
          })}
        </nav>

        {/* User section */}
        <div style={{
          padding: 'var(--space-4)',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--space-3)',
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-3)',
            padding: 'var(--space-2)',
          }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: 'var(--radius-full)',
              background: 'var(--bg-hover)',
              border: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 'var(--text-sm)',
              fontWeight: 600,
              color: 'var(--accent-text)',
              fontFamily: 'var(--font-body)',
            }}>
              {user?.username?.charAt(0).toUpperCase() || '?'}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <p style={{
                fontSize: 'var(--text-sm)',
                fontWeight: 500,
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-body)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {user?.username}
              </p>
              <p style={{
                fontSize: 'var(--text-xs)',
                color: 'var(--text-muted)',
                fontFamily: 'var(--font-body)',
              }}>
                En ligne
              </p>
            </div>
          </div>
          <button
            onClick={clearAuth}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 'var(--space-2)',
              padding: '8px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--danger-muted)',
              background: 'transparent',
              color: 'var(--danger)',
              fontSize: 'var(--text-sm)',
              fontFamily: 'var(--font-body)',
              fontWeight: 500,
              cursor: 'pointer',
              transition: `all var(--transition-fast)`,
            }}
          >
            <LogOut size={16} />
            Déconnexion
          </button>
        </div>
      </aside>

      {/* ── Mobile bottom tab bar ── */}
      <nav className="mobile-bottom-nav fixed bottom-0 left-0 right-0 bg-[var(--bg-surface)] border-t border-[var(--border)] hidden z-[1000]">
        <div className="mobile-bottom-nav__inner flex justify-around items-center py-2 pb-[max(8px,env(safe-area-inset-bottom))] px-1">
          {mobileNavItems.map((item) => {
            const isMore = item.href === '__more__'
            const isActive = !isMore && location.pathname === item.href
            const Icon = item.icon

            if (isMore) {
              return (
                <button
                  key="more"
                  onClick={() => setMobileMenuOpen(true)}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: 2,
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: mobileMenuOpen ? 'var(--accent)' : 'var(--text-muted)',
                    fontFamily: 'var(--font-body)',
                  }}
                  className="py-1 px-1.5 text-[9px] min-[360px]:text-[10px]"
                >
                  <Icon size={18} className="min-[360px]:w-5 min-[360px]:h-5" />
                  <span>Plus</span>
                </button>
              )
            }

            return (
              <Link
                key={item.href}
                to={item.href}
                onClick={() => setMobileMenuOpen(false)}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 2,
                  textDecoration: 'none',
                  color: isActive ? 'var(--accent)' : 'var(--text-muted)',
                  fontFamily: 'var(--font-body)',
                  fontWeight: isActive ? 600 : 400,
                }}
                className="py-1 px-1.5 text-[9px] min-[360px]:text-[10px]"
              >
                <Icon size={18} className="min-[360px]:w-5 min-[360px]:h-5" />
                <span>{item.label}</span>
              </Link>
            )
          })}
        </div>
      </nav>

      {/* ── Mobile full-screen "More" drawer ── */}
      {mobileMenuOpen && (
        <div className="mobile-more-drawer" style={{
          position: 'fixed',
          inset: 0,
          background: 'var(--bg-void)',
          zIndex: 1100,
          display: 'flex',
          flexDirection: 'column',
          animation: 'fadeIn 0.15s ease',
        }}>
          {/* Header */}
          <div className="mobile-drawer-header" style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: 'var(--space-4) var(--space-5)',
            paddingTop: 'max(var(--space-4), env(safe-area-inset-top))',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-surface)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <div style={{
                width: 28,
                height: 28,
                borderRadius: 'var(--radius-md)',
                background: 'var(--accent)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <Lock size={14} style={{ color: 'var(--text-inverse)' }} />
              </div>
              <span style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-lg)', color: 'var(--text-primary)' }}>
                FluXlock
              </span>
            </div>
            <button
              onClick={() => setMobileMenuOpen(false)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--text-muted)',
                padding: 'var(--space-2)',
              }}
            >
              <X size={24} />
            </button>
          </div>

          {/* All nav items */}
          <nav className="mobile-drawer-nav" style={{ flex: 1, padding: 'var(--space-4) var(--space-5)', overflowY: 'auto' }}>
            {navItems.map((item) => {
              const isActive = location.pathname === item.href
              const Icon = item.icon
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-4)',
                    padding: 'var(--space-4) var(--space-3)',
                    borderRadius: 'var(--radius-md)',
                    textDecoration: 'none',
                    fontSize: 'var(--text-base)',
                    fontFamily: 'var(--font-body)',
                    fontWeight: isActive ? 600 : 400,
                    color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                    background: isActive ? 'var(--bg-hover)' : 'transparent',
                    marginBottom: 2,
                  }}
                >
                  <Icon size={22} style={{ color: isActive ? 'var(--accent)' : 'var(--text-muted)' }} />
                  {item.label}
                </Link>
              )
            })}
          </nav>

          {/* User / Logout */}
          <div className="mobile-drawer-footer" style={{
            padding: 'var(--space-4) var(--space-5)',
            paddingBottom: 'max(var(--space-4), env(safe-area-inset-bottom))',
            borderTop: '1px solid var(--border)',
            background: 'var(--bg-surface)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
              <div style={{
                width: 36, height: 36, borderRadius: 'var(--radius-full)',
                background: 'var(--bg-hover)', border: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--accent-text)',
              }}>
                {user?.username?.charAt(0).toUpperCase() || '?'}
              </div>
              <div>
                <p style={{ fontSize: 'var(--text-sm)', fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>{user?.username}</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>En ligne</p>
              </div>
            </div>
            <button
              onClick={() => { setMobileMenuOpen(false); clearAuth() }}
              style={{
                width: '100%',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-2)',
                padding: '10px', borderRadius: 'var(--radius-md)',
                border: '1px solid var(--danger)', background: 'var(--danger-muted)',
                color: 'var(--danger)', fontSize: 'var(--text-sm)', fontFamily: 'var(--font-body)',
                fontWeight: 500, cursor: 'pointer',
              }}
            >
              <LogOut size={16} /> Déconnexion
            </button>
          </div>
        </div>
      )}
    </>
  )
}
