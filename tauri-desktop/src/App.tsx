import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect } from 'react'
import { listen } from '@tauri-apps/api/event'
import { invoke } from './lib/vault-context'
import { useAuthStore } from './stores/authStore'
import { type AutoLockStatus } from './lib/vault-service'
import { ToastProvider } from './design-system/organisms'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import { vaults } from './lib/vault-service'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import ResetVaultPage from './pages/ResetVaultPage'
import DashboardPage from './pages/DashboardPage'
import PasswordsPage from './pages/PasswordsPage'
import FilesPage from './pages/FilesPage'
import NotesPage from './pages/NotesPage'
import KeysPage from './pages/KeysPage'
import { AutoUpdater } from './components/AutoUpdater'
import { AndroidUpdater } from './components/AndroidUpdater'
import SecurityPage from './pages/SecurityPage'
import SystemSecurityPage from './pages/SystemSecurityPage'
import SettingsPage from './pages/SettingsPage'
import SharesPage from './pages/SharesPage'
import BackupRestorePage from './pages/BackupRestorePage'
import TransferPage from './pages/TransferPage'

function AppRoutes() {
  const { isAuthenticated, clearAuth, setDbReady } = useAuthStore()
  useKeyboardShortcuts()
  useEffect(() => {
    let disposed = false
    let unlisten: (() => void) | undefined
    void listen('autofill-vault-locked', () => useAuthStore.getState().acceptNativeLock()).then((off) => {
      if (disposed) off()
      else unlisten = off
    }).catch(() => {})
    return () => { disposed = true; unlisten?.() }
  }, [])

  useEffect(() => {
    const saved = localStorage.getItem('theme')
    if (saved === 'dark') document.documentElement.classList.add('dark')
    else if (saved === 'light') document.documentElement.classList.remove('dark')
    else if (window.matchMedia('(prefers-color-scheme: dark)').matches) document.documentElement.classList.add('dark')

    const savedColor = localStorage.getItem('color-theme')
    if (savedColor) document.documentElement.setAttribute('data-theme', savedColor)
    else document.documentElement.removeAttribute('data-theme')

    invoke<string>('init_local_db')
      .then(() => vaults.list())
      .then((overview) => { useAuthStore.getState().setOverview(overview); setDbReady(true) })
      .catch((e) => {
        console.error('[App] init_local_db failed:', e)
        useAuthStore.getState().setStartupError(String(e))
      })
  }, [])

  // Validate backend session is still alive when frontend thinks user is authenticated
  useEffect(() => {
    if (!isAuthenticated) return
    let active = true

    // Validate session with a command that requires auth
    // If it fails, the backend session expired (app restart, etc.) → force re-login
    invoke<AutoLockStatus>('check_auto_lock')
      .then((status) => {
        // If auto-lock says we're locked, force re-login to unlock the enclave
        if (active && status?.locked) {
          void clearAuth().catch(() => {})
        }
      })
      .catch(() => {
        // Backend session not active → force re-login (enclave unlock required)
        if (active) void clearAuth().catch(() => {})
      })
    return () => { active = false }
  }, [isAuthenticated])

  return (
    <Routes>
      {!isAuthenticated ? (
        <>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </>
      ) : (
        <>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/passwords" element={<PasswordsPage />} />
          <Route path="/files" element={<FilesPage />} />
          <Route path="/notes" element={<NotesPage />} />
          <Route path="/keys" element={<KeysPage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/system-security" element={<SystemSecurityPage />} />
          <Route path="/shares" element={<SharesPage />} />
          <Route path="/backup" element={<BackupRestorePage />} />
          <Route path="/transfer" element={<TransferPage />} />
          <Route path="/reset-vault" element={<ResetVaultPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </>
      )}
    </Routes>
  )
}

function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AutoUpdater />
        <AndroidUpdater />
        <AppRoutes />
      </ToastProvider>
    </BrowserRouter>
  )
}

export default App
