import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useAuthStore } from './stores/authStore'
import { type AutoLockStatus } from './lib/vault-service'
import { ToastProvider } from './design-system/organisms'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import ResetVaultPage from './pages/ResetVaultPage'
import DashboardPage from './pages/DashboardPage'
import PasswordsPage from './pages/PasswordsPage'
import FilesPage from './pages/FilesPage'
import KeysPage from './pages/KeysPage'
import { AutoUpdater } from './components/AutoUpdater'
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
    const saved = localStorage.getItem('theme')
    if (saved === 'dark') document.documentElement.classList.add('dark')
    else if (saved === 'light') document.documentElement.classList.remove('dark')
    else if (window.matchMedia('(prefers-color-scheme: dark)').matches) document.documentElement.classList.add('dark')

    const savedColor = localStorage.getItem('color-theme')
    if (savedColor) document.documentElement.setAttribute('data-theme', savedColor)
    else document.documentElement.removeAttribute('data-theme')

    invoke<string>('init_local_db')
      .then(() => setDbReady(true))
      .catch((e) => {
        console.error('[App] init_local_db failed:', e)
        // Still mark dbReady so login page can show the actual error
        setDbReady(true)
      })
  }, [])

  // Validate backend session is still alive when frontend thinks user is authenticated
  useEffect(() => {
    if (!isAuthenticated) return

    // Validate session with a command that requires auth
    // If it fails, the backend session expired (app restart, etc.) → force re-login
    invoke<AutoLockStatus>('check_auto_lock')
      .then((status) => {
        // If auto-lock says we're locked, force re-login to unlock the enclave
        if (status?.locked) {
          clearAuth()
        }
      })
      .catch(() => {
        // Backend session not active → force re-login (enclave unlock required)
        clearAuth()
      })
  }, [isAuthenticated])

  return (
    <Routes>
      {!isAuthenticated ? (
        <>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/reset-vault" element={<ResetVaultPage />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </>
      ) : (
        <>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/passwords" element={<PasswordsPage />} />
          <Route path="/files" element={<FilesPage />} />
          <Route path="/keys" element={<KeysPage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/system-security" element={<SystemSecurityPage />} />
          <Route path="/shares" element={<SharesPage />} />
          <Route path="/backup" element={<BackupRestorePage />} />
          <Route path="/transfer" element={<TransferPage />} />
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
        <AppRoutes />
      </ToastProvider>
    </BrowserRouter>
  )
}

export default App
