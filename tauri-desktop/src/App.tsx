import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect } from 'react'
import { invoke } from '@tauri-apps/api/tauri'
import { useAuthStore } from './stores/authStore'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import ResetVaultPage from './pages/ResetVaultPage'
import DashboardPage from './pages/DashboardPage'
import PasswordsPage from './pages/PasswordsPage'
import FilesPage from './pages/FilesPage'
import KeysPage from './pages/KeysPage'
import SecurityPage from './pages/SecurityPage'
import SystemSecurityPage from './pages/SystemSecurityPage'
import SettingsPage from './pages/SettingsPage'
import SharesPage from './pages/SharesPage'

function App() {
  const { isAuthenticated } = useAuthStore()

  // Initialiser le thème et la base de données au démarrage
  useEffect(() => {
    // Appliquer le thème sauvegardé immédiatement
    const savedTheme = localStorage.getItem('theme')
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark')
    } else if (savedTheme === 'light') {
      document.documentElement.classList.remove('dark')
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.classList.add('dark')
    }

    // Initialiser la base de données
    const initDb = async () => {
      try {
        console.log('🔄 Initializing database...')
        const result = await invoke<string>('init_local_db')
        console.log('✅ Database initialized:', result)
      } catch (error) {
        console.error('❌ Error initializing database:', error)
        // Afficher l'erreur à l'utilisateur si critique
      }
    }
    initDb()
  }, [])

  return (
    <BrowserRouter>
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
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  )
}

export default App
