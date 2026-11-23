import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import AutofillAuthPage from './pages/AutofillAuthPage'
import { useAuthStore } from './stores/authStore'
import './index.css'

// Configuration React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
})

useAuthStore.subscribe((state, previous) => {
  if (!state.isAuthenticated && previous.isAuthenticated) {
    queryClient.clear()
  }
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      {location.pathname === '/autofill-auth' ? <AutofillAuthPage /> : <App />}
    </QueryClientProvider>
  </React.StrictMode>,
)
