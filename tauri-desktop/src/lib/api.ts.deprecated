import axios from 'axios'
import { useAuthStore } from '../stores/authStore'

// URL de base de l'API
// @ts-ignore - Vite env variables
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1'

// Instance axios configurée
export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
})

// Intercepteur pour ajouter le token d'authentification
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().accessToken
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Intercepteur pour gérer le refresh token
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // Si l'erreur est 401 et qu'on n'a pas déjà essayé de refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      const refreshToken = useAuthStore.getState().refreshToken
      if (refreshToken) {
        try {
          const response = await axios.post(
            `${API_BASE_URL}/auth/refresh`,
            { refresh_token: refreshToken }
          )

          const { access_token } = response.data
          useAuthStore.getState().updateAccessToken(access_token)

          // Réessayer la requête originale avec le nouveau token
          originalRequest.headers.Authorization = `Bearer ${access_token}`
          return api(originalRequest)
        } catch (refreshError) {
          // Si le refresh échoue, déconnecter l'utilisateur
          useAuthStore.getState().clearAuth()
          window.location.href = '/login'
          return Promise.reject(refreshError)
        }
      }
    }

    return Promise.reject(error)
  }
)

// Types pour les requêtes
export interface RegisterRequest {
  username: string
  email: string
  password: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  user: {
    id: string
    username: string
    email: string
  }
  access_token: string
  refresh_token: string
}

export interface Password {
  id: string
  user_id: string
  title: string
  username: string
  password: string
  url?: string
  notes?: string
  category?: string
  created_at: string
  updated_at: string
}

export interface CreatePasswordRequest {
  title: string
  username: string
  password: string
  url?: string
  notes?: string
  category?: string
}

export interface File {
  id: string
  user_id: string
  name: string
  size: number
  mime_type: string
  encrypted_path: string
  created_at: string
}

// API Functions
export const authAPI = {
  register: (data: RegisterRequest) => 
    api.post<LoginResponse>('/auth/register', data),
  
  login: (data: LoginRequest) => 
    api.post<LoginResponse>('/auth/login', data),
  
  refresh: (refreshToken: string) =>
    api.post<{ access_token: string }>('/auth/refresh', { refresh_token: refreshToken }),
}

export const passwordsAPI = {
  getAll: () => 
    api.get<Password[]>('/passwords'),
  
  getById: (id: string) => 
    api.get<Password>(`/passwords/${id}`),
  
  create: (data: CreatePasswordRequest) => 
    api.post<Password>('/passwords', data),
  
  update: (id: string, data: Partial<CreatePasswordRequest>) => 
    api.put<Password>(`/passwords/${id}`, data),
  
  delete: (id: string) => 
    api.delete(`/passwords/${id}`),
}

export const filesAPI = {
  getAll: () => 
    api.get<File[]>('/files'),
  
  upload: (file: FormData) => 
    api.post<File>('/files', file, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  
  download: (id: string) => 
    api.get(`/files/${id}`, { responseType: 'blob' }),
  
  delete: (id: string) => 
    api.delete(`/files/${id}`),
}

export const securityAPI = {
  getActivity: () => 
    api.get('/audit/activity'),
  
  getSecurityEvents: () => 
    api.get('/audit/security-events'),
  
  analyzeBehavior: (activity: any) =>
    axios.post('http://localhost:8000/analyze/behavior', activity),
  
  detectAnomalies: (activity: any) =>
    axios.post('http://localhost:8000/analyze/anomaly', activity),
  
  detectRansomware: (events: any[]) =>
    axios.post('http://localhost:8000/analyze/ransomware', { events }),
}
