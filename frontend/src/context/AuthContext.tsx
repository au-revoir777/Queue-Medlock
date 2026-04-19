import { createContext, useContext, useState, ReactNode } from 'react'

export interface Identity {
  hospital_id: string
  staff_id:    string
  department:  string
  role:        string
}

interface AuthContextType {
  token:    string | null
  identity: Identity | null
  login:    (token: string, identity: Identity) => void
  logout:   () => void
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(
    sessionStorage.getItem('token')
  )
  const [identity, setIdentity] = useState<Identity | null>(() => {
    const stored = sessionStorage.getItem('identity')
    return stored ? JSON.parse(stored) : null
  })

  function login(tok: string, id: Identity) {
    setToken(tok)
    setIdentity(id)
    sessionStorage.setItem('token', tok)
    sessionStorage.setItem('identity', JSON.stringify(id))
  }

  function logout() {
    setToken(null)
    setIdentity(null)
    sessionStorage.clear()
  }

  return (
    <AuthContext.Provider value={{ token, identity, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
