import React, { useEffect, useState } from 'react'
import api from '../api'
import { Link, useNavigate, useLocation } from 'react-router-dom'

export default function AuthHeader(){
  const [user, setUser] = useState<any>(null)
  const nav = useNavigate()
  const loc = useLocation()

  useEffect(()=>{
    (async()=>{
      try{
        const r = await api.get('/auth/me')
        setUser(r.data.user)
      }catch(e){
        setUser(null)
      }
    })()
  },[])

  const logout = async ()=>{
    try{
      await api.post('/auth/logout')
    }catch(e){ /* ignore */ }
    setUser(null)
    nav('/')
  }

  // Hide the sign-in button when already on the auth/login page
  if(!user && loc.pathname === '/login'){
    return null
  }

  if(!user){
    return (
      <div className="flex items-center gap-3">
        <Link to="/login" className="btn-neon px-3 py-2">Sign in</Link>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-3">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-full bg-[#0b1020] border border-gray-700 grid place-items-center text-sm">{(user.name||user.email||user.id||'U')[0].toUpperCase()}</div>
        <div className="text-sm">
          <div className="font-semibold">{user.name || user.email}</div>
          <div className="text-xs muted">{user.provider || 'oauth'}</div>
        </div>
      </div>
      <button onClick={logout} className="px-3 py-2 bg-transparent border border-gray-700 rounded muted">Logout</button>
    </div>
  )
}