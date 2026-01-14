import { useEffect, useState } from 'react'
import api from '../api'
import { useNavigate } from 'react-router-dom'
import GlobalLoader from '../components/GlobalLoader'

export default function AuthCallback(){
  const [status, setStatus] = useState('Checking...')
  const nav = useNavigate()
  
  useEffect(()=>{
    (async()=>{
      try{
        const r = await api.get('/auth/me')
        const name = r.data.user.email || r.data.user.name || r.data.user.id
        setStatus('Welcome back, ' + name)
        
        // Check for pending redirect
        const returnTo = localStorage.getItem('sast_post_auth_redirect')
        localStorage.removeItem('sast_post_auth_redirect')
        
        setTimeout(()=>nav(returnTo || '/'), 900)
      }catch(e:any){
        setStatus('Authentication failed — please try again.')
        console.error('Auth callback error', e)
        setTimeout(()=>nav('/login'), 2000)
      }
    })()
  },[])

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0b0e14]">
      <div className="bg-[#1e2330] p-12 rounded-[30px] shadow-2xl text-center max-w-md w-full border border-[#1e2330]">
        
        <div className="flex justify-center mb-8">
           <GlobalLoader size="large" />
        </div>

        <h1 className="text-2xl font-bold text-white mb-2">Authenticating</h1>
        <p className="text-[#9197b3] text-lg mb-8">{status}</p>

        <p className="mt-8 text-sm text-[#9197b3]/60">Verifying credentials...</p>
      </div>
    </div>
  )
}
