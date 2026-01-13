import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'

export default function Login(){
  const navigate = useNavigate()
  const [providers, setProviders] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  
  const [state, setState] = useState({
    step: 'email', // 'email' | 'otp'
    email: '',
    sending: false,
    otp: '',
    verifying: false,
    resendCooldown: 0,
    devOtp: '' as string | null,
    message: '' as string | null,
  })

  // Request list of oauth providers
  const fetchProviders = async ()=>{
    setError(null)
    try{
      const r = await api.get('/auth/providers')
      setProviders(r.data.providers || [])
    }catch(e:any){
      setProviders([])
      setError(e?.error?.detail || e?.message || 'Failed to reach server')
    }
  }

  useEffect(()=>{
    let t: any
    if(state.resendCooldown > 0){
      t = setInterval(()=> setState((s:any)=> ({...s, resendCooldown: Math.max(0, s.resendCooldown-1)})), 1000)
    }
    return ()=> clearInterval(t)
  },[state.resendCooldown])

  const requestOtp = async ()=>{
    setError(null)
    if(!state.email || !state.email.includes('@')){ setError('Please enter a valid email'); return }
    setState((s:any)=> ({...s, sending: true}))
    try{
      const r = await api.post('/auth/email/send-otp', { email: state.email })
      setState((s:any)=> ({...s, sending:false, step: 'otp', resendCooldown: 30, devOtp: r.data?.dev_otp || null, message: 'Verification code sent to your email.'}))
    }catch(e:any){
      setState((s:any)=> ({...s, sending:false}))
      const msg = e?.response?.data?.detail || e?.message || 'Failed to send OTP'
      setError(msg)
    }
  }

  const resendOtp = async ()=>{
    setError(null)
    if(state.resendCooldown > 0) return
    setState((s:any)=> ({...s, sending: true}))
    try{
      await api.post('/auth/email/send-otp', { email: state.email })
      setState((s:any)=> ({...s, sending:false, resendCooldown: 30, message: 'Verification code resent to your email.'}))
    }catch(e:any){
      setState((s:any)=> ({...s, sending:false}))
      setError(e?.response?.data?.detail || e?.message || 'Failed to send OTP')
    }
  }

  const verifyOtp = async ()=>{
    setError(null)
    if(!state.otp || state.otp.length < 4){ setError('Please enter the 6-digit code'); return }
    setState((s:any)=> ({...s, verifying: true}))
    try{
      const r = await api.post('/auth/email/verify', { email: state.email, otp: state.otp })
      // server sets cookie and returns redirect
      const redirect = r.data?.redirect
      if(redirect){ window.location.href = redirect }
      else { window.location.href = '/' }
    }catch(e:any){
      setState((s:any)=> ({...s, verifying:false}))
      setError(e?.response?.data?.detail || e?.message || 'Invalid or expired code')
    }
  }

  const changeEmail = ()=>{
    setError(null)
    setState((s:any)=> ({...s, step: 'email', otp: '', sending:false, verifying:false, resendCooldown:0}))
  }

  useEffect(()=>{ fetchProviders() },[])

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0b0e14] p-4 font-sans relative overflow-hidden">
        {/* Back button */}
        <button onClick={() => navigate(-1)} aria-label="Back" className="absolute top-6 left-4 md:top-8 md:left-8 flex items-center text-gray-400 hover:text-white transition-colors z-20">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" className="mr-2"><path d="M15 18l-6-6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
          <span className="text-sm font-medium">Back</span>
        </button>

        {/* Ambient background effects */}
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-[#5932ea]/10 rounded-full blur-[120px] pointer-events-none"></div>
        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-blue-600/10 rounded-full blur-[100px] pointer-events-none"></div>

      <div className="w-full max-w-5xl md:h-[600px] h-auto max-h-[92vh] bg-[#1e2330] rounded-[30px] overflow-auto shadow-2xl flex flex-col md:flex-row relative z-10">
        
        {/* Left Section: Login Form */}
        <div className="w-full md:w-1/2 p-6 md:p-12 flex flex-col justify-center relative bg-[#1e2330]">
            <div className="max-w-sm mx-auto w-full px-2">
                <h2 className="text-2xl md:text-3xl font-bold text-white mb-2">Welcome Back</h2>
                <p className="text-[#9197b3] mb-8">Log in to your security dashboard.</p>
                
                {/* Social Login Buttons */}
                <div className="space-y-3">
                  {providers.includes('google') && (
                    <button 
                      onClick={()=>{ window.location.href = '/auth/login/google' }} 
                      className="w-full py-3 px-4 bg-white hover:bg-gray-100 text-gray-900 rounded-xl flex items-center justify-center gap-3 transition-colors font-bold text-sm">
                      <div className="p-0.5 rounded-full"><svg width="18" height="18" viewBox="0 0 533.5 544.3"><path fill="#4285F4" d="M533.5 278.4c0-18.5-1.6-36.3-4.6-53.6H272v101.4h146.9c-6.3 34.1-25.2 63-53.6 82.2l86.5 67.1c50.4-46.6 81.7-115 81.7-196.9z"/><path fill="#34A853" d="M272 544.3c73.4 0 135.3-24.1 180.4-65.7l-87.7-68c-24.4 16.6-55.9 26-92.6 26-71 0-131.2-47.9-152.8-112.3H28.9v70.1c46.2 91.9 140.3 149.9 243.1 149.9z"/><path fill="#FBBC05" d="M119.3 324.3c-11.4-33.8-11.4-70.4 0-104.2V150H28.9c-38.6 76.9-38.6 167.5 0 244.4l90.4-70.1z"/><path fill="#EA4335" d="M272 107.7c38.8.6 76.3 14 104.4 37l78.7-78.7C403.7 20.6 339.4-4.5 272 0 169.2 0 75.1 58 28.9 150l90.4 70.1c21.5-64.5 81.8-112.4 152.7-112.4z"/></svg></div>
                      <span>Sign in with Google</span>
                    </button>
                  )}
                  {providers.includes('github') && (
                     <button 
                      onClick={()=>{ window.location.href = '/auth/login/github' }} 
                      aria-label="Sign in with GitHub"
                      className="w-full py-3 px-4 bg-[#0b0e14] hover:bg-black text-white rounded-xl flex items-center justify-center gap-3 transition-colors font-bold text-sm border border-gray-800">
                      <svg width="20" height="20" fill="currentColor" viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.2 1.87.86 2.33.66.07-.52.28-.86.51-1.06-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.34-.27 2.03-.27.69 0 1.39.09 2.03.27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
                      <span>Sign in with GitHub</span>
                    </button>
                  )}
                </div>

                {/* Divider */}
                <div className="relative my-8">
                    <div className="absolute inset-0 flex items-center">
                        <div className="w-full border-t border-gray-700"></div>
                    </div>
                    <div className="relative flex justify-center text-xs uppercase">
                        <span className="bg-[#1e2330] px-3 text-[#9197b3]">Or continue with email</span>
                    </div>
                </div>

                {/* Email Form / OTP Flow */}
                <div className="space-y-5">
                    {/** Step 1: Request OTP **/}
                    {state.step === 'email' && (
                      <div>
                        <label className="block text-xs font-bold text-[#9197b3] uppercase tracking-wide mb-2">Email address</label>
                        <input 
                            type="email" 
                            value={state.email}
                            onChange={(e)=>setState({...state, email: e.target.value})}
                            className="w-full bg-[#0b0e14] border border-transparent rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-[#5932ea] transition-all"
                            placeholder="name@company.com"
                        />
                        <div className="mt-4">
                          <button disabled={state.sending} onClick={requestOtp} className="w-full bg-[#5932ea] hover:bg-[#4a2bc2] text-white font-bold py-3 rounded-xl shadow-lg shadow-[#5932ea]/25 transition-all transform active:scale-95">
                              {state.sending ? 'Sending...' : 'Continue'}
                          </button>
                        </div>
                      </div>
                    )}

                    {/** Step 2: Enter OTP **/}
                    {state.step === 'otp' && (
                      <div>
                        <label className="block text-xs font-bold text-[#9197b3] uppercase tracking-wide mb-2">Enter Verification Code</label>
                        <input 
                            type="text" 
                            inputMode="numeric"
                            maxLength={6}
                            value={state.otp}
                            onChange={(e)=>setState({...state, otp: e.target.value.replace(/[^0-9]/g,'')})}
                            className="w-full bg-[#0b0e14] border border-transparent rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-[#5932ea] transition-all tracking-widest text-center text-lg md:text-lg text-base font-mono"
                            placeholder="000 000"
                        />
                        <div className="mt-4 flex gap-3">
                          <button disabled={state.verifying} onClick={verifyOtp} className="flex-1 bg-[#5932ea] hover:bg-[#4a2bc2] text-white font-bold py-3 rounded-xl shadow-lg shadow-[#5932ea]/25 transition-all transform active:scale-95">
                              {state.verifying ? 'Verifying...' : 'Verify Code'}
                          </button>
                          <button onClick={changeEmail} className="flex-none px-4 py-3 bg-[#0b0e14] hover:bg-black rounded-xl text-gray-400 font-medium transition-colors">Change</button>
                        </div>

                        <div className="mt-4 text-sm text-[#9197b3] flex items-center justify-between">
                          <button disabled={state.resendCooldown > 0 || state.sending} onClick={resendOtp} className={`hover:text-white transition-colors ${state.resendCooldown>0? 'opacity-50 cursor-not-allowed':''}`}>
                            {state.resendCooldown > 0 ? `Resend code in ${state.resendCooldown}s` : 'Resend code'}
                          </button>

                          {state.devOtp && (
                            <div className="px-2 py-1 text-xs bg-gray-800 rounded text-gray-400 font-mono">Dev: <span className="text-white">{state.devOtp}</span></div>
                          )}
                        </div>

                        {state.message && (
                          <div className="mt-3 text-sm text-green-400 text-center animate-pulse">{state.message}</div>
                        )}
                      </div>
                    )}
                </div>

                 {error && (
                  <div className="mt-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-200 text-sm flex items-center gap-3">
                    <svg className="w-5 h-5 shrink-0 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    <div>
                      {error} <span onClick={fetchProviders} className="underline cursor-pointer ml-1 hover:text-white">Retry</span>
                    </div>
                  </div>
                )}
            </div>
        </div>

        {/* Right Section: Visual */}
        <div className="hidden md:block w-1/2 relative bg-[#151925] overflow-hidden">
           {/* Abstract Shapes */}
           <div className="absolute top-0 right-0 w-full h-full bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 opacity-mix-blend-overlay"></div>
           <div className="absolute -top-24 -right-24 w-96 h-96 bg-[#5932ea] rounded-full blur-[128px] opacity-40"></div>
           <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-blue-600 rounded-full blur-[100px] opacity-20"></div>
           
           {/* Content Overlay */}
           <div className="absolute inset-0 z-10 p-12 flex flex-col justify-end pointer-events-none">
             <div className="mb-8">
                <div className="w-12 h-12 bg-[#5932ea] rounded-xl flex items-center justify-center mb-6 shadow-lg shadow-[#5932ea]/30">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                </div>
                <h3 className="text-3xl font-bold text-white mb-4 leading-tight">Secure your codebase <br/>with <span className="text-[#5932ea]">Intelligent Analysis</span></h3>
                <p className="text-[#9197b3] leading-relaxed max-w-sm text-lg">
                    Detect vulnerabilities, secrets, and compliance issues before they reach production.
                </p>
             </div>
           </div>
        </div>

      </div>
    </div>
  )
}
