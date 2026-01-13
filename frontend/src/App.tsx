import { Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import api from './api'
import Health from './pages/Health'
import Analyze from './pages/Analyze'
import Login from './pages/Login'
import AuthCallback from './pages/AuthCallback'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'

// Layout Icons
const Icons = {
  Dashboard: <path d="M3 13h1m-1-4h1m-1-4h1m4 10h12a1 1 0 001-1V5a1 1 0 00-1-1H7a1 1 0 00-1 1v10a1 1 0 001 1zM7 5h12v10H7V5z" strokeLinecap="round" strokeLinejoin="round" />,
  Product: <path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" strokeLinecap="round" strokeLinejoin="round" />,
  Customers: <path d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" strokeLinecap="round" strokeLinejoin="round" />,
  Income: <path d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" />,
  Promote: <path d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6 3 3 0 000 6zM5 19a2 2 0 012-2h6a2 2 0 012 2v1H5v-1z" strokeLinecap="round" strokeLinejoin="round" />,
  Help: <path d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" />,
  ChevronRight: <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
}

export default function App() {
  const location = useLocation()
  const isAuthPage = location.pathname === '/login' || location.pathname.startsWith('/auth-')
  const [user, setUser] = useState<any>(null)
  const navigate = useNavigate()

  useEffect(()=>{
     api.get('/auth/me').then(r => setUser(r.data.user)).catch(()=> setUser(null))
  }, [location.pathname])

  const menuItems = [
    { name: 'Dashboard', path: '/'},
    { name: 'Analyze Code', path: '/run-analysis'}, // "Product" in template
    { name: 'Scan History', path: '/scans'}, // "Customers" in template
    
  ]

  const NavItem = ({ item }: { item: any }) => {
    const isActive = location.pathname === item.path
    // Figma style: Active state has a solid violet/purple gradient background with white text.
    // Inactive is gray text, transparent bg.
    return (
      <Link 
        to={item.path}
        className={`flex items-center justify-between px-4 py-3 mb-2 rounded-xl transition-all duration-200 group ${
          isActive 
            ? 'bg-gradient-to-r from-[#5932ea] to-[#4e2cd3] text-white shadow-lg shadow-[#5932ea]/30' 
            : 'text-[#9197b3] hover:bg-[#5932ea]/10 hover:text-[#5932ea]'
        }`}
      >
        <div className="flex items-center gap-4">
           {/* Icon Render */}
           <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={`${isActive ? 'stroke-white' : 'stroke-[#9197b3] group-hover:stroke-[#5932ea]'}`}>
             {Icons[item.icon as keyof typeof Icons]}
           </svg>
           <span className="font-medium">{item.name}</span>
        </div>
        {/* Chevron only on inactive or specific design choice, figma shows chevron on sidebar items often */}
        <div className={isActive ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}>
          <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
             <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </div>
      </Link>
    )
  }

  return (
    <div className="min-h-screen bg-[#0b0e14] font-sans flex overflow-hidden">
      {!isAuthPage && (
        <aside className="w-[306px] h-screen bg-[#111620] flex flex-col pt-9 pb-6 px-7 border-r border-[#1e2330] fixed left-0 top-0 z-50 transition-all duration-300 transform -translate-x-full md:translate-x-0">
           {/* Logo Section */}
           <div className="flex items-center gap-3 mb-14 px-2">
              <img src="/logo-header.svg" alt="SAST" className="h-9" />
           </div>

           {/* Navigation */}
           <div className="flex-1 overflow-y-auto no-scrollbar">
              {menuItems.map((item, idx) => (
                 <NavItem key={idx} item={item} />
              ))}
           </div>

           {/* Pro Banner - Figma Style with gradient */}
           <div className="mt-6 mb-8 rounded-2xl p-6 text-center relative overflow-hidden group hover:scale-[1.02] transition-transform">
              <div className="absolute inset-0 bg-gradient-to-br from-[#ea4869] to-[#8651f5] opacity-90"></div>
              <div className="relative z-10 text-white">
                 <div className="text-lg font-bold mb-1">Upgrade to PRO</div>
                 <p className="text-xs text-white/80 mb-4 px-2">Get access to all advanced security rules!</p>
                 <button onClick={()=>navigate('/run-analysis')} className="bg-white text-[#5932ea] text-xs font-bold px-5 py-2.5 rounded-full shadow-lg hover:bg-gray-50 transition-colors uppercase tracking-wide">
                    Get Pro Now!
                 </button>
              </div>
           </div>

           {/* User Profile */}
           <div className="flex items-center gap-3 mt-auto pt-4 border-t border-[#1e2330]">
              {user ? (
                 <>
                   <div className="w-10 h-10 rounded-full bg-slate-700 overflow-hidden border-2 border-[#1e2330]">
                     <img src={`https://ui-avatars.com/api/?name=${user.name||user.email}&background=random`} alt="User" />
                   </div>
                   <div className="flex-1 min-w-0">
                     <div className="text-sm font-bold text-white truncate">{user.name || 'User'}</div>
                     <div className="text-xs text-[#9197b3] truncate">Project Manager</div>
                   </div>
                   <button onClick={async()=>{ await api.post('/auth/logout'); setUser(null); navigate('/') }} className="text-[#9197b3] hover:text-white">
                     <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
                   </button>
                 </>
              ) : (
                 <Link to="/login" className="flex items-center gap-3 w-full p-2 hover:bg-[#5932ea]/10 rounded-lg group text-[#9197b3] hover:text-[#5932ea] transition-colors">
                    <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700">
                       <svg width="20" height="20" stroke="currentColor" fill="none" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
                    </div>
                    <div>
                       <div className="text-sm font-bold group-hover:text-white transition-colors">Sign In</div>
                       <div className="text-xs">Access Dashboard</div>
                    </div>
                 </Link>
              )}
           </div>
        </aside>
      )}

      {/* Main Content Area */}
      <main className={`flex-1 relative ${isAuthPage ? '' : 'md:ml-[306px]'} overflow-x-hidden bg-[#0b0e14]`}>
         {/* Background glow effects for "best dark theme" vibe */}
         {!isAuthPage && (
           <div className="absolute top-[-200px] right-[-200px] w-[600px] h-[600px] bg-purple-900/10 rounded-full blur-[120px] pointer-events-none"></div>
         )}

         <div className={`${isAuthPage ? '' : 'p-10'} min-h-full`}>
            <Routes>
              <Route path="/" element={<Health />} />
              <Route path="/run-analysis" element={<Analyze />} />
              <Route path="/login" element={<Login />} />
              <Route path="/auth-callback" element={<AuthCallback />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scans/:id" element={<ScanDetail />} />
            </Routes>
         </div>
      </main>
    </div>
  )
}
