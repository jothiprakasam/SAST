import api from '../api'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import GlobalLoader from '../components/GlobalLoader'

export default function Home() {
  const [user, setUser] = useState<any>(null)
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [sortOption, setSortOption] = useState('newest')
  const [page, setPage] = useState(1)
  const pageSize = 10

  const fetchUser = async ()=>{
    try{
      const r = await api.get('/auth/me')
      setUser(r.data.user)
    }catch(e:any){ setUser(null); setLoading(false) }
  }

  const fetchScans = async ()=>{
    setLoading(true)
    try{
      const r = await api.get('/scans')
      setScans(r.data || [])
    }catch(e:any){ console.error('Failed to fetch scans') }
    setLoading(false)
  }

  useEffect(()=>{ fetchUser() }, [])
  useEffect(()=>{ if(user) fetchScans() }, [user])

  // --- Helpers ---
  const getProjectName = (scan: any) => {
      if (scan.project_name) return scan.project_name
      // Handle db:// paths fallback
      const path = scan.project_path || ''
      if(path.startsWith('db://')) return 'Cloud Project'
      
      // Handle both slash types
      const normalized = path.replace(/\\/g, '/')
      const parts = normalized.split('/')
      return parts[parts.length - 1] || 'Project'
  }

  // --- Filtered Data ---
  const filteredScans = scans.filter(s => {
     const name = getProjectName(s).toLowerCase()
     const query = searchTerm.toLowerCase()
     return name.includes(query) || s.project_path.toLowerCase().includes(query)
  }).sort((a, b) => {
     if (sortOption === 'newest') return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
     if (sortOption === 'oldest') return new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
     if (sortOption === 'findings-high') return (b.total_findings||0) - (a.total_findings||0)
     if (sortOption === 'findings-low') return (a.total_findings||0) - (b.total_findings||0)
     if (sortOption === 'name-asc') return getProjectName(a).localeCompare(getProjectName(b))
     if (sortOption === 'name-desc') return getProjectName(b).localeCompare(getProjectName(a))
     return 0
  })

  // --- Pagination ---
  const pageCount = Math.max(1, Math.ceil(filteredScans.length / pageSize))

  // Ensure page is within bounds when results change
  useEffect(()=>{ if(page > pageCount) setPage(pageCount) }, [pageCount])
  useEffect(()=>{ setPage(1) }, [searchTerm])

  const startIndex = (page - 1) * pageSize
  const endIndex = Math.min(startIndex + pageSize, filteredScans.length)
  const pageItems = filteredScans.slice(startIndex, endIndex)
  const startEntry = filteredScans.length === 0 ? 0 : startIndex + 1
  const endEntry = endIndex

  const totalFindings = scans.reduce((acc,s)=> acc + (s.total_findings||0), 0)

  // --- Render: Loading ---
  if(loading){
      return (
         <div className="min-h-[80vh] flex items-center justify-center">
            <GlobalLoader />
         </div>
      )
  }

  // --- Render: Unauthenticated / Landing ---
  if(!user){
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center text-center p-8">
        <div className="max-w-2xl">
          <h1 className="text-5xl font-extrabold text-white mb-6">
            Secure Your Codebase
          </h1>
          <p className="text-xl text-[#9197b3] mb-10 leading-relaxed">
            Advanced static analysis engine that scans your source code for vulnerabilities, 
            secrets, and security flaws instantly.
          </p>
          <div className="flex gap-4 justify-center">
             <Link to="/login" className="px-8 py-3 bg-[#5932ea] hover:bg-[#4a2bc2] text-white rounded-full font-bold transition-all shadow-lg hover:shadow-[#5932ea]/40">
               Get Started
             </Link>
          </div>
        </div>
      </div>
    )
  }

  // --- Render: Dashboard (Figma Template Style) ---
  return (
    <div className="font-sans text-[#292D32]">
      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-10 gap-6">
         <div>
            <h1 className="text-2xl font-bold text-white mb-1">Hello {user?.name?.split(' ')[0] || 'User'} 👋,</h1>
            <p className="text-[#9197b3] text-sm">Welcome back to your security dashboard</p>
         </div>
         {/* <div className="relative">
            <input 
              type="text" 
              placeholder="Search..." 
              className="bg-[#1e2330] text-white pl-10 pr-4 py-2.5 rounded-xl border border-[#2d3748] focus:outline-none focus:border-[#5932ea] w-64 shadow-sm placeholder-[#9197b3]" 
            />
            <svg className="w-5 h-5 text-[#9197b3] absolute left-3 top-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
         </div> */}
      </div>

      {/* Stats Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
         {/* Card 1: Total Scans */}
         <div className="bg-[#1e2330] p-8 rounded-[30px] flex items-center gap-6 shadow-xl border border-[#2d3748]">
            <div className="w-20 h-20 rounded-full bg-[#00ac56]/10 flex items-center justify-center shrink-0">
               <svg className="w-10 h-10 text-[#00ac56]" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
            </div>
            <div>
               <div className="text-[#9197b3] text-sm mb-1">Total Scans</div>
               <div className="text-3xl font-bold text-white mb-1">{scans.length}</div>
               {/* <div className="flex items-center text-xs">
                  <span className="text-[#00ac56] font-bold flex items-center mr-1">
                    <svg className="w-3 h-3 mr-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 10l7-7m0 0l7 7m-7-7v18" /></svg>
                    16%
                  </span>
                  <span className="text-[#9197b3]">this month</span>
               </div> */}
            </div>
         </div>

         {/* Card 2: Total Findings */}
         <div className="bg-[#1e2330] p-8 rounded-[30px] flex items-center gap-6 shadow-xl border border-[#2d3748]">
            <div className="w-20 h-20 rounded-full bg-[#5932ea]/10 flex items-center justify-center shrink-0">
               <svg className="w-10 h-10 text-[#5932ea]" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
            </div>
            <div>
               <div className="text-[#9197b3] text-sm mb-1">Total Vulnerabilities</div>
               <div className="text-3xl font-bold text-white mb-1">{totalFindings}</div>
               {/* <div className="flex items-center text-xs">
                  <span className="text-[#d0004b] font-bold flex items-center mr-1">
                    <svg className="w-3 h-3 mr-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M19 14l-7 7m0 0l-7-7m7 7V3" /></svg>
                    2%
                  </span>
                  <span className="text-[#9197b3]">this month</span>
               </div> */}
            </div>
         </div>

         {/* Card 3: Active Now */}
        
      </div>

      {/* Main Table Section: "All Scans" */}
      <div className="bg-[#1e2330] rounded-[30px] p-8 shadow-xl border border-[#2d3748]">
         {/* Table Header */}
         <div className="flex flex-col md:flex-row md:items-center justify-between mb-8 gap-4">
            <div>
               <h2 className="text-xl font-bold text-white">All Scans</h2>
               
            </div>
            <div className="flex gap-4 flex-col md:flex-row md:items-center">
               <div className="relative w-full md:w-auto">
                  <input 
                    type="text" 
                    value={searchTerm}
                    onChange={(e)=>setSearchTerm(e.target.value)}
                    placeholder="Search" 
                    className="bg-[#2d3748] text-white pl-10 pr-4 py-2 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-[#5932ea] placeholder-[#9197b3] w-full md:w-64" 
                  />
                  <svg className="w-4 h-4 text-[#9197b3] absolute left-3 top-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
               </div>

               {/* Desktop dropdown */}
               <div className="hidden md:block bg-[#2d3748] px-4 py-2 rounded-xl text-sm text-[#9197b3] flex items-center gap-2 cursor-pointer relative group">
                  <span className="flex items-center gap-1">
                      Sort by: <span className="text-white font-bold">{sortOption.replace('-', ' ')}</span>
                  </span>
                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
                  
                  {/* Dropdown */}
                  <div className="absolute top-full right-0 mt-2 w-48 bg-[#1e2330] border border-[#2d3748] rounded-xl shadow-xl overflow-hidden hidden group-hover:block z-20">
                      {[
                          { label: 'Newest', value: 'newest' },
                          { label: 'Oldest', value: 'oldest' },
                          { label: 'Most Findings', value: 'findings-high' },
                          { label: 'Fewest Findings', value: 'findings-low' },
                          { label: 'Name (A-Z)', value: 'name-asc' },
                          { label: 'Name (Z-A)', value: 'name-desc' },
                      ].map(opt => (
                          <div 
                             key={opt.value}
                             onClick={()=>setSortOption(opt.value)}
                             className={`px-4 py-3 hover:bg-[#2d3748] text-white cursor-pointer ${sortOption === opt.value ? 'bg-[#2d3748]/50 text-[#5932ea]' : ''}`}
                          >
                             {opt.label}
                          </div>
                      ))}
                  </div>
               </div>

               {/* Mobile native select - avoids hover/overflow issues */}
               <select value={sortOption} onChange={(e)=>setSortOption(e.target.value)} className="md:hidden bg-[#2d3748] px-3 py-2 rounded-xl text-sm text-white w-full">
                  <option value="newest">Newest</option>
                  <option value="oldest">Oldest</option>
                  <option value="findings-high">Most Findings</option>
                  <option value="findings-low">Fewest Findings</option>
                  <option value="name-asc">Name (A-Z)</option>
                  <option value="name-desc">Name (Z-A)</option>
               </select>
            </div>
         </div>

         {/* Table (Desktop) */}
         <div className="hidden md:block overflow-x-auto">
            <table className="w-full text-left border-collapse">
               <thead>
                  <tr className="border-b border-[#2d3748]">
                     <th className="py-4 text-[#9197b3] font-medium text-sm">Project Name</th>
                     <th className="py-4 text-[#9197b3] font-medium text-sm">Engine</th>
                     <th className="py-4 text-[#9197b3] font-medium text-sm">Findings</th>
                     <th className="py-4 text-[#9197b3] font-medium text-sm text-center">Date</th>
                     <th className="py-4 text-[#9197b3] font-medium text-sm text-center">Status</th>
                  </tr>
               </thead>
               <tbody className="divide-y divide-[#2d3748]">
                  {filteredScans.length === 0 && (
                     <tr><td colSpan={6} className="py-8 text-center text-[#9197b3]">No scans found matching your search.</td></tr>
                  )}
                  {pageItems.map(s => (
                     <tr key={s.id} className="group hover:bg-[#2d3748]/30 transition-colors">
                        <td className="py-5 font-medium text-white">
                           <div className="flex flex-col">
                              {/* Truncate long project names */}
                              <span className="text-sm font-bold truncate max-w-[200px]" title={getProjectName(s)}>
                                 {getProjectName(s)}
                              </span>
                           </div>
                        </td>
                        <td className="py-5 text-white">SAST Core</td>
                        <td className="py-5 text-white">
                           {s.total_findings > 0 
                              ? <span className="text-orange-400 font-bold">{s.total_findings} issues</span> 
                              : <span className="text-green-400">Secure</span>}
                        </td>
                        <td className="py-5 text-center text-[#9197b3] text-sm">
                           {new Date(s.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-5 text-center">
                           <Link to={`/scans/${s.id}`} className={`px-5 py-1.5 rounded border font-medium text-sm inline-block min-w-[80px] hover:opacity-80 transition-opacity ${
                              s.total_findings === 0 
                                 ? 'bg-[#00ac56]/20 text-[#00ac56] border-[#00ac56]' 
                                 : 'bg-[#d0004b]/20 text-[#d0004b] border-[#d0004b]'
                           }`}>
                              {s.total_findings === 0 ? 'Active' : 'Critical'}
                           </Link>
                        </td>
                     </tr>
                  ))}
               </tbody>
            </table>
         </div>

         {/* Mobile List View */}
         <div className="md:hidden space-y-5">
             {filteredScans.length === 0 && (
                 <div className="py-8 text-center text-[#9197b3]">No scans found matching your search.</div>
             )}
             {pageItems.map(s => (
               <div key={s.id} className="bg-[#1e2330] p-5 rounded-2xl border border-[#2d3748] shadow-lg flex flex-col gap-4 relative overflow-hidden group">
                  {/* Decorative gradient blob */}
                  <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-[#5932ea]/20 to-transparent rounded-bl-full -mr-4 -mt-4 opacity-50"></div>

                  <div className="flex justify-between items-start gap-4 z-10">
                     <div className="overflow-hidden">
                        <h3 className="text-white font-bold text-lg truncate pr-2">{getProjectName(s)}</h3>
                        <div className="flex items-center gap-1.5 text-[#9197b3] text-xs mt-1">
                           <span className="opacity-80">SAST Core</span>
                        </div>
                     </div>
                     <div className={`flex-shrink-0 px-2.5 py-1 rounded-md text-[10px] uppercase font-bold tracking-wider ${s.total_findings === 0 ? 'bg-green-500/10 text-green-500 border border-green-500/20' : 'bg-red-500/10 text-red-500 border border-red-500/20'}`}>
                        {s.total_findings === 0 ? 'Secure' : 'Issues'}
                     </div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4 border-t border-[#2d3748] pt-4 mt-1 z-10">
                     <div className="flex flex-col">
                        <span className="text-[#9197b3] text-[10px] uppercase tracking-wider mb-1 font-semibold">Findings</span>
                        <div className="flex items-baseline gap-1.5">
                           <span className={`text-xl font-bold ${s.total_findings > 0 ? 'text-white' : 'text-green-400'}`}>{s.total_findings}</span>
                           <span className="text-[#9197b3] text-xs">Detected</span>
                        </div>
                     </div>
                      <div className="flex flex-col text-right">
                        <span className="text-[#9197b3] text-[10px] uppercase tracking-wider mb-1 font-semibold">Date</span>
                        <span className="text-white font-medium text-sm">{new Date(s.created_at).toLocaleDateString()}</span>
                     </div>
                  </div>

                  <div className="z-10 mt-1">
                     <Link to={`/scans/${s.id}`} className="block w-full text-center bg-[#5932ea] hover:bg-[#4e2cd3] active:scale-[0.98] text-white py-3 rounded-xl font-semibold text-sm transition-all shadow-lg shadow-[#5932ea]/20">
                        View Detailed Report
                     </Link>
                  </div>
               </div>
             ))}
         </div>

         {/* Pagination Footer */}
         <div className="mt-8 flex flex-col md:flex-row items-center justify-between text-[#9197b3] text-sm gap-4">
            <div>Showing data {startEntry} to {endEntry} of {filteredScans.length} entries</div>
            <div className="flex items-center gap-2">
               <button onClick={() => setPage(p => Math.max(1, p - 1))} className="w-8 h-8 rounded bg-[#2d3748] flex items-center justify-center hover:bg-[#5932ea] hover:text-white transition-colors">&lt;</button>

               {Array.from({ length: pageCount }).map((_, i) => (
                  <button key={i} onClick={() => setPage(i + 1)} className={`w-8 h-8 rounded flex items-center justify-center ${page === i + 1 ? 'bg-[#5932ea] text-white font-bold' : 'bg-[#2d3748] hover:bg-[#5932ea] hover:text-white transition-colors'}`}>
                     {i + 1}
                  </button>
               ))}

               <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} className="w-8 h-8 rounded bg-[#2d3748] flex items-center justify-center hover:bg-[#5932ea] hover:text-white transition-colors">&gt;</button>
            </div>
         </div>
      </div>
    </div>
  )
}
