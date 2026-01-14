import { useEffect, useState } from 'react'
import api from '../api'
import { Link } from 'react-router-dom'
import GlobalLoader from '../components/GlobalLoader'

export default function Scans() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')

  const fetch = async () => {
    setLoading(true)
    try {
      const r = await api.get('/scans')
      setScans(r.data || [])
    } catch (e: any) { console.error(e); setScans([]) }
    setLoading(false)
  }

  useEffect(() => { fetch() }, [])

  const getProjectName = (scan: any) => {
    if (scan.project_name) return scan.project_name
    const path = scan.project_path || ''
    if (path.startsWith('db://')) return 'Cloud Project'
    const normalized = path.replace(/\\/g, '/')
    const parts = normalized.split('/')
    return parts[parts.length - 1] || 'Project'
  }

  // Filter
  const filtered = scans.filter(s => {
    const name = getProjectName(s).toLowerCase()
    const query = searchTerm.toLowerCase()
    return name.includes(query) || s.project_path.toLowerCase().includes(query)
  })

  return (
    <div className="font-sans text-[#292D32]">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-8 md:mb-10 gap-6">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-white mb-2">Scan History</h1>
          <p className="text-[#9197b3] text-sm md:text-base">Comprehensive archive of all your security analyses.</p>
        </div>
        <div className="flex gap-3 md:gap-4 w-full md:w-auto">
          <div className="relative flex-1 md:flex-none">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search history..."
              className="w-full md:w-64 bg-[#1e2330] text-white pl-10 pr-4 py-2.5 rounded-xl border border-[#2d3748] focus:outline-none focus:border-[#5932ea] shadow-sm placeholder-[#9197b3] transition-all"
            />
            <svg className="w-5 h-5 text-[#9197b3] absolute left-3 top-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
          </div>
          <button onClick={fetch} className="px-4 py-2.5 bg-[#1e2330] hover:bg-[#2d3748] text-white rounded-xl border border-[#2d3748] transition-colors flex items-center justify-center gap-2 font-medium shadow-sm">
            <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
          </button>
        </div>
      </div>

      {loading && (
        <div className="py-20 flex justify-center">
          <GlobalLoader />
        </div>
      )}

      {!loading && scans.length === 0 && (
        <div className="text-center py-20 bg-[#1e2330] rounded-[30px] border border-[#2d3748]">
          <p className="text-[#9197b3] mb-4">No scan history available.</p>
          <Link to="/analyze" className="text-[#5932ea] hover:underline font-bold">Start your first scan</Link>
        </div>
      )}

      {/* Table View */}
      {!loading && scans.length > 0 && (
        <div className="bg-[#1e2330] rounded-[30px] border border-[#2d3748] p-8 shadow-xl">
          <div className="hidden md:block overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#2d3748]">
                  <th className="py-4 text-[#9197b3] font-medium text-sm">Project Path</th>
                  <th className="py-4 text-[#9197b3] font-medium text-sm">Target</th>
                  <th className="py-4 text-[#9197b3] font-medium text-sm">Status</th>
                  <th className="py-4 text-[#9197b3] font-medium text-sm">Findings</th>
                  <th className="py-4 text-[#9197b3] font-medium text-sm">Date</th>
                  <th className="py-4 text-[#9197b3] font-medium text-sm text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2d3748]">
                {filtered.map(s => (
                  <tr key={s.id} className="group hover:bg-[#2d3748]/30 transition-colors">
                    <td className="py-5 text-white font-bold">
                      {/* Truncate project name if too long */}
                      <div className="truncate max-w-[200px]" title={getProjectName(s)}>
                        {getProjectName(s)}
                      </div>
                    </td>
                    <td className="py-5 text-[#9197b3] text-sm truncate max-w-[150px]" title={s.project_path}>
                      {/* Only show path if hovered, keep it clean otherwise. Or hide entirely if sensitive/ugly */}
                      <span className="opacity-50 hover:opacity-100 transition-opacity cursor-help">{s.project_path.substring(0, 20)}...</span>
                    </td>
                    <td className="py-5">
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded border border-[#00ac56] text-[#00ac56] text-xs font-bold bg-[#00ac56]/10">
                        Completed
                      </span>
                    </td>
                    <td className="py-5">
                      {s.total_findings === 0 ? (
                        <span className="text-[#00ac56] font-bold text-sm">Secure</span>
                      ) : (
                        <span className="text-[#d0004b] font-bold text-sm">{s.total_findings} Issues</span>
                      )}
                    </td>
                    <td className="py-5 text-[#9197b3] text-sm">
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-5 text-right">
                      <Link to={`/scans/${s.id}`} className="px-4 py-2 bg-[#5932ea]/10 text-[#5932ea] hover:bg-[#5932ea] hover:text-white rounded-lg font-bold text-xs transition-all">
                        View Report
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile list view */}
          <div className="md:hidden space-y-5">
            {filtered.map(s => (
              <div key={s.id} className="bg-[#1e2330] p-5 rounded-2xl border border-[#2d3748] shadow-lg flex flex-col gap-4 relative overflow-hidden group">
                {/* Decorative gradient blob */}
                <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-[#5932ea]/20 to-transparent rounded-bl-full -mr-4 -mt-4 opacity-50"></div>

                <div className="flex justify-between items-start gap-4 z-10">
                  <div className="overflow-hidden">
                    <h3 className="text-white font-bold text-lg truncate pr-2">{getProjectName(s)}</h3>
                    <div className="flex items-center gap-1.5 text-[#9197b3] text-xs mt-1">
                      <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" /></svg>
                      <p className="truncate opacity-80">{s.project_path}</p>
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

          {/* Pagination Footer (Static for now) */}
          <div className="mt-8 flex items-center justify-between text-[#9197b3] text-sm">
            <div>Showing {filtered.length} entries</div>
            <div className="flex items-center gap-2">
              <button className="w-8 h-8 rounded bg-[#2d3748] flex items-center justify-center hover:bg-[#5932ea] hover:text-white transition-colors">&lt;</button>
              <button className="w-8 h-8 rounded bg-[#5932ea] text-white flex items-center justify-center font-bold">1</button>
              <button className="w-8 h-8 rounded bg-[#2d3748] flex items-center justify-center hover:bg-[#5932ea] hover:text-white transition-colors">&gt;</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
