import { useEffect, useState } from 'react'
import api from '../api'
import { useParams, Link } from 'react-router-dom'
import ScanLoader from '../components/ScanLoader'

export default function ScanDetail(){
  const { id } = useParams()
  const [scan, setScan] = useState<any>(null)
  const [files, setFiles] = useState<any[]>([])
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [fileDetails, setFileDetails] = useState<any>(null)
  const [loadingFile, setLoadingFile] = useState<boolean>(false)
  const [showFull, setShowFull] = useState<boolean>(false)

  const fetchScan = async ()=>{
    try{
      const r = await api.get(`/scans/${id}`)
      setScan(r.data)
    }catch(e:any){ console.error(e) }
  }
  const fetchFiles = async ()=>{
    try{
      const r = await api.get(`/scans/${id}/files`)
      setFiles(r.data)
    }catch(e:any){ console.error(e) }
  }
  const fetchFileDetails = async (p: string)=>{
    setSelectedFile(p)
    setShowFull(false)
    setFileDetails(null)
    setLoadingFile(true)
    try{
      const r = await api.get(`/scans/${id}/files/details`, { params: { file_path: p } })
      setTimeout(() => {
        setFileDetails(r.data)
        setLoadingFile(false)
      }, 700)
    }catch(e:any){ 
      console.error(e) 
      setLoadingFile(false)
    }
  }

  const getProjectName = (path: string) => {
     if(path.startsWith('db://')) return 'Cloud Project'
     const normalized = path.replace(/\\/g, '/')
     const parts = normalized.split('/')
     return parts[parts.length - 1] || 'Project'
  }

  const handleExportJSON = () => {
     if(!scan) return
     const findings = scan.results && scan.results.findings ? scan.results.findings : []
     const dataStr = JSON.stringify(findings, null, 2)
     const blob = new Blob([dataStr], { type: "application/json" })
     const url = URL.createObjectURL(blob)
     const link = document.createElement("a")
     link.href = url
     link.download = `scan_results_${scan.id}.json`
     link.click()
  }

  const handleExportCSV = () => {
     if(!scan) return
     const findings = scan.results && scan.results.findings ? scan.results.findings : []
     
     // CSV Header
     let csvContent = "Category,Severity,File,Line,Message\n"
     
     findings.forEach((f:any) => {
        // Escape quotes
        const msg = (f.message || '').replace(/"/g, '""')
        const file = (f.file || '').replace(/"/g, '""')
        const row = `"${f.category}","${f.severity}","${file}","${f.line}","${msg}"`
        csvContent += row + "\n"
     })
     
     const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" })
     const url = URL.createObjectURL(blob)
     const link = document.createElement("a")
     link.href = url
     link.download = `scan_results_${scan.id}.csv`
     link.click()
  }

  useEffect(()=>{ fetchScan(); fetchFiles() }, [id])

  if(!scan) return <div className="min-h-screen flex items-center justify-center"><ScanLoader text="LOADING REPORT" /></div>

  return (
    <div className="min-h-screen pb-12 font-sans text-[#292D32]">
      <div className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
           <div className="flex items-center gap-2 text-sm text-[#5932ea] mb-1">
             <Link to="/" className="hover:underline flex items-center gap-1">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
                Back to Dashboard
             </Link>
           </div>
           <h1 className="text-3xl font-bold text-white mb-2">Scan Report</h1>
           <div className="flex items-center gap-4 text-sm text-[#9197b3]">
             <span className="font-mono bg-[#1e2330] px-2 py-0.5 rounded text-white border border-[#2d3748]">{getProjectName(scan.project_path)}</span>
             <span>•</span>
             <span>{new Date(scan.created_at).toLocaleString()}</span>
           </div>
        </div>
        <div className="flex gap-3">
           <button onClick={handleExportJSON} className="px-5 py-2.5 bg-[#1e2330] border border-[#2d3748] hover:bg-[#2d3748] text-white rounded-xl font-bold transition-all shadow-lg flex items-center gap-2">
             <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
             JSON
           </button>
           <button onClick={handleExportCSV} className="px-5 py-2.5 bg-[#5932ea] hover:bg-[#4a2bc2] text-white rounded-xl font-bold transition-all shadow-lg hover:shadow-[#5932ea]/40 flex items-center gap-2">
             <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
             Excel (CSV)
           </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
         {/* Sidebar: Files */}
         <div className="md:col-span-1 bg-[#1e2330] rounded-[30px] border border-[#2d3748] p-6 shadow-xl h-fit">
            <h2 className="text-xl font-bold text-white mb-6">Vulnerable Files</h2>
            <div className="space-y-2">
              {files.map(f=> (
                <button 
                  key={f.path} 
                  onClick={()=>fetchFileDetails(f.path)}
                  className={`w-full text-left p-4 rounded-xl transition-all border border-transparent ${
                    selectedFile===f.path 
                      ? 'bg-[#5932ea]/10 text-[#5932ea] border-[#5932ea]/50 shadow-sm' 
                      : 'text-[#9197b3] hover:bg-[#2d3748] hover:text-white'
                  }`}
                >
                  <div className="font-bold text-sm truncate mb-1">{f.path.split('/').pop()}</div>
                  <div className="text-xs opacity-60 truncate mb-2" title={f.path}>{f.path}</div>
                  <div className="flex items-center justify-between">
                     <span className="text-[10px] bg-[#2d3748] px-2 py-0.5 rounded text-white font-medium">{f.count} Issues</span>
                     <svg className={`w-4 h-4 ${selectedFile===f.path ? 'opacity-100' : 'opacity-0'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                  </div>
                </button>
              ))}
              {files.length === 0 && <div className="text-sm text-[#9197b3] italic text-center py-4">No vulnerabilities found!</div>}
            </div>
         </div>

         {/* Main Content: Findings */}
         <div className="md:col-span-3">
           {loadingFile ? (
             <div className="bg-[#1e2330] rounded-[30px] border border-[#2d3748] p-12 text-center shadow-xl min-h-[400px] flex items-center justify-center">
                <ScanLoader text="Analyzing File" />
             </div>
           ) : !fileDetails ? (
             <div className="bg-[#1e2330] rounded-[30px] border border-[#2d3748] p-12 text-center shadow-xl min-h-[400px] flex flex-col items-center justify-center">
                <div className="w-20 h-20 bg-[#2d3748] rounded-full flex items-center justify-center mb-6">
                   <svg className="w-10 h-10 text-[#9197b3]" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Select a file to inspect</h3>
                <p className="text-[#9197b3]">Click on any file from the sidebar to view detailed security findings.</p>
             </div>
           ) : (
             <div className="space-y-6">
                <div className="bg-[#1e2330] rounded-[30px] border border-[#2d3748] p-6 shadow-xl flex items-center justify-between">
                   <div className="flex items-center gap-4">
                      <div className="p-3 bg-[#5932ea]/10 rounded-xl">
                        <svg className="w-6 h-6 text-[#5932ea]" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                      </div>
                      <div>
                        <h2 className="text-xl font-bold text-white">{fileDetails.file.split('/').pop()}</h2>
                        <div className="text-sm text-[#9197b3]">{fileDetails.file}</div>
                      </div>
                   </div>
                   <button onClick={()=>setShowFull(!showFull)} className="px-4 py-2 border border-[#2d3748] hover:bg-[#2d3748] rounded-xl text-sm font-medium text-white transition-colors">
                      {showFull ? 'Show Context Only' : 'Show Full File'}
                   </button>
                </div>

                <div className="space-y-4">
                  {fileDetails.findings.map((f:any, i:number)=> (
                    <div key={i} className="bg-[#1e2330] rounded-[30px] border border-[#2d3748] overflow-hidden shadow-xl">
                       <div className="px-8 py-5 border-b border-[#2d3748] flex items-center justify-between bg-[#2d3748]/10">
                          <div className="flex items-center gap-3">
                             <span className={`text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wide ${f.severity==='CRITICAL'||f.severity==='HIGH' ? 'bg-[#d0004b]/20 text-[#d0004b]' : 'bg-yellow-500/20 text-yellow-500'}`}>
                               {f.severity}
                             </span>
                             <span className="font-bold text-white">{f.category}</span>
                          </div>
                          <span className="text-sm text-[#9197b3] font-mono">Line {f.line}</span>
                       </div>
                       
                       <div className="p-8">
                          <p className="text-[#9197b3] mb-6 leading-relaxed">{f.message}</p>
                          
                          {/* Code Block */}
                          <div className="bg-[#0b0e14] rounded-2xl border border-[#2d3748] overflow-hidden">
                             <div className="px-4 py-2 border-b border-[#2d3748] bg-[#2d3748]/20 flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50"></div>
                                <div className="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50"></div>
                                <div className="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/50"></div>
                                <span className="ml-2 text-xs font-mono text-[#9197b3]">Source Preview</span>
                             </div>
                             <div className="p-4 overflow-x-auto">
                                <pre className="font-mono text-xs leading-6">
                                  {(showFull ? f.full : f.snippet).map((ln:any)=> (
                                    <div key={ln.line} className={`flex ${ln.highlight ? 'bg-[#d0004b]/10 -mx-4 px-4 border-l-2 border-[#d0004b]' : ''}`}>
                                       <span className="w-8 text-[#545969] text-right mr-4 select-none shrink-0">{ln.line}</span>
                                       <span className={`${ln.highlight ? 'text-[#ffbbc0]' : 'text-[#9197b3]'}`}>{ln.code}</span>
                                    </div>
                                  ))}
                                </pre>
                             </div>
                          </div>
                       </div>
                    </div>
                  ))}
                </div>
             </div>
           )}
         </div>
      </div>
    </div>
  )
}