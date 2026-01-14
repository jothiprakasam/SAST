import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import api from '../api'
import ScanLoader from '../components/ScanLoader'
import GlobalLoader from '../components/GlobalLoader'

export default function Analyze(){
  const [searchParams] = useSearchParams()
  const [activeTab, setActiveTab] = useState<'upload' | 'github' | 'editor'>('upload')
  const [res, setRes] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  // Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  
  // GitHub State
  const [ghToken, setGhToken] = useState('')
  const [ghUsername, setGhUsername] = useState('')
  const [ghRepos, setGhRepos] = useState<any[]>([])
  const [ghLoading, setGhLoading] = useState(false)

  // Editor State
  const [codeContent, setCodeContent] = useState('')
  const [filename, setFilename] = useState('main.py')

  // --- Effects ---
  useEffect(() => {
     // Check for tab param
     const tab = searchParams.get('tab')
     if(tab === 'github' || tab === 'upload' || tab === 'editor') {
         setActiveTab(tab)
     }
     
     // Check for auto-load action (e.g. came back from auth)
     const action = searchParams.get('action')
     if(tab === 'github' && action === 'load_repos') {
         // Auto-trigger fetch
         handleGithubConnect()
     }
  }, [searchParams])

  // --- Core Scan Logic ---
  const runScan = async (path: string) => {
    setLoading(true)
    setRes(null)
    try {
      const r = await api.post('/analyze', { project_path: path })
      setRes(r.data)
      if(r.data && r.data.saved_to_db && r.data.scan_id){
         setTimeout(() => navigate(`/scans/${r.data.scan_id}`), 1500)
      } else {
        setLoading(false)
      }
    } catch(e:any){ 
      console.error(e)
      setRes({ error: 'Analysis failed.' })
      setLoading(false)
    }
  }

  // --- Handlers ---
  const handleUpload = async () => {
    if(!selectedFile) return
    setLoading(true)
    const fd = new FormData()
    fd.append('file', selectedFile)
    try {
      const r = await api.post('/upload-zip', fd)
      await runScan(r.data.project_path)
    } catch(e:any) { 
      console.error(e)
      const msg = e?.detail || e?.error || e?.message || 'Upload failed. Ensure you are uploading a valid zip.'
      setRes({ error: msg })
      setLoading(false)
    }
  }

  const handleGithubConnect = async () => {
    setGhLoading(true)
    const fd = new FormData()
    if(ghToken) fd.append('token', ghToken)
    if(ghUsername) fd.append('username', ghUsername)
    
    try {
        const r = await api.post('/github/repos', fd)
        setGhRepos(r.data)
    } catch(e) {
        setRes({ error: 'Failed to fetch repositories. Check your token/username.' })
    }
    setGhLoading(false)
  }

  const handleClone = async (repoUrl: string) => {
    setLoading(true)
    const fd = new FormData()
    fd.append('repo_url', repoUrl)
    if(ghToken) fd.append('token', ghToken)
    
    try {
        const r = await api.post('/github/clone', fd)
        await runScan(r.data.project_path)
    } catch(e) {
        setRes({ error: 'Failed to clone repository.' })
        setLoading(false)
    }
  }

  const handleCreateFile = async () => {
      if(!codeContent.trim()) return
      setLoading(true)
      const fd = new FormData()
      fd.append('filename', filename)
      fd.append('content', codeContent)
      
      try {
          const r = await api.post('/create-file', fd)
          await runScan(r.data.project_path)
      } catch(e) {
          setRes({ error: 'Failed to create file.' })
          setLoading(false)
      }
  }

  return (
    <div className="max-w-6xl mx-auto py-10">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-extrabold text-white mb-2 tracking-tight">New Scan</h1>
        <p className="text-[#9197b3]">Choose how you want to import your code for analysis</p>
      </div>

      <div className="bg-[#1e2330] rounded-[24px] shadow-2xl border border-[#2d3748] overflow-hidden min-h-[500px] flex flex-col md:flex-row">
        
        {/* Sidebar Tabs */}
        <div className="md:w-64 bg-[#151922] p-4 flex flex-col gap-2 border-r border-[#2d3748]">
            <button 
                onClick={()=>!loading && setActiveTab('upload')}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all font-medium text-left ${activeTab==='upload' ? 'bg-[#5932ea] text-white shadow-lg shadow-[#5932ea]/20' : 'text-[#9197b3] hover:bg-[#1e2330] hover:text-white'}`}
            >
                <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg>
                Upload Zip
            </button>
            {/* <button 
                onClick={()=>!loading && setActiveTab('github')}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all font-medium text-left ${activeTab==='github' ? 'bg-[#5932ea] text-white shadow-lg shadow-[#5932ea]/20' : 'text-[#9197b3] hover:bg-[#1e2330] hover:text-white'}`}
            >
                <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
                GitHub Repos
            </button> */}
            <button 
                onClick={()=>!loading && setActiveTab('editor')}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all font-medium text-left ${activeTab==='editor' ? 'bg-[#5932ea] text-white shadow-lg shadow-[#5932ea]/20' : 'text-[#9197b3] hover:bg-[#1e2330] hover:text-white'}`}
            >
                <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                Direct Input
            </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 p-8 relative">
           
           {/* Loading Overlay */}
           {loading && (
             <div className="absolute inset-0 z-50 bg-[#1e2330]/90 flex flex-col items-center justify-center backdrop-blur-sm animate-in fade-in duration-300">
                <ScanLoader text="PROCESSING" />
                <p className="mt-4 text-[#9197b3]">Analyzing codebase...</p>
             </div>
           )}

           {/* Tab: Upload */}
           {activeTab === 'upload' && !loading && (
             <div className="h-full flex flex-col items-center justify-center text-center animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className="w-24 h-24 bg-[#2d3748]/50 rounded-full flex items-center justify-center mb-6 border-2 border-dashed border-[#5932ea]/50 text-[#5932ea]">
                   <svg width="40" height="40" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg>
                </div>
                <h3 className="text-2xl font-bold text-white mb-2">Upload Project Archive</h3>
                <p className="text-[#9197b3] mb-8 max-w-sm">
                   Select a <code className="bg-[#0b0e14] px-1.5 py-0.5 rounded text-white text-xs">.zip</code> file containing your source code. 
                   We'll extract it securely and run the analysis.
                </p>
                <div className="relative">
                   <input 
                     type="file" 
                     accept=".zip"
                     onChange={(e)=>setSelectedFile(e.target.files?.[0] || null)}
                     className="block w-full text-sm text-[#9197b3]
                       file:mr-4 file:py-3 file:px-6
                       file:rounded-full file:border-0
                       file:text-sm file:font-semibold
                       file:bg-[#5932ea] file:text-white
                       hover:file:bg-[#4a2bc2]
                       cursor-pointer bg-[#0b0e14] rounded-full pl-2 pr-4 py-2 border border-[#2d3748]
                     "
                   />
                </div>
                {selectedFile && (
                   <button onClick={handleUpload} className="mt-8 px-10 py-3 bg-[#5932ea] hover:bg-[#4a2bc2] text-white rounded-xl font-bold shadow-lg shadow-[#5932ea]/30 transition-all">
                      Analyze {selectedFile.name}
                   </button>
                )}
             </div>
           )}

           {/* Tab: GitHub */}
           {activeTab === 'github' && !loading && (
             <div className="h-full flex flex-col animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className="flex gap-4 mb-6">
                   <button 
                       onClick={() => {
                           localStorage.setItem('sast_post_auth_redirect', '/analyze?tab=github&action=load_repos')
                           window.location.href = 'http://localhost:8000/auth/login/github'
                       }}
                       className="px-6 py-2.5 bg-[#2d3748] hover:bg-[#1e2330] text-white rounded-xl font-bold flex items-center gap-2 border border-[#4a5568] transition-colors"
                   >
                       <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                       Connect GitHub
                   </button>
                   <div className="flex-1 flex gap-2">
                       <input 
                         placeholder="Or find user (public)..." 
                         value={ghUsername}
                         onChange={e=>setGhUsername(e.target.value)}
                         className="flex-1 bg-[#0b0e14] text-white px-4 py-2.5 rounded-xl border border-[#2d3748] focus:border-[#5932ea] outline-none"
                       />
                        <button onClick={handleGithubConnect} disabled={ghLoading} className="px-6 py-2.5 bg-[#5932ea] text-white rounded-xl font-bold hover:bg-[#4a2bc2]">
                             {ghLoading ? <GlobalLoader /> : 'Fetch Repos'}
                        </button>
                   </div>
                </div>

                {/* Info Note for users manually entering token */}
                <div className="text-xs text-[#9197b3] mb-4 bg-[#1e2330] p-3 rounded-lg border border-[#2d3748] flex items-center justify-between">
                   <span>
                      <strong>Tip:</strong> Click "Connect GitHub" to link your account and see private repos automatically.
                   </span>
                   {/* Toggle manual token input if really needed? Or just keep simple. Kept simple for now. */}
                </div>
                
                <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                   {ghRepos.length === 0 ? (
                      <div className="h-40 flex items-center justify-center text-[#9197b3] border-2 border-dashed border-[#2d3748] rounded-xl">
                         No repositories loaded. Enter details above.
                      </div>
                   ) : (
                      <div className="grid grid-cols-1 gap-3">
                         {ghRepos.map(repo => (
                            <div key={repo.id} className="flex items-center justify-between p-4 bg-[#0b0e14] rounded-xl border border-[#2d3748] hover:border-[#5932ea] transition-colors group">
                               <div>
                                  <div className="font-bold text-white flex items-center gap-2">
                                     {repo.private && <span className="text-xs bg-yellow-500/20 text-yellow-500 px-1.5 py-0.5 rounded">Private</span>}
                                     {repo.full_name}
                                  </div>
                                  <div className="text-xs text-[#9197b3] mt-1">{repo.description || 'No description'}</div>
                               </div>
                               <button onClick={()=>handleClone(repo.clone_url)} className="opacity-0 group-hover:opacity-100 flex items-center gap-2 px-4 py-2 bg-[#1e2330] hover:bg-[#5932ea] text-white rounded-lg transition-all text-sm font-medium border border-[#2d3748]">
                                  Import & Analyze
                               </button>
                            </div>
                         ))}
                      </div>
                   )}
                </div>
             </div>
           )}

           {/* Tab: Editor */}
           {activeTab === 'editor' && !loading && (
             <div className="h-full flex flex-col animate-in fade-in slide-in-from-bottom-4 duration-500">
                <input 
                  value={filename}
                  onChange={e=>setFilename(e.target.value)}
                  placeholder="Filename (e.g. main.py)"
                  className="w-full bg-[#0b0e14] text-white px-4 py-2.5 rounded-t-xl border border-[#2d3748] border-b-0 focus:border-[#5932ea] outline-none font-mono text-sm"
                />
                <textarea 
                  value={codeContent}
                  onChange={e=>setCodeContent(e.target.value)}
                  placeholder="# Paste your python code here..."
                  className="flex-1 w-full bg-[#0b0e14] text-gray-300 p-4 border border-[#2d3748] outline-none font-mono text-sm resize-none focus:border-[#5932ea]"
                ></textarea>
                <button onClick={handleCreateFile} className="w-full py-3 bg-[#5932ea] hover:bg-[#4a2bc2] text-white rounded-b-xl font-bold transition-all">
                   Analyze Code Snippet
                </button>
             </div>
           )}

           {/* Error Toast */}
           {res?.error && (
             <div className="absolute bottom-4 left-4 right-4 bg-red-900/90 text-white p-4 rounded-xl border border-red-500 backdrop-blur-md flex items-center justify-between animate-in slide-in-from-bottom-2">
                <span>{res.error}</span>
                <button onClick={()=>setRes(null)} className="text-white hover:text-red-200 font-bold ml-4">✕</button>
             </div>
           )}
        </div>
      </div>
    </div>
  )
}

