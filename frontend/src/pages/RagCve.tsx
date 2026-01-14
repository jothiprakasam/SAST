import api from '../api'
import { useState } from 'react'

export default function RagCve(){
  const [res, setRes] = useState<any>(null)
  
  const run = async () => {
    try{
      setRes({ status: 'running' })
      const r = await api.post('/rag_cve', { project_path: './project_test' })
      setRes(r.data)
    }catch(e:any){ setRes(e) }
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">RAG CVE Analysis</h1>
          <p className="text-[#9197b3]">Run Retrieval-Augmented Generation analysis for CVE detection.</p>
        </div>
        <button 
          onClick={run} 
          className="px-6 py-3 bg-[#5932ea] hover:bg-[#4a2bc2] text-white rounded-xl shadow-lg shadow-[#5932ea]/20 transition-all font-bold"
        >
          Run Analysis
        </button>
      </div>

      <div className="bg-[#1e2330] rounded-[30px] p-8 shadow-sm border border-[#1e2330]">
        <div className="flex items-center justify-between mb-6">
           <h3 className="text-xl font-bold text-white">Output Console</h3>
           <span className="text-xs font-mono text-[#9197b3] bg-[#0b0e14] px-2 py-1 rounded">JSON Response</span>
        </div>
        
        <div className="bg-[#0b0e14] rounded-xl p-6 overflow-auto max-h-[600px] border border-[#2d3748]">
          {res ? (
            <pre className="font-mono text-sm text-green-400 whitespace-pre-wrap">{JSON.stringify(res, null, 2)}</pre>
          ) : (
            <div className="text-center py-12 text-[#9197b3] italic">
              Click &quot;Run Analysis&quot; to start the process...
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
