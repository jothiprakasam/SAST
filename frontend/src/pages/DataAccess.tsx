import api from '../api'
import { useState } from 'react'

export default function DataAccess(){
  const [res, setRes] = useState<any>(null)
  const run = async () => {
    try{
      setRes({ status: 'running' })
      const r = await api.post('/data_access', { project_path: './project_test', include_ast: true })
      setRes(r.data)
    }catch(e:any){ setRes(e) }
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Data Access & AST</h1>
          <p className="text-[#9197b3]">Inspect Abstract Syntax Trees and Data Access patterns.</p>
        </div>
        <button 
          onClick={run} 
          className="px-6 py-3 bg-[#5932ea] hover:bg-[#4a2bc2] text-white rounded-xl shadow-lg shadow-[#5932ea]/20 transition-all font-bold"
        >
          Fetch Data
        </button>
      </div>

      <div className="bg-[#1e2330] rounded-[30px] p-8 shadow-sm border border-[#1e2330]">
        <div className="flex items-center justify-between mb-6">
           <h3 className="text-xl font-bold text-white">Inspector Output</h3>
           <span className="text-xs font-mono text-[#9197b3] bg-[#0b0e14] px-2 py-1 rounded">JSON Response</span>
        </div>
        
        <div className="bg-[#0b0e14] rounded-xl p-6 overflow-auto max-h-[600px] border border-[#2d3748]">
          {res ? (
            <pre className="font-mono text-sm text-sky-400 whitespace-pre-wrap">{JSON.stringify(res, null, 2)}</pre>
          ) : (
            <div className="text-center py-12 text-[#9197b3] italic">
              No data loaded. Click &quot;Fetch Data&quot; to begin.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
