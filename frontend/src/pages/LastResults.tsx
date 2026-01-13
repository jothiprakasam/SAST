import api from '../api'
import { useState } from 'react'

export default function LastResults() {
  const [data, setData] = useState<any>(null)
  const fetch = async () => {
    try {
      const r = await api.get('/last-results')
      setData(r.data)
    } catch (e: any) {
      setData(e)
    }
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Last Scan Results</h1>
          <p className="text-[#9197b3]">Retrieve the results of the most recent analysis session.</p>
        </div>
        <button 
          onClick={fetch} 
          className="px-6 py-3 bg-[#5932ea] hover:bg-[#4a2bc2] text-white rounded-xl shadow-lg shadow-[#5932ea]/20 transition-all font-bold"
        >
          Refresh Data
        </button>
      </div>

      <div className="bg-[#1e2330] rounded-[30px] p-8 shadow-sm border border-[#1e2330]">
        <div className="flex items-center justify-between mb-6">
           <h3 className="text-xl font-bold text-white">Results Dump</h3>
           <span className="text-xs font-mono text-[#9197b3] bg-[#0b0e14] px-2 py-1 rounded">JSON Object</span>
        </div>
        
        <div className="bg-[#0b0e14] rounded-xl p-6 overflow-auto max-h-[600px] border border-[#2d3748]">
          {data ? (
            <pre className="font-mono text-sm text-yellow-500 whitespace-pre-wrap">{JSON.stringify(data, null, 2)}</pre>
          ) : (
            <div className="text-center py-12 text-[#9197b3] italic">
               No data loaded. Click &quot;Refresh Data&quot; to fetch.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
