import axios from 'axios'

// Use relative URLs so the app works both in dev (vite proxy) and when served by FastAPI
const api = axios.create({ baseURL: '', withCredentials: true })

// Normalize errors so pages can display helpful messages
api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response) {
      // Reject with backend payload when available
      return Promise.reject(error.response.data ?? { error: error.message })
    }
    return Promise.reject({ error: error.message })
  }
)

export default api
