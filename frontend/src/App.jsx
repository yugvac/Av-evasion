import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import ScanUpload from './pages/ScanUpload'
import ScanResult from './pages/ScanResult'
import History from './pages/History'
import Stats from './pages/Stats'

function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<ScanUpload />} />
            <Route path="/result/:sha256" element={<ScanResult />} />
            <Route path="/history" element={<History />} />
            <Route path="/stats" element={<Stats />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
