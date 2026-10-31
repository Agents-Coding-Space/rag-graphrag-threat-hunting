import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import './index.css'

class GlobalErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; error: Error | null }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("Global Error Caught:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '24px', color: '#EF4444', background: '#0B0F19', height: '100vh', fontFamily: 'monospace' }}>
          <h1 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '12px' }}>🚨 Giao diện gặp lỗi Runtime:</h1>
          <pre style={{ background: '#111827', padding: '16px', borderRadius: '8px', border: '1px solid #1F2937', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {this.state.error?.stack || this.state.error?.message}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{ marginTop: '16px', padding: '8px 16px', background: '#06B6D4', color: '#000', fontWeight: 'bold', borderRadius: '6px', cursor: 'pointer', border: 'none' }}
          >
            Tải lại trang (Reload)
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <GlobalErrorBoundary>
      <App />
    </GlobalErrorBoundary>
  </React.StrictMode>,
)
