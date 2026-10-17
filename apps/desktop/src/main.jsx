import React, { Component } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './styles.css';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: '2rem', fontFamily: 'DM Sans, sans-serif', color: '#e8f0ea', background: '#0c1210', minHeight: '100vh' }}>
          <h1 style={{ fontFamily: 'Instrument Serif, serif' }}>Aegis TI hit a display error</h1>
          <p style={{ color: '#8fa398' }}>The console recovered enough to show this message. Reload the window to continue.</p>
          <pre style={{ whiteSpace: 'pre-wrap', border: '1px solid rgba(232,240,234,0.1)', padding: '1rem' }}>
            {String(this.state.error?.message || this.state.error).slice(0, 500)}
          </pre>
          <button type="button" onClick={() => window.location.reload()}>Reload</button>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
