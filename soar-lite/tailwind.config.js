/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        bg: {
          900: '#04060f',
          800: '#080d1a',
          700: '#0c1224',
          600: '#101729',
        },
        surface: {
          DEFAULT: 'rgba(255,255,255,0.04)',
          hover: 'rgba(255,255,255,0.07)',
          border: 'rgba(255,255,255,0.08)',
        },
        neon: {
          blue:   '#00d4ff',
          purple: '#a855f7',
          pink:   '#ec4899',
          green:  '#10b981',
          red:    '#ef4444',
          yellow: '#f59e0b',
        },
      },
      backgroundImage: {
        'app-bg': 'linear-gradient(135deg, #04060f 0%, #080d1a 40%, #0f0a1e 70%, #04060f 100%)',
        'card-glass': 'linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
        'neon-blue-gradient': 'linear-gradient(135deg, #00d4ff22, #0066ff22)',
        'neon-purple-gradient': 'linear-gradient(135deg, #a855f722, #7c3aed22)',
        'neon-red-gradient': 'linear-gradient(135deg, #ef444422, #dc262622)',
        'neon-green-gradient': 'linear-gradient(135deg, #10b98122, #05966922)',
      },
      boxShadow: {
        'neon-blue':   '0 0 20px rgba(0,212,255,0.15), 0 0 40px rgba(0,212,255,0.05)',
        'neon-purple': '0 0 20px rgba(168,85,247,0.15), 0 0 40px rgba(168,85,247,0.05)',
        'neon-red':    '0 0 20px rgba(239,68,68,0.2),  0 0 40px rgba(239,68,68,0.08)',
        'neon-green':  '0 0 20px rgba(16,185,129,0.15),0 0 40px rgba(16,185,129,0.05)',
        'glass':       '0 8px 32px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.08)',
        'glass-hover': '0 12px 40px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.12)',
      },
      animation: {
        'pulse-slow':  'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'glow-pulse':  'glowPulse 2s ease-in-out infinite',
        'slide-in':    'slideIn 0.3s ease-out',
        'fade-in':     'fadeIn 0.4s ease-out',
        'count-up':    'countUp 0.6s ease-out',
        'shimmer':     'shimmer 1.5s infinite',
      },
      keyframes: {
        glowPulse: {
          '0%, 100%': { opacity: '1', boxShadow: '0 0 8px currentColor' },
          '50%':      { opacity: '0.6', boxShadow: '0 0 20px currentColor' },
        },
        slideIn: {
          from: { transform: 'translateX(100%)', opacity: '0' },
          to:   { transform: 'translateX(0)',    opacity: '1' },
        },
        fadeIn: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to:   { opacity: '1', transform: 'translateY(0)'   },
        },
        shimmer: {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition:  '200% 0' },
        },
      },
    },
  },
  plugins: [],
}
