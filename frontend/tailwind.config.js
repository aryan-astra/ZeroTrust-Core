/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: '#0B0B0B',
          secondary: '#111111',
          tertiary: '#1A1A1A',
          elevated: '#222222',
          hover: '#2A2A2A',
        },
        border: {
          DEFAULT: '#2A2A2A',
          light: '#333333',
          focus: '#555555',
        },
        text: {
          primary: '#FFFFFF',
          secondary: '#A1A1A1',
          tertiary: '#6B6B6B',
          muted: '#4A4A4A',
        },
        status: {
          trusted: '#FFFFFF',
          suspicious: '#A1A1A1',
          quarantined: '#6B6B6B',
        }
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}

