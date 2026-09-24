/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        zinc: {
          50: '#fafafa',
          100: '#f4f4f5',
          200: '#e4e4e7',
          300: '#d4d4d8',
          400: '#a1a1aa',
          500: '#71717a',
          600: '#52525b',
          700: '#3f3f46',
          800: '#27272a',
          900: '#18181b',
          950: '#09090b', // main background
        },
        indigo: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5', // Primary brand color
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          950: '#1e1b4b',
        }
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'xs': '0 1px 2px 0 rgba(0,0,0,0.4)',
        'sm': '0 1px 3px 0 rgba(0,0,0,0.5)',
        'DEFAULT': '0 2px 4px -1px rgba(0,0,0,0.6)',
        'md': '0 4px 6px -1px rgba(0,0,0,0.7)',
        'lg': '0 10px 15px -3px rgba(0,0,0,0.8)',
        'xl': '0 20px 25px -5px rgba(0,0,0,0.9)',
        'inner-light': 'inset 0 1px 0 0 rgba(255,255,255,0.05)',
      },
      borderRadius: {
        '2xl': '1rem',
        'xl': '0.75rem',
        'lg': '0.5rem',
        'md': '0.375rem',
      }
    },
  },
  plugins: [],
}
