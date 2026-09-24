/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return {
      fallback: [
        {
          source: '/:path*',
          destination: 'http://127.0.0.1:8000/:path*',
        },
      ],
    }
  },
}

export default nextConfig;
