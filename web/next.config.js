/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: '/ws/:path*',
        destination: process.env.PROXY_URL
          ? `${process.env.PROXY_URL}/ws/:path*`
          : 'http://localhost:3022/ws/:path*',
      },
    ]
  },
}

module.exports = nextConfig
