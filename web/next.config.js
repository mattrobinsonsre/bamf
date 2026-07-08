/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // In local dev the Next dev server is reached via the ingress hostname
  // (https://bamf.local through Traefik), which is cross-origin to the pod's
  // dev server. Next 16 rejects cross-origin dev requests — including the HMR
  // websocket and dev-client payloads — unless the origin is allowlisted here.
  // Without this the client runtime never boots and client-only pages (e.g.
  // /login, whose content is behind Suspense+useSearchParams) hang on their
  // fallback. Prod builds ignore this field.
  allowedDevOrigins: ['bamf.local'],
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
