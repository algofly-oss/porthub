const withPWA = require("next-pwa")({
  dest: "public",
  disable: process.env.NODE_ENV === "development",
  reloadOnOnline: false,
  fallbacks: { document: "/offline" },
  runtimeCaching: [
    {
      // Live inventory and account data must never survive in an offline cache.
      urlPattern: ({ url }) => url.pathname.startsWith("/api/") || url.pathname.startsWith("/socket.io/"),
      handler: "NetworkOnly",
      options: { plugins: [{
        handlerDidError: async () => new Response(JSON.stringify({detail:"PortHub is unreachable. Reconnect to your network and try again."}), {
          status: 503,
          headers: {"Content-Type":"application/json", "Cache-Control":"no-store"},
        }),
      }] },
    },
    ...require("next-pwa/cache"),
  ],
});

module.exports = withPWA({
  reactStrictMode: true,
  // Self-contained server with only the modules it uses (small image).
  output: "standalone",
  // Production assets are exported and served by Rust, without a Node image API.
  images: { unoptimized: true },
  distDir: process.env.NEXT_BUILD_DIR || ".next",
  async rewrites() {
    const backend = process.env.PORTHUB_DEV_BACKEND_URL;
    return backend ? [
      { source: "/api/:path*", destination: `${backend}/api/:path*` },
      { source: "/socket.io/:path*", destination: `${backend}/socket.io/:path*` },
    ] : [];
  },
});
