import type { NextConfig } from "next";

// The demo is served from an exact loopback origin; no external images, no
// telemetry, and the Admin API is reached only through the server-side proxy.
const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  output: "standalone",
  outputFileTracingRoot: "../..",
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "x-frame-options", value: "DENY" },
          { key: "referrer-policy", value: "no-referrer" },
          { key: "x-content-type-options", value: "nosniff" },
        ],
      },
    ];
  },
};

export default config;
