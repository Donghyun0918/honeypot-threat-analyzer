import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // 커스텀 server.js(http-proxy)로 /tpot-map·/websocket을 프록시하므로 standalone 미사용.
  async rewrites() {
    return [
      {
        source: "/user",
        destination: "/",
      },
    ];
  },
};

export default nextConfig;
