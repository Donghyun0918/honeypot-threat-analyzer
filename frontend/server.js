// 커스텀 Next.js 서버 + T-Pot 어택맵 리버스 프록시.
//
// - /tpot-map/*  → T-Pot map_web(:64299)의 /*  (어택맵 UI, HTTP)
// - /websocket   → T-Pot map_web(:64299)의 /websocket (실시간 공격 피드, WS 업그레이드)
// - 그 외 모든 경로 → Next.js 핸들러
//
// Next standalone server.js는 WebSocket 업그레이드 프록시를 못 해서 직접 작성.
// 타깃은 TPOT_MAP_TARGET env로 구성 (기본 http://map_web:64299).

const http = require("http");
const next = require("next");
const httpProxy = require("http-proxy");

const port = parseInt(process.env.PORT || "8001", 10);
const TPOT = process.env.TPOT_MAP_TARGET || "http://map_web:64299";

const app = next({ dev: false });
const handle = app.getRequestHandler();

const proxy = httpProxy.createProxyServer({
  target: TPOT,
  ws: true,
  changeOrigin: true,
  xfwd: true,
});

proxy.on("error", (err, req, res) => {
  console.error("[tpot-map proxy] error:", err.message);
  if (res && typeof res.writeHead === "function" && !res.headersSent) {
    res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("T-Pot 어택맵 연결 실패 — infra_only(map_web) 기동 여부를 확인하세요.\n" + err.message);
  } else if (res && typeof res.destroy === "function") {
    res.destroy();
  }
});

function isMap(url) {
  return url.startsWith("/tpot-map");
}
function isWs(url) {
  return url.startsWith("/websocket");
}
// /tpot-map 프리픽스 제거 → map_web은 루트(/)에서 서빙
function stripPrefix(url) {
  const u = url.replace(/^\/tpot-map/, "");
  return u === "" ? "/" : u;
}

app.prepare().then(() => {
  const server = http.createServer((req, res) => {
    const url = req.url || "/";
    if (isMap(url)) {
      req.url = stripPrefix(url);
      proxy.web(req, res, { target: TPOT });
      return;
    }
    if (isWs(url)) {
      proxy.web(req, res, { target: TPOT });
      return;
    }
    handle(req, res);
  });

  // WebSocket 업그레이드 프록시
  server.on("upgrade", (req, socket, head) => {
    const url = req.url || "";
    if (isWs(url)) {
      proxy.ws(req, socket, head, { target: TPOT });
    } else if (isMap(url)) {
      req.url = stripPrefix(url);
      proxy.ws(req, socket, head, { target: TPOT });
    } else {
      socket.destroy();
    }
  });

  server.listen(port, "0.0.0.0", () => {
    console.log(`> capstone frontend ready on :${port} (TPOT_MAP_TARGET=${TPOT})`);
  });
});
