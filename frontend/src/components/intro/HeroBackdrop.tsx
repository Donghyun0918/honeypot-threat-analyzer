// 히어로 배경 — 원근 바닥 격자, 흘러 올라가는 수집 로그 질감, 레이더, 번지는 빛.
// 전부 장식(aria-hidden)이다. 로그 행은 실제 이벤트가 아니라 형태만 흉내 낸 것이고,
// 시각은 수집 창 마지막 날(2026-05-06)에 고정해 빌드마다 바뀌지 않게 했다.

import Radar from "./Radar";

const REPS = ["Known Attacker", "Reputation Unknown", "Mass Scanner", "Bot / Crawler"];
const POTS = ["Honeytrap", "Cowrie", "Dionaea", "Suricata", "Elasticpot"];
const PROTOS = ["OTHER", "SSH", "SQL", "HTTP", "SMB"];
const COUNTRIES = ["United States", "Brazil", "United Kingdom", "Netherlands", "China", "Germany", "India", "Vietnam"];
const PORTS = [8081, 22, 1433, 5443, 18184, 445, 2087];

function buildLogRows() {
  const base = Date.UTC(2026, 4, 6, 23, 59, 30);
  const rows = Array.from({ length: 26 }, (_, i) => {
    const d = new Date(base - i * 41000);
    const p = (n: number) => String(n).padStart(2, "0");
    return {
      ts: `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`,
      ip: `${20 + ((i * 37) % 200)}.${(i * 53) % 255}.${(i * 91) % 255}.${(i * 17) % 255}`,
      ipDim: i % 3 !== 0,
      rep: REPS[i % REPS.length],
      country: COUNTRIES[i % COUNTRIES.length],
      pot: POTS[i % POTS.length],
      proto: PROTOS[i % PROTOS.length],
      port: PORTS[i % PORTS.length],
    };
  });
  return [...rows, ...rows];
}

const 가림 = (g: string): React.CSSProperties => ({ maskImage: g, WebkitMaskImage: g });

export default function HeroBackdrop() {
  const rows = buildLogRows();

  return (
    <div aria-hidden="true" style={{ pointerEvents: "none", position: "absolute", inset: 0, zIndex: 0, overflow: "hidden" }}>
      {/* 원근 바닥 격자 */}
      <div style={{ position: "absolute", left: "-20%", right: "-20%", bottom: "-12%", height: "80%", perspective: "520px", perspectiveOrigin: "50% 0%" }}>
        <div
          style={{
            position: "absolute", inset: 0,
            transform: "rotateX(68deg)", transformOrigin: "50% 0%",
            backgroundImage:
              "linear-gradient(rgba(244,244,241,0.14) 1px, transparent 1px), linear-gradient(90deg, rgba(244,244,241,0.09) 1px, transparent 1px)",
            backgroundSize: "120px 120px",
            animation: "k-floor 5.5s linear infinite",
            ...가림("linear-gradient(to bottom, #000 0%, transparent 62%)"),
          }}
        />
      </div>

      {/* 흘러 올라가는 수집 로그 */}
      <div
        style={{
          position: "absolute", top: "-6%", bottom: "-6%", right: 0, overflow: "hidden",
          width: "min(78%, 1180px)", whiteSpace: "nowrap", opacity: 0.55,
          fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.9,
          ...가림("linear-gradient(100deg, transparent 0%, transparent 34%, #000 62%, #000 88%, transparent 100%)"),
        }}
      >
        <div style={{ display: "grid", gap: 2, paddingLeft: "4%", animation: "k-colup 42s linear infinite" }}>
          {rows.map((r, i) => (
            <div
              key={i}
              style={{ display: "grid", gap: 22, color: "rgba(244,244,241,0.30)", gridTemplateColumns: "150px 118px 132px 110px 88px 62px 50px" }}
            >
              <span>{r.ts}</span>
              <span style={{ color: r.ipDim ? "rgba(255,92,120,0.42)" : "rgba(255,92,120,0.72)" }}>{r.ip}</span>
              <span>{r.rep}</span>
              <span>{r.country}</span>
              <span style={{ color: "rgba(244,244,241,0.42)" }}>{r.pot}</span>
              <span>{r.proto}</span>
              <span>{r.port}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 레이더 */}
      <Radar
        style={{
          position: "absolute", right: "-6vw", top: "-10vh",
          width: "min(70vh, 52vw)", opacity: 0.55,
          ...가림("radial-gradient(closest-side, #000 68%, transparent 100%)"),
        }}
      />

      {/* 번지는 빛 */}
      <div
        style={{
          position: "absolute", left: "-10vw", top: "-22vh", width: "48vw", height: "48vw", borderRadius: "50%",
          background: "var(--accent)", opacity: 0.08, filter: "blur(130px)",
          animation: "k-drift-a 18s ease-in-out infinite",
        }}
      />
      <div
        style={{
          position: "absolute", bottom: "-24vh", right: "18vw", width: "36vw", height: "36vw", borderRadius: "50%",
          background: "#3f6bff", opacity: 0.1, filter: "blur(140px)",
          animation: "k-drift-b 22s ease-in-out infinite",
        }}
      />

      {/* 주사선 + 비네팅 */}
      <div style={{ position: "absolute", inset: 0, backgroundImage: "linear-gradient(rgba(244,244,241,0.028) 1px, transparent 1px)", backgroundSize: "100% 3px" }} />
      <div style={{ position: "absolute", inset: 0, background: "radial-gradient(70% 60% at 14% 42%, rgba(6,6,7,0.92) 0%, rgba(6,6,7,0) 100%)" }} />
      <div style={{ position: "absolute", inset: 0, background: "linear-gradient(to bottom, rgba(6,6,7,0.35) 0%, rgba(6,6,7,0) 30%, rgba(6,6,7,0.82) 100%)" }} />
    </div>
  );
}
