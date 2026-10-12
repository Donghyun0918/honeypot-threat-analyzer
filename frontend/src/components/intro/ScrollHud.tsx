"use client";

// 상단 진행 막대 + 넓은 화면에서만 보이는 좌표·스크롤 계기.

import { useEffect, useRef, useState } from "react";

const 계기글꼴: React.CSSProperties = {
  pointerEvents: "none", position: "fixed", bottom: 14, zIndex: 70,
  fontFamily: "var(--mono)", fontSize: 10, letterSpacing: "0.12em", color: "rgba(244,244,241,0.34)",
};

export default function ScrollHud() {
  const barRef = useRef<HTMLDivElement>(null);
  const dotRef = useRef<HTMLSpanElement>(null);
  const coordRef = useRef<HTMLDivElement>(null);
  const [hudVisible, setHudVisible] = useState(false);

  useEffect(() => {
    const scrollPct = () =>
      Math.min(100, (window.scrollY / Math.max(1, document.body.scrollHeight - innerHeight)) * 100);

    const onScroll = () => {
      const p = scrollPct();
      if (barRef.current) barRef.current.style.width = `${p}%`;
      if (dotRef.current) dotRef.current.style.width = `${p}%`;
    };
    const onMove = (e: MouseEvent) => {
      const el = coordRef.current;
      if (!el) return;
      const p = Math.round(scrollPct());
      el.textContent = `x:${String(Math.round(e.clientX)).padStart(4, "0")} y:${String(Math.round(e.clientY)).padStart(4, "0")} p:${String(p).padStart(3, "0")}%`;
    };
    const onResize = () => setHudVisible(innerWidth >= 940 && innerHeight >= 700);

    onResize();
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("mousemove", onMove, { passive: true });
    window.addEventListener("resize", onResize, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <>
      <div ref={barRef} style={{ position: "fixed", left: 0, top: 0, zIndex: 90, height: 2, width: 0, background: "var(--accent)" }} />
      {hudVisible && (
        <>
          <div ref={coordRef} style={{ ...계기글꼴, left: 40 }}>x:0000 y:0000 p:000%</div>
          <div style={{ ...계기글꼴, right: 40, display: "flex", alignItems: "center", gap: 8 }}>
            <span>SCROLL VECTOR</span>
            <span style={{ display: "block", height: 3, width: 60, overflow: "hidden", borderRadius: 999, background: "rgba(244,244,241,0.14)" }}>
              <span ref={dotRef} style={{ display: "block", height: 3, width: 0, background: "var(--accent)" }} />
            </span>
          </div>
        </>
      )}
    </>
  );
}
