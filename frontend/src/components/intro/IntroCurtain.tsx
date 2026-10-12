"use client";

// 첫 진입 커튼 — 로고와 진행 수치를 1초 남짓 보여준 뒤 위로 걷힌다.

import { useEffect, useRef } from "react";

export default function IntroCurtain() {
  const curtainRef = useRef<HTMLDivElement>(null);
  const loadRef = useRef<HTMLSpanElement>(null);
  const barRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      if (curtainRef.current) curtainRef.current.style.display = "none";
      return;
    }

    const t0 = Date.now();
    const loadTimer = setInterval(() => {
      const p = Math.min(100, Math.round(((Date.now() - t0) / 1150) * 100));
      if (loadRef.current) loadRef.current.textContent = String(p).padStart(3, "0");
      if (barRef.current) barRef.current.style.width = `${p}%`;
      if (p >= 100) clearInterval(loadTimer);
    }, 40);

    const hideTimer = setTimeout(() => {
      if (curtainRef.current) curtainRef.current.style.display = "none";
    }, 2250);

    return () => {
      clearInterval(loadTimer);
      clearTimeout(hideTimer);
    };
  }, []);

  return (
    <div
      ref={curtainRef}
      aria-hidden="true"
      style={{
        position: "fixed", inset: 0, zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "var(--bg)",
        animation: "k-curtain 1.05s 1.1s cubic-bezier(.76,0,.24,1) forwards",
      }}
    >
      <div
        style={{
          display: "grid", justifyItems: "center", gap: 14,
          animation: "k-curtain-in 2.1s cubic-bezier(.2,.7,.2,1) forwards",
        }}
      >
        <div
          style={{
            fontFamily: "var(--display)", fontWeight: 700, lineHeight: 1, letterSpacing: "-0.06em",
            fontSize: "clamp(44px, 9vw, 110px)",
          }}
        >
          정사평<span style={{ color: "var(--accent)" }}>.</span>
        </div>
        <div
          style={{
            display: "flex", alignItems: "center", gap: 12,
            fontFamily: "var(--mono)", fontSize: 11, letterSpacing: "0.22em", color: "rgba(244,244,241,0.45)",
          }}
        >
          <span>INITIALIZING HONEYPOT NODES</span>
          <span ref={loadRef} style={{ color: "var(--accent)" }}>000</span>
        </div>
        <div style={{ height: 2, overflow: "hidden", background: "rgba(244,244,241,0.12)", width: "clamp(140px, 24vw, 260px)" }}>
          <div ref={barRef} style={{ height: 2, width: 0, background: "var(--accent)", transition: "width .1s linear" }} />
        </div>
      </div>
    </div>
  );
}
