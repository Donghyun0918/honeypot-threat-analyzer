"use client";

// 랜딩 상단 내비. 조금 내려가면 로고가 "정사평" → 프로젝트 전체 이름으로 바뀐다.

import { useEffect, useRef } from "react";
import Link from "next/link";

const 항목 = [
  { label: "#구조", href: "#구조" },
  { label: "#검증", href: "#검증" },
  { label: "#스택", href: "#스택" },
];

export default function Nav() {
  const logoARef = useRef<HTMLSpanElement>(null);
  const logoBRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const onScroll = () => {
      const swap = window.scrollY > 140;
      const a = logoARef.current;
      const b = logoBRef.current;
      if (!a || !b) return;
      a.style.opacity = swap ? "0" : "1";
      a.style.transform = swap ? "translateY(-8px)" : "translateY(0)";
      b.style.opacity = swap ? "1" : "0";
      b.style.transform = swap ? "translateY(0)" : "translateY(8px)";
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const 전환 = "opacity .3s ease-out, transform .3s ease-out";

  return (
    <header className="ix-nav">
      <a href="#top" className="ix-nav-logo">
        <span className="brand-mark" />
        <span style={{ position: "relative", display: "inline-block", whiteSpace: "nowrap" }}>
          <span ref={logoARef} style={{ display: "inline-block", transition: 전환 }}>정사평</span>
          <span
            ref={logoBRef}
            style={{
              position: "absolute", left: 0, top: 0, opacity: 0, transition: 전환, transform: "translateY(8px)",
              fontSize: "clamp(12px, 1.2vw, 15px)", fontWeight: 600, letterSpacing: "-0.01em",
            }}
          >
            허니팟 기반 사이버 공격 분석 시스템
          </span>
        </span>
      </a>
      <nav className="ix-nav-links">
        {항목.map((i) => (
          <a key={i.href} href={i.href} className="pill-nav">{i.label}</a>
        ))}
        <Link href="/dashboard" className="pill-nav 주">대시보드 →</Link>
      </nav>
    </header>
  );
}
