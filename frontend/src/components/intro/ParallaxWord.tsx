"use client";

// 스크롤에 따라 조금 늦게 따라오는 큰 글자(푸터 워드마크).

import { useEffect, useRef } from "react";
import type { ReactNode } from "react";

export default function ParallaxWord({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const el = ref.current;
    if (!el) return;

    const onScroll = () => {
      const r = el.getBoundingClientRect();
      const h = innerHeight;
      const k = (r.top + r.height / 2 - h / 2) / h;
      el.style.translate = `0 ${(k * -26).toFixed(1)}px`;
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return <div ref={ref}>{children}</div>;
}
