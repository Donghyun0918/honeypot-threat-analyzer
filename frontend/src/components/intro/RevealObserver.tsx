"use client";

// [data-reveal] · [data-rule] 노드가 처음 화면에 들어올 때 data-revealed="true" 를 붙인다
// (실제 전환은 globals.css). 한 번에 들어온 것들은 조금씩 시차를 둔다.
// 마운트 시점에 있는 노드만 본다 — 정적인 면(랜딩)에만 둔다.

import { useEffect } from "react";

export default function RevealObserver() {
  useEffect(() => {
    const reveals = Array.from(document.querySelectorAll<HTMLElement>("[data-reveal]"));
    const rules = Array.from(document.querySelectorAll<HTMLElement>("[data-rule]"));

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      [...reveals, ...rules].forEach((el) => { el.dataset.revealed = "true"; });
      return;
    }

    const io = new IntersectionObserver(
      (entries) => {
        const hits = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        hits.forEach((entry, i) => {
          const el = entry.target as HTMLElement;
          el.style.transitionDelay = `${Math.min(i * 90, 360)}ms`;
          el.dataset.revealed = "true";
          io.unobserve(el);
        });
      },
      { rootMargin: "0px 0px -6% 0px", threshold: 0.05 },
    );
    reveals.forEach((el) => io.observe(el));

    const ro = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          (entry.target as HTMLElement).dataset.revealed = "true";
          ro.unobserve(entry.target);
        });
      },
      { threshold: 0.4 },
    );
    rules.forEach((el) => ro.observe(el));

    return () => {
      io.disconnect();
      ro.disconnect();
    };
  }, []);

  return null;
}
