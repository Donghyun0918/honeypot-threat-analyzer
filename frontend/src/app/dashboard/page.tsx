"use client";

// 대시보드 (static/index.html → Next.js Client Component)
// D3.js 는 npm 패키지로 사용 (CDN → import)

import { useEffect, useRef, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { 인증fetch, 로그아웃 } from "@/lib/auth";
import * as d3 from "d3";
import type { 공격로그입력 } from "@/types/input";
import {
  Shield, Activity, AlertTriangle, Globe, ShieldCheck, Share2, Search,
  FileDown, RefreshCw, Clock, Radio, BarChart3, Crosshair, TrendingUp,
  Database, ShieldAlert, Flame, Sparkles, ChevronDown, ChevronUp,
  BrainCircuit,
} from "lucide-react";

// 현재 분류 모델 메타정보 (/api/model)
type 모델정보타입 = {
  available: boolean; algorithm: string;
  accuracy: number | null; macro_f1: number | null;
  cv_acc_mean: number | null; cv_acc_std: number | null;
  labels: string[]; n_total: number; n_features: number | null;
  // 학습에 쓰지 않은 실 문서에서의 규칙 합의율. accuracy/macro_f1 은 학습셋
  // 내부 분할이라 99.9% 가 나오지만 그건 "규칙을 외웠다"는 뜻이다. 화면에는
  // 이쪽을 먼저 내보낸다 (DATASET_FINDINGS.md §6).
  holdout_n: number | null; holdout_micro: number | null; holdout_macro: number | null;
};

// 공격 패턴 단위 해설 (/api/llm-patterns)
//
// llm-analyzer 는 패턴당 한 번만 해설한다. 그래서 건별 목록을 그대로 그리면
// 같은 문단이 수백 줄 반복된다 — 파이프라인은 패턴 단위로 갔는데 화면만 건별로
// 남는 것이다. 접어서 보여주면 반복이 사라지고, 동시에 "4만 건이 실은 수십 개
// 패턴" 이라는 이 프로젝트의 측정 결과가 화면에 그대로 드러난다.
type 패턴타입 = {
  키: string; 레거시?: boolean; 허니팟: string; 라벨: string; 포트: string;
  건수: number; 공격IP수: number; 최근: string | null;
  위험등급: string | null; 위협점수: number | null;
  요약: string; 대응: string; 기법: string[];
};

// 내 자산 노출 대조 (/api/exposure)
//
// 허니팟 데이터는 "우리 대역을 노리는 공격" 이지 "우리가 뚫렸다" 가 아니다.
// 열어둔 포트를 대면 비로소 내 얘기가 된다 — 노린 공격이 몇 건인지, 그중
// 고위험이 몇 건인지, 몇 명이 두드렸는지.
// 이미 만들어둔 해설 (/api/llm-explain)
//
// llm-analyzer 는 패턴당 한 번만 모델을 부르지만 결과는 사건마다 남긴다.
// 그래서 고위험 사건 대부분은 고르는 즉시 **추론 없이 0초에** 해설이 나온다.
// 모델을 다시 부르는 건 해설이 없거나 더 깊은 리포트를 원할 때뿐이다.
type 해설타입 = {
  found: boolean; 요약: string; 대응: string;
  위험등급: string | null; 기법: string[]; 패턴키: string | null;
  공유: boolean; 모델: string | null;
};

type 노출타입 = {
  포트: number; 공격: number; 고위험: number;
  공격IP수: number; 최고점수: number; 주라벨: string | null; 위험: boolean;
};

// ── 표시용 헬퍼 (실 T-Pot 공격로그) ───────────────────────────────────────────

const 위험배지클래스: Record<string, string> = { CRITICAL: "치명", HIGH: "높음", MEDIUM: "보통", LOW: "보통" };

// 9-class ML 라벨(영문 ml_label) → 한국어 표시명
const 라벨한글: Record<string, string> = {
  "Normal": "정상", "Recon": "정찰", "Brute Force": "무차별 대입",
  "Intrusion": "침입", "Malware": "악성코드", "Web Attack": "웹 공격",
  "Service Attack": "서비스 공격", "ICS Attack": "산업제어 공격", "Etc": "기타",
};

function 공격표시명(a: 공격로그입력): string {
  const label = (a as unknown as { _ml_label?: string })._ml_label;
  if (label && label.length > 0) return 라벨한글[label] ?? label;
  return a.공격유형;
}
function 발생시각짧게(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

// ── 결과 카드 HTML 생성 헬퍼 ─────────────────────────────────────────────────

function 사건요약카드(r: Record<string, unknown>): string {
  const pts = ((r.핵심포인트 as string[]) || []).map((p) => `<li>${p}</li>`).join("");
  return `<div class="요약카드"><p class="요약텍스트">${r.요약문 || ""}</p><ul class="포인트목록">${pts}</ul><span class="공격명배지">${r.공격명칭 || ""}</span></div>`;
}
function 의도분석카드(r: Record<string, unknown>): string {
  const pct = Math.round((Number(r.신뢰도) || 0) * 100);
  return `<div class="분석칩카드"><div class="분석칩섹션제목">공격 의도 분류</div><span class="큰배지 ${r.의도}">${r.의도 || "알 수 없음"}</span><div class="신뢰도바컨테이너"><div class="라벨"><span>AI 분석 신뢰도</span><span>${pct}%</span></div><div class="신뢰도바"><div class="채움" style="width:${pct}%"></div></div></div><p class="근거설명">${r.판단근거 || ""}</p></div>`;
}
function 숙련도카드(r: Record<string, unknown>): string {
  const 표시: Record<string, string> = { "Script Kiddie": "초보 해커", "Intermediate": "중급 해커", "Advanced": "고급 해커" };
  const 배지cls: Record<string, string> = { "Script Kiddie": "초보", "Intermediate": "중급", "Advanced": "고급" };
  const 등급 = String(r.등급 || "");
  const 근거 = ((r.근거목록 as string[]) || []).map((g) => `<li>${g}</li>`).join("");
  return `<div class="분석칩카드"><div class="분석칩섹션제목">공격자 숙련도 평가</div><span class="큰배지 ${배지cls[등급] || ""}">${표시[등급] || 등급}</span><ul class="포인트목록" style="margin:8px 0">${근거}</ul><p class="근거설명">${r.종합설명 || ""}</p></div>`;
}
function 대응권고카드(r: Record<string, unknown>): string {
  const 즉각 = ((r.즉각조치 as string[]) || []).map((a) => `<li>${a}</li>`).join("");
  const 장기 = ((r.장기권고 as string[]) || []).map((a) => `<li>${a}</li>`).join("");
  const p = String(r.대응우선순위 || "");
  const 우선cls = p === "즉시" ? "즉시" : p.includes("24") ? "시간" : "주";
  return `<div class="권고카드"><div class="우선순위행">대응 우선순위: <span class="우선순위배지 ${우선cls}">${p}</span></div><p class="권고섹션제목 즉각">지금 당장 해야 할 조치</p><ul class="권고목록 즉각">${즉각}</ul><p class="권고섹션제목 장기">장기적으로 해야 할 조치</p><ul class="권고목록 장기">${장기}</ul></div>`;
}
function 전체리포트카드(r: Record<string, unknown>): string {
  let h = "";
  const 소제목 = (t: string) => `<div style="margin-bottom:6px;font-size:0.8rem;font-weight:700;color:var(--text-2);">${t}</div>`;
  if (r.사건요약) h += `${소제목("사건 요약")}${사건요약카드(r.사건요약 as Record<string, unknown>)}`;
  if (r.의도분석 || r.숙련도분석) {
    h += `<hr class="결과구분선"><div class="결과그리드">`;
    if (r.의도분석) h += `<div>${소제목("공격 의도")}${의도분석카드(r.의도분석 as Record<string, unknown>)}</div>`;
    if (r.숙련도분석) h += `<div>${소제목("숙련도")}${숙련도카드(r.숙련도분석 as Record<string, unknown>)}</div>`;
    h += `</div>`;
  }
  if (r.대응권고) h += `<hr class="결과구분선">${소제목("대응 권고")}${대응권고카드(r.대응권고 as Record<string, unknown>)}`;
  if (r.리포트서술) h += `<hr class="결과구분선">${소제목("종합 리포트")}<div class="리포트서술박스">${r.리포트서술}</div>`;
  return h;
}

// ── 메인 컴포넌트 ────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [선택공격, set선택공격] = useState<공격로그입력 | null>(null);
  const [공격목록, set공격목록] = useState<공격로그입력[]>([]);
  const [목록오류, set목록오류] = useState<string | null>(null);
  const [개요, set개요] = useState({ total_events: 0, total_attacks: 0, high_risk: 0, llm_analyzed: 0 });
  const [모델정보, set모델정보] = useState<모델정보타입 | null>(null);
  // 지도는 라이브 이벤트가 흐를 때만 그려진다. 기본으로 펼쳐두면 대개 빈
  // 화면이 650px 를 차지하므로 접어둔다(사용자가 필요할 때 펼친다).
  const [맵펼침, set맵펼침] = useState(false);
  const [사용자, set사용자] = useState<string | null>(null);
  const [교차검증, set교차검증] = useState<{ 모델관여: number; 합의: number; 불일치: number; 저신뢰: number; 합의율: number | null } | null>(null);
  const [패턴, set패턴] = useState<{ 패턴목록: 패턴타입[]; 패턴수: number; 사건합계: number; 건당덮는수: number | null } | null>(null);
  // 자산 포트는 계정에 딸려 있다(/api/assets). 기기를 바꿔도 따라오고,
  // 같은 센서를 여러 사람이 공유하는 형태에서 대조만 개인별이 된다.
  // 민감한 목록이므로 본인 것만 오간다 — 경로에 사용자 id 가 없다.
  const [자산입력, set자산입력] = useState("");
  const [자산저장중, set자산저장중] = useState(false);
  const [해설, set해설] = useState<해설타입 | null>(null);
  const [해설조회중, set해설조회중] = useState(false);
  const [노출, set노출] = useState<{ 노출목록: 노출타입[]; 위험포트수: number; 해당이벤트: number } | null>(null);
  const router = useRouter();
  const [필터, set필터] = useState<"all" | "attacks" | "highrisk" | "llm">("all");
  const [분석중, set분석중] = useState(false);
  const [서버상태, set서버상태] = useState<{ 연결됨: boolean; 모델: string }>({ 연결됨: false, 모델: "" });
  const [스트리밍텍스트, set스트리밍텍스트] = useState("");
  const [결과HTML, set결과HTML] = useState("");
  const [차트HTML, set차트HTML] = useState("");
  const [단계칩, set단계칩] = useState<{ 이름: string; 상태: "pending" | "진행중" | "완료" }[]>([]);
  const [showStreaming, setShowStreaming] = useState(false);
  const [showSteps, setShowSteps] = useState(false);
  const [showPDF, setShowPDF] = useState(false);
  const [showGauge, setShowGauge] = useState(false);
  const [showGraph, setShowGraph] = useState(false);
  const [커서보임, set커서보임] = useState(false);
  const [showEmpty, setShowEmpty] = useState(true);

  const 게이지SVGRef = useRef<SVGSVGElement>(null);
  const 네트워크SVGRef = useRef<SVGSVGElement>(null);
  const 스트리밍본문Ref = useRef<HTMLDivElement>(null);
  const 시뮬레이션Ref = useRef<d3.Simulation<d3.SimulationNodeDatum, undefined> | null>(null);
  const 레이더SVGRef = useRef<SVGSVGElement | null>(null);
  const 바차트SVGRef = useRef<SVGSVGElement | null>(null);

  // ── 로그인 확인 ─────────────────────────────────────────────────────────
  // 세션은 httpOnly 쿠키라 화면에서 읽을 수 없다. 그래서 **서버에 물어보는 것이
  // 유일한 방법이고, 동시에 가장 정확한 방법이다** — 전에는 localStorage 에 값이
  // 있는지로 먼저 걸렀는데 그건 만료도 서명 키 교체도 알지 못하는 검사였다.
  useEffect(() => {
    인증fetch("/api/auth/me")
      .then(async (r) => {
        if (!r.ok) throw new Error("만료");
        const d = await r.json();
        set사용자(d.email ?? null);
      })
      .catch(() => {
        router.replace("/login");
      });
  }, [router]);

  // ── 서버 상태 확인 ──────────────────────────────────────────────────────
  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((data: { Ollama연결: boolean; 사용모델: string }) => {
        set서버상태({ 연결됨: data.Ollama연결, 모델: data.사용모델 });
      })
      .catch(() => {});
  }, []);

  // ── 실 T-Pot 공격로그 목록 로드 (ES ml-analysis-*) ────────────────────────
  const 공격목록새로고침 = useCallback(() => {
    const view = 필터 === "llm" ? "llm" : "ml";
    인증fetch(`/api/attacks?view=${view}`)
      .then((r) => r.json())
      .then((data: { 공격목록: 공격로그입력[]; 오류?: string }) => {
        set공격목록(data.공격목록 ?? []);
        set목록오류(data.오류 ?? null);
      })
      .catch((e) => set목록오류(String(e)));
  }, [필터]);
  useEffect(() => { 공격목록새로고침(); }, [공격목록새로고침]);

  // ── 24h 개요 통계 로드 (/api/overview) ───────────────────────────────────
  useEffect(() => {
    인증fetch("/api/overview")
      .then((r) => r.json())
      .then((d) => set개요({
        total_events: d.total_events ?? 0,
        total_attacks: d.total_attacks ?? 0,
        high_risk: d.high_risk ?? 0,
        llm_analyzed: d.llm_analyzed ?? 0,
      }))
      .catch(() => {});
  }, []);

  // ── 모델·규칙 교차검증 현황 ────────────────────────────────────────────
  // 학습 지표(holdout)는 학습 분포 안에서만 유효하다. 운영에서 의미 있는 건
  // "지금 들어오는 문서에 대해 모델이 규칙과 얼마나 합의하는가" 이다.
  useEffect(() => {
    인증fetch("/api/ml-stats")
      .then((r) => r.json())
      .then((d) => { if (d?.교차검증?.모델관여 > 0) set교차검증(d.교차검증); })
      .catch(() => {});
  }, []);

  // ── 공격 패턴 단위 해설 로드 (/api/llm-patterns) ───────────────────────────
  useEffect(() => {
    인증fetch("/api/llm-patterns?since=now-1y&size=8")
      .then((r) => r.json())
      .then((d) => { if (Array.isArray(d?.패턴목록) && d.패턴목록.length) set패턴(d); })
      .catch(() => {});
  }, []);

  // ── 자산 포트 복원 (계정에서) ──────────────────────────────────────────────
  useEffect(() => {
    인증fetch("/api/assets")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d && typeof d.rawText === "string" && d.rawText) { set자산입력(d.rawText); return; }
        // 계정에 없으면 예전에 이 브라우저에 저장해둔 값을 한 번 끌어올린다.
        // 다음 저장에서 계정으로 옮겨간다.
        try {
          const 옛값 = localStorage.getItem("자산포트");
          if (옛값) set자산입력(옛값);
        } catch { /* 접근이 막히면 빈 값으로 둔다 */ }
      })
      .catch(() => {});
  }, []);

  const 노출조회 = useCallback((입력: string) => {
    const 포트들 = Array.from(new Set(
      (입력.match(/\d{1,5}/g) ?? []).map(Number).filter((n) => n > 0 && n <= 65535),
    )).slice(0, 100);

    // 목록을 계정에 저장한다. 저장이 실패해도 조회는 막지 않는다 —
    // 보려던 사람이 저장 오류 때문에 아무것도 못 보는 건 과하다.
    set자산저장중(true);
    인증fetch("/api/assets", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rawText: 입력 }),
    }).catch(() => {}).finally(() => set자산저장중(false));

    if (포트들.length === 0) { set노출(null); return; }
    인증fetch(`/api/exposure?since=now-1y&ports=${포트들.join(",")}`)
      .then((r) => r.json())
      .then((d) => { if (Array.isArray(d?.노출목록)) set노출(d); })
      .catch(() => {});
  }, []);

  // ── 현재 분류 모델 메타정보 로드 (/api/model) ──────────────────────────────
  useEffect(() => {
    fetch("/api/model")
      .then((r) => r.json())
      .then((d: 모델정보타입) => { if (d.available) set모델정보(d); })
      .catch(() => {});
  }, []);

  // ── D3 게이지 ────────────────────────────────────────────────────────────
  const 게이지그리기 = useCallback((위험점수: number) => {
    if (!게이지SVGRef.current) return;
    const 건강점수 = Math.round(100 - 위험점수);
    const svg = d3.select(게이지SVGRef.current);
    svg.selectAll("*").remove();
    const W = 220, H = 115, cx = W / 2, cy = 102, R외 = 88, R내 = 58;
    const g = svg.append("g").attr("transform", `translate(${cx},${cy})`);
    const 각도 = (p: number) => -Math.PI / 2 + (p / 100) * Math.PI;
    const arc = d3.arc<{ startAngle: number; endAngle: number }>().innerRadius(R내).outerRadius(R외).cornerRadius(4);

    g.append("path").attr("d", arc({ startAngle: 각도(0), endAngle: 각도(100) }) ?? "").attr("fill", "#e2e8f0");
    ([{ s: 0, e: 34, c: "#ef4444" }, { s: 34, e: 67, c: "#f59e0b" }, { s: 67, e: 100, c: "#22c55e" }] as const).forEach(({ s, e, c }) => {
      g.append("path").attr("d", arc({ startAngle: 각도(s), endAngle: 각도(e) }) ?? "").attr("fill", c).attr("opacity", 0.18);
    });

    const 활성색 = 건강점수 < 34 ? "#ef4444" : 건강점수 < 67 ? "#f59e0b" : "#22c55e";
    const 활성arc = g.append("path").attr("fill", 활성색).attr("filter", `drop-shadow(0 0 6px ${활성색}88)`);
    const d = { startAngle: 각도(0), endAngle: 각도(0) };
    활성arc.datum(d).attr("d", arc(d) ?? "")
      .transition().duration(900).ease(d3.easeCubicOut)
      .attrTween("d", () => {
        const i = d3.interpolate(d.endAngle, 각도(건강점수));
        return (t) => { d.endAngle = i(t); return arc(d) ?? ""; };
      });

    [0, 25, 50, 75, 100].forEach((p) => {
      const θ = 각도(p);
      g.append("line").attr("x1", (R외 + 5) * Math.sin(θ)).attr("y1", -(R외 + 5) * Math.cos(θ))
        .attr("x2", (R외 + 11) * Math.sin(θ)).attr("y2", -(R외 + 11) * Math.cos(θ))
        .attr("stroke", "#cbd5e1").attr("stroke-width", 1.5).attr("stroke-linecap", "round");
      g.append("text").attr("x", (R외 + 20) * Math.sin(θ)).attr("y", -(R외 + 20) * Math.cos(θ))
        .attr("text-anchor", "middle").attr("dominant-baseline", "middle")
        .attr("font-size", "9px").attr("fill", "#94a3b8").text(p);
    });

    const 바늘 = g.append("line").attr("x1", 0).attr("y1", 0).attr("x2", 0).attr("y2", 0)
      .attr("stroke", "#1a1a2e").attr("stroke-width", 2.5).attr("stroke-linecap", "round");
    const L = R내 - 6;
    바늘.transition().duration(900).ease(d3.easeCubicOut)
      .attrTween("x2", () => { const i = d3.interpolate(0, L * Math.sin(각도(건강점수))); return (t) => String(i(t)); })
      .attrTween("y2", () => { const i = d3.interpolate(0, -L * Math.cos(각도(건강점수))); return (t) => String(i(t)); });

    g.append("circle").attr("r", 6).attr("fill", "#1a1a2e");
    g.append("text").attr("text-anchor", "middle").attr("y", -16)
      .attr("font-size", "28px").attr("font-weight", "800").attr("fill", 활성색).text(건강점수);
    g.append("text").attr("text-anchor", "middle").attr("y", 0)
      .attr("font-size", "10px").attr("fill", "#94a3b8").text("/ 100");
  }, []);

  // ── D3 네트워크 그래프 ───────────────────────────────────────────────────
  const 네트워크그래프그리기 = useCallback((로그: 공격로그입력) => {
    if (!네트워크SVGRef.current) return;
    const svgEl = 네트워크SVGRef.current;
    const W = svgEl.getBoundingClientRect().width || 560, H = 260;
    const svg = d3.select(svgEl).attr("viewBox", `0 0 ${W} ${H}`).attr("width", W).attr("height", H);
    svg.selectAll("*").remove();
    if (시뮬레이션Ref.current) 시뮬레이션Ref.current.stop();

    type 노드타입 = d3.SimulationNodeDatum & { id: string; label: string; sub?: string; type: string };
    const 노드: 노드타입[] = [
      { id: "attacker", label: 로그.공격자IP, sub: 로그.공격자국가 ?? "", type: "attacker" },
      ...로그.행위시퀀스.map((행위, i) => ({ id: `act_${i}`, label: 행위, type: "action" })),
      { id: "honeypot", label: "허니팟", sub: 로그.허니팟ID, type: "honeypot" },
    ];
    type 링크타입 = d3.SimulationLinkDatum<노드타입> & { source: string | 노드타입; target: string | 노드타입 };
    const 링크: 링크타입[] = [];
    let 이전 = "attacker";
    로그.행위시퀀스.forEach((_, i) => { 링크.push({ source: 이전, target: `act_${i}` }); 이전 = `act_${i}`; });
    링크.push({ source: 이전, target: "honeypot" });

    const defs = svg.append("defs");
    defs.append("marker").attr("id", "화살표").attr("viewBox", "0 -5 10 10").attr("refX", 28).attr("refY", 0).attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", "auto")
      .append("path").attr("d", "M0,-5L10,0L0,5").attr("fill", "#94a3b8");
    const 필터 = defs.append("filter").attr("id", "glow").attr("x", "-30%").attr("y", "-30%").attr("width", "160%").attr("height", "160%");
    필터.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "blur");
    필터.append("feMerge").selectAll("feMergeNode").data(["blur", "SourceGraphic"]).join("feMergeNode").attr("in", (d) => d);

    const 링크El = svg.append("g").selectAll("line").data(링크).join("line")
      .attr("stroke", "#e2e8f0").attr("stroke-width", 2).attr("stroke-dasharray", "7 4").attr("marker-end", "url(#화살표)");
    const 노드El = svg.append("g").selectAll<SVGGElement, 노드타입>("g").data(노드).join("g").attr("cursor", "default");

    노드El.append("circle")
      .attr("r", (d) => d.type === "action" ? 20 : 28)
      .attr("fill", (d) => d.type === "attacker" ? "#fee2e2" : d.type === "honeypot" ? "#eef2ff" : "#f8fafc")
      .attr("stroke", (d) => d.type === "attacker" ? "#ef4444" : d.type === "honeypot" ? "#6366f1" : "#cbd5e1")
      .attr("stroke-width", 2).attr("filter", (d) => d.type === "attacker" ? "url(#glow)" : null);
    노드El.filter((d) => d.type !== "action").append("text")
      .attr("text-anchor", "middle").attr("dominant-baseline", "central").attr("font-size", "16px")
      .text((d) => d.type === "attacker" ? "!" : "HP");
    노드El.filter((d) => d.type === "action").append("text")
      .attr("text-anchor", "middle").attr("dominant-baseline", "central")
      .attr("font-size", "9.5px").attr("font-weight", "600").attr("fill", "#475569")
      .text((d) => d.label.slice(0, 5));
    노드El.append("text").attr("text-anchor", "middle").attr("y", (d) => d.type === "action" ? 30 : 38)
      .attr("font-size", "10px").attr("font-weight", "600").attr("fill", "#374151")
      .text((d) => d.label.length > 13 ? d.label.slice(0, 13) + "…" : d.label);
    노드El.filter((d) => !!d.sub).append("text").attr("text-anchor", "middle").attr("y", (d) => d.type === "action" ? 43 : 50)
      .attr("font-size", "9px").attr("fill", "#94a3b8").text((d) => d.sub ?? "");

    function 입자생성(링크d: 링크타입) {
      const 입자 = svg.append("circle").attr("r", 4).attr("fill", "#ef4444").attr("opacity", 0.85).attr("filter", "url(#glow)");
      function 이동() {
        const src = 링크d.source as 노드타입;
        const tgt = 링크d.target as 노드타입;
        if (!src.x) return;
        입자.attr("cx", src.x!).attr("cy", src.y!)
          .transition().duration(1200).ease(d3.easeLinear)
          .attr("cx", tgt.x!).attr("cy", tgt.y!)
          .on("end", () => setTimeout(이동, Math.random() * 800));
      }
      setTimeout(이동, Math.random() * 1000);
    }

    const sim = d3.forceSimulation<노드타입>(노드)
      .force("link", d3.forceLink<노드타입, 링크타입>(링크).id((d) => d.id).distance(95))
      .force("charge", d3.forceManyBody().strength(-260))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("x", d3.forceX(W / 2).strength(0.04))
      .force("y", d3.forceY(H / 2).strength(0.06))
      .on("tick", () => {
        링크El.attr("x1", (d) => (d.source as 노드타입).x!).attr("y1", (d) => (d.source as 노드타입).y!)
          .attr("x2", (d) => (d.target as 노드타입).x!).attr("y2", (d) => (d.target as 노드타입).y!);
        노드El.attr("transform", (d) => `translate(${Math.max(32, Math.min(W - 32, d.x!))},${Math.max(32, Math.min(H - 32, d.y!))})`);
      })
      .on("end", () => { 링크.forEach((l) => 입자생성(l)); });

    시뮬레이션Ref.current = sim as unknown as d3.Simulation<d3.SimulationNodeDatum, undefined>;
  }, []);

  // ── 공격 로그 선택 ───────────────────────────────────────────────────────
  function 공격선택(a: 공격로그입력) {
    set선택공격(a);
    setShowEmpty(false);
    setShowGauge(true);
    setShowGraph(true);
    setTimeout(() => {
      게이지그리기(a.위험점수);
      네트워크그래프그리기(a);
    }, 50);

    // 이미 만들어둔 해설이 있으면 바로 보여준다. 추론을 부르지 않는다.
    set해설(null);
    const id = (a as unknown as { _doc_id?: string })._doc_id;
    if (!id) return;
    set해설조회중(true);
    인증fetch(`/api/llm-explain?id=${encodeURIComponent(id)}`)
      .then((r) => r.json())
      .then((d: 해설타입) => { if (d?.found) set해설(d); })
      .catch(() => {})
      .finally(() => set해설조회중(false));
  }

  // ── 분석 시작 ────────────────────────────────────────────────────────────
  async function 분석시작() {
    if (!선택공격 || 분석중) return;
    set분석중(true);
    set결과HTML("");
    set차트HTML("");
    set스트리밍텍스트("");
    setShowPDF(false);
    setShowStreaming(true);
    setShowSteps(true);
    set커서보임(true);
    set단계칩([
      { 이름: "사건 요약", 상태: "pending" },
      { 이름: "공격 의도", 상태: "pending" },
      { 이름: "숙련도 분석", 상태: "pending" },
      { 이름: "대응 권고", 상태: "pending" },
      { 이름: "리포트 서술", 상태: "pending" },
    ]);

    try {
      const res = await 인증fetch("/api/analyze/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 분석유형: "전체리포트", 로그: 선택공격 }),
      });

      // 관문(인증·쿼터·동시 실행)이 막으면 본문은 스트림이 아니라 JSON 이다.
      // 그대로 reader 를 열면 파싱이 조용히 실패해 "분석 중" 에서 멈춘 것처럼
      // 보이므로, 왜 막혔는지를 화면에 그대로 보여준다.
      if (!res.ok) {
        const 사유 = await res.json().catch(() => ({ message: `요청이 거부되었습니다 (${res.status})` }));
        set결과HTML(`<div class="오류박스">${String((사유 as { message?: string }).message ?? "분석을 시작할 수 없습니다.")}</div>`);
        set분석중(false);
        set커서보임(false);
        return;
      }
      if (!res.body) {
        set결과HTML(`<div class="오류박스">응답 본문이 비어 있습니다. 서버 상태를 확인해주세요.</div>`);
        set분석중(false);
        set커서보임(false);
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try { 이벤트처리(JSON.parse(line.slice(6)) as Record<string, unknown>); } catch { /* skip */ }
          }
        }
      }
    } catch (e) {
      set결과HTML(`<div class="오류박스">연결 오류: ${String(e)}<br>서버가 실행 중인지 확인해주세요.</div>`);
    }

    set분석중(false);
    set커서보임(false);
  }

  function 이벤트처리(ev: Record<string, unknown>) {
    switch (ev.유형) {
      case "시작":
        set스트리밍텍스트((p) => p + `▶ ${ev.메시지}\n\n`);
        break;
      case "단계시작":
        set단계칩((prev) => prev.map((c, i) => i === (Number(ev.단계) - 1) ? { ...c, 상태: "진행중" } : c));
        set스트리밍텍스트((p) => p + `\n\n── [${ev.단계}/${ev.총단계}] ${ev.이름} ──\n`);
        break;
      case "단계완료":
        set단계칩((prev) => prev.map((c, i) => i === (Number(ev.단계) - 1) ? { ...c, 상태: "완료" } : c));
        break;
      case "토큰":
        set스트리밍텍스트((p) => p + String(ev.텍스트));
        setTimeout(() => {
          if (스트리밍본문Ref.current) 스트리밍본문Ref.current.scrollTop = 스트리밍본문Ref.current.scrollHeight;
        }, 10);
        break;
      case "완료": {
        set스트리밍텍스트((p) => p + "\n\n분석 완료");
        const 결과 = ev.결과 as Record<string, unknown>;
        const 유형이름: Record<string, string> = { 사건요약: "사건 요약", 의도분석: "공격 의도 분석", 숙련도분석: "숙련도 분석", 대응권고: "대응 권고", 전체리포트: "전체 분석 리포트" };
        const 유형 = String(ev.분석유형);
        let html = `<div class="카드"><div class="결과카드헤더"><span class="결과카드제목">${유형이름[유형] || "분석 결과"}</span><span class="결과카드부제">AI 분석 완료</span></div>`;
        if (유형 === "사건요약") html += 사건요약카드(결과);
        else if (유형 === "의도분석") html += 의도분석카드(결과);
        else if (유형 === "숙련도분석") html += 숙련도카드(결과);
        else if (유형 === "대응권고") html += 대응권고카드(결과);
        else if (유형 === "전체리포트") html += 전체리포트카드(결과);
        html += `</div>`;
        set결과HTML(html);

        if (유형 === "전체리포트" && 선택공격) {
          setShowPDF(true);
          // 차트 렌더링은 다음 tick 이후 D3 ref가 DOM에 있을 때 수행
          set차트HTML("__RENDER_CHARTS__");
          setTimeout(() => {
            if (레이더SVGRef.current && 바차트SVGRef.current) {
              const 숙련도점수: Record<string, number> = { "Script Kiddie": 25, "Intermediate": 60, "Advanced": 92 };
              const 의도점수: Record<string, number> = { 정보수집: 22, 취약점탐색: 48, 침투시도: 72, 데이터탈취: 88, 서비스방해: 65 };
              const 의도 = 결과.의도분석 as Record<string, unknown> | undefined;
              const 숙련도 = 결과.숙련도분석 as Record<string, unknown> | undefined;
              const 권고 = 결과.대응권고 as Record<string, unknown> | undefined;
              const 숙련도점수값 = 숙련도점수[String(숙련도?.등급 ?? "")] ?? 50;
              const 의도점수값 = 의도점수[String(의도?.의도 ?? "")] ?? 50;
              const p = String(권고?.대응우선순위 ?? "");
              const 긴급도 = p.includes("즉시") ? 95 : p.includes("24") ? 65 : 40;
              레이더차트그리기([
                { 축: "위험도", 값: 선택공격.위험점수 },
                { 축: "정교함", 값: 숙련도점수값 },
                { 축: "파급력", 값: 의도점수값 },
                { 축: "탐지신뢰도", 값: (선택공격.탐지신뢰도 || 0.8) * 100 },
                { 축: "긴급도", 값: 긴급도 },
              ]);
              바차트그리기([
                { 항목: "위험 점수", 값: 선택공격.위험점수, 색: "#ef4444" },
                { 항목: "탐지 신뢰도", 값: (선택공격.탐지신뢰도 || 0.8) * 100, 색: "#6366f1" },
                { 항목: "공격자 정교함", 값: 숙련도점수값, 색: "#f59e0b" },
                { 항목: "파급력 점수", 값: 의도점수값, 색: "#8b5cf6" },
                { 항목: "대응 긴급도", 값: 긴급도, 색: "#dc2626" },
              ]);
            }
          }, 100);
        }
        break;
      }
      case "오류":
        set결과HTML(`<div class="오류박스">${ev.메시지}</div>`);
        break;
      // 모델 응답에 한자가 섞였거나 파싱이 깨져 대체 내용으로 채웠을 때.
      // 오류와 달리 분석은 계속되므로 지금까지 나온 것을 지우지 않고 덧붙인다 —
      // 사용자가 대체된 내용을 정상 결과로 읽지 않게 하는 게 목적이다.
      case "경고":
        set결과HTML((이전) => `${이전}<div class="경고박스">${ev.메시지}</div>`);
        break;
    }
  }

  // ── D3 레이더 차트 ───────────────────────────────────────────────────────
  function 레이더차트그리기(데이터목록: { 축: string; 값: number }[]) {
    if (!레이더SVGRef.current) return;
    const svg = d3.select(레이더SVGRef.current);
    svg.selectAll("*").remove();
    const W = 280, H = 260, cx = W / 2, cy = H / 2 + 10, R = 90;
    const N = 데이터목록.length;
    const 각도fn = (i: number) => (Math.PI * 2 * i / N) - Math.PI / 2;
    const 값to좌표 = (i: number, 값: number): [number, number] => {
      const r = (값 / 100) * R;
      return [cx + r * Math.cos(각도fn(i)), cy + r * Math.sin(각도fn(i))];
    };
    const g = svg.append("g");

    [20, 40, 60, 80, 100].forEach((p) => {
      const pts = d3.range(N).map((i) => 값to좌표(i, p));
      g.append("polygon").attr("points", pts.map((d) => d.join(",")).join(" "))
        .attr("fill", p === 100 ? "#f8fafc" : "none").attr("stroke", "#e2e8f0").attr("stroke-width", p === 100 ? 1.5 : 1);
    });
    d3.range(N).forEach((i) => {
      const [x, y] = 값to좌표(i, 100);
      g.append("line").attr("x1", cx).attr("y1", cy).attr("x2", x).attr("y2", y).attr("stroke", "#e2e8f0").attr("stroke-width", 1);
    });
    const pts = 데이터목록.map((d, i) => 값to좌표(i, d.값));
    g.append("polygon").attr("points", pts.map((d) => d.join(",")).join(" ")).attr("fill", "#6366f130").attr("stroke", "#6366f1").attr("stroke-width", 2);
    pts.forEach(([x, y]) => {
      g.append("circle").attr("cx", x).attr("cy", y).attr("r", 4).attr("fill", "#6366f1").attr("stroke", "white").attr("stroke-width", 1.5);
    });
    데이터목록.forEach((d, i) => {
      const [x, y] = 값to좌표(i, 118);
      const 정렬 = x < cx - 5 ? "end" : x > cx + 5 ? "start" : "middle";
      g.append("text").attr("x", x).attr("y", y).attr("text-anchor", 정렬).attr("dominant-baseline", "middle").attr("font-size", "11px").attr("font-weight", "700").attr("fill", "#374151").text(d.축);
      g.append("text").attr("x", x).attr("y", y + 13).attr("text-anchor", 정렬).attr("dominant-baseline", "middle").attr("font-size", "10px").attr("fill", "#6366f1").attr("font-weight", "800").text(Math.round(d.값));
    });
  }

  // ── D3 바 차트 ───────────────────────────────────────────────────────────
  function 바차트그리기(데이터목록: { 항목: string; 값: number; 색: string }[]) {
    if (!바차트SVGRef.current) return;
    const svg = d3.select(바차트SVGRef.current);
    svg.selectAll("*").remove();
    const W = 280, 여백L = 80, 여백R = 45, 여백T = 15;
    const 바높이 = 24, 바간격 = 20;
    const 바영역W = W - 여백L - 여백R;
    const g = svg.append("g").attr("transform", `translate(${여백L},${여백T})`);

    데이터목록.forEach((d, i) => {
      const y = i * (바높이 + 바간격);
      const barW = (d.값 / 100) * 바영역W;
      g.append("rect").attr("x", 0).attr("y", y).attr("width", 바영역W).attr("height", 바높이).attr("rx", 6).attr("fill", "#f1f5f9");
      g.append("rect").attr("x", 0).attr("y", y).attr("width", 0).attr("height", 바높이).attr("rx", 6).attr("fill", d.색).attr("opacity", 0.85)
        .transition().duration(800).delay(i * 100).ease(d3.easeCubicOut).attr("width", barW);
      g.append("text").attr("x", -8).attr("y", y + 바높이 / 2).attr("text-anchor", "end").attr("dominant-baseline", "middle").attr("font-size", "11px").attr("font-weight", "600").attr("fill", "#374151").text(d.항목);
      g.append("text").attr("x", 바영역W + 6).attr("y", y + 바높이 / 2).attr("dominant-baseline", "middle").attr("font-size", "11px").attr("font-weight", "800").attr("fill", d.색).text(Math.round(d.값));
    });
  }

  // ── PDF 저장 ─────────────────────────────────────────────────────────────
  async function PDF저장() {
    if (!선택공격) return;
    const { default: html2canvas } = await import("html2canvas");
    const { jsPDF } = await import("jspdf");

    const 시각 = new Date().toLocaleString("ko-KR");
    const 결과내용 = 결과HTML;
    const 임시div = document.createElement("div");
    임시div.style.cssText = "position:absolute;top:0;left:0;width:794px;background:#ffffff;padding:40px 44px;z-index:9999;font-family:-apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo','Noto Sans KR',sans-serif;color:#1a1a2e;box-sizing:border-box;";
    임시div.innerHTML = `
      <div style="padding-bottom:16px;border-bottom:3px solid #0f172a;margin-bottom:24px;">
        <div style="font-size:1.3rem;font-weight:800;color:#0f172a;">정사평 — 허니팟 공격 분석 리포트</div>
        <div style="font-size:0.8rem;color:#64748b;margin-top:5px;">공격: ${공격표시명(선택공격)} · ${선택공격.공격자IP} · 생성: ${시각}</div>
      </div>
      <div>${결과내용}</div>
    `;
    document.body.appendChild(임시div);
    const 이전스크롤Y = window.scrollY;
    window.scrollTo(0, 0);
    try {
      const canvas = await html2canvas(임시div, { scale: 2, useCORS: true, logging: false, backgroundColor: "#ffffff", scrollX: 0, scrollY: 0, windowWidth: 794 });
      const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const margin = 12, contentW = 210 - margin * 2, contentH = 297 - margin * 2;
      const totalImgH = (canvas.height / canvas.width) * contentW;
      const totalPages = Math.ceil(totalImgH / contentH);
      for (let i = 0; i < totalPages; i++) {
        if (i > 0) pdf.addPage();
        const srcY = Math.round((i * contentH / totalImgH) * canvas.height);
        const srcH = Math.round(Math.min((contentH / totalImgH) * canvas.height, canvas.height - srcY));
        const destH = (srcH / canvas.height) * totalImgH;
        const slice = document.createElement("canvas");
        slice.width = canvas.width; slice.height = Math.max(srcH, 1);
        const ctx = slice.getContext("2d")!;
        ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, slice.width, slice.height);
        ctx.drawImage(canvas, 0, srcY, canvas.width, srcH, 0, 0, canvas.width, srcH);
        pdf.addImage(slice.toDataURL("image/jpeg", 0.95), "JPEG", margin, margin, contentW, destH);
      }
      pdf.save(`정사평_공격분석_${공격표시명(선택공격)}_${new Date().toISOString().slice(0, 10)}.pdf`);
    } finally {
      document.body.removeChild(임시div);
      window.scrollTo(0, 이전스크롤Y);
    }
  }

  const 단계이름 = ["사건 요약", "공격 의도", "숙련도 분석", "대응 권고", "리포트 서술"];
  const 건강점수 = 선택공격 ? Math.round(100 - 선택공격.위험점수) : null;
  const 활성색 = 건강점수 !== null ? (건강점수 < 34 ? "#ef4444" : 건강점수 < 67 ? "#f59e0b" : "#22c55e") : "#22c55e";
  const 건강라벨 = 건강점수 !== null ? (건강점수 < 34 ? "위험" : 건강점수 < 67 ? "주의" : "양호") : "";

  // 개요 스탯 클릭 필터 적용
  const 표시목록 = 공격목록.filter((a) => {
    if (필터 === "attacks") return (a as unknown as { _is_attack?: boolean })._is_attack !== false;
    if (필터 === "highrisk") return a.위험점수 >= 70;
    return true; // all / llm (소스에서 이미 필터됨)
  });

  /* 유형별 건수와 그 유형에서 관측된 최고 위험등급. 건수 내림차순. */
  const 유형분포: [string, number, string][] = (() => {
    const 순위: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    const 집계 = new Map<string, { 수: number; 최고: string }>();
    표시목록.forEach((a) => {
      const 이름 = 공격표시명(a);
      const 현재 = 집계.get(이름) ?? { 수: 0, 최고: "LOW" };
      현재.수 += 1;
      if ((순위[a.위험등급] ?? 0) > (순위[현재.최고] ?? 0)) 현재.최고 = a.위험등급;
      집계.set(이름, 현재);
    });
    return [...집계.entries()]
      .map(([이름, v]) => [이름, v.수, v.최고] as [string, number, string])
      .sort((x, y) => y[1] - x[1]);
  })();
  const 필터라벨: Record<string, string> = { all: "전체", attacks: "분류된 공격", highrisk: "고위험 ≥ 70", llm: "LLM 분석" };

  return (
    <>
      <style>{`
        body { background: var(--bg); color: var(--text); min-height: 100vh; }
        header { position: sticky; top: 0; z-index: 50; background: var(--chrome); color: var(--chrome-text); padding: 0 26px; display: flex; align-items: center; justify-content: space-between; height: 60px; border-bottom: 1px solid var(--chrome-border); }
        .헤더왼쪽 { display: flex; align-items: center; gap: 11px; }
        .헤더제목 { font-size: 1rem; font-weight: 800; letter-spacing: -0.01em; color: var(--chrome-text); }
        .헤더제목 span { color: var(--chrome-accent); }
        .헤더부제 { font-size: 0.7rem; color: var(--chrome-text-2); margin-top: 1px; }
        .헤더우측 { display: flex; align-items: center; gap: 10px; }
        .세션칩 { display: flex; align-items: center; gap: 10px; background: rgba(255,255,255,0.06); border: 1px solid var(--chrome-border); border-radius: var(--radius-sm); padding: 5px 6px 5px 12px; }
        .세션이메일 { font-family: var(--mono); font-size: 0.74rem; color: var(--chrome-text-2); }
        .로그아웃 { font-size: 0.74rem; font-weight: 600; color: var(--chrome-text); background: rgba(255,255,255,0.08); border: 1px solid var(--chrome-border); border-radius: 3px; padding: 4px 9px; cursor: pointer; }
        .로그아웃:hover { background: rgba(255,255,255,0.16); }
        .서버상태칩 { display: flex; align-items: center; gap: 7px; background: rgba(255,255,255,0.06); border: 1px solid var(--chrome-border); border-radius: 20px; padding: 6px 13px; font-size: 0.78rem; color: var(--chrome-text-2); font-weight: 500; }
        .레이아웃 { display: grid; grid-template-columns: minmax(400px, 460px) minmax(0, 1fr); gap: 20px; padding: 20px 28px; max-width: 1760px; margin: 0 auto; align-items: start; }
        @media (max-width: 1100px) { .레이아웃 { grid-template-columns: 1fr; } }
        .맵섹션 { max-width: 1760px; margin: 0 auto; padding: 24px 28px 0; }
        .모델밴드 { max-width: 1760px; margin: 0 auto; padding: 16px 28px 0; }
        .모델카드 { display: flex; flex-direction: column; gap: 14px; }
        .모델헤더 { display: flex; align-items: center; gap: 12px; }
        .모델아이콘 { width: 40px; height: 40px; border-radius: 10px; background: var(--accent); color: #fff; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .모델아이콘 .icon { width: 22px; height: 22px; }
        .모델제목 { font-size: 1rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 8px; }
        .모델배지 { font-size: 0.7rem; font-weight: 700; padding: 2px 8px; border-radius: 6px; background: #eef2ff; color: var(--accent); }
        .모델부제 { font-size: 0.76rem; color: var(--text-3); margin-top: 3px; }
        .모델지표그리드 { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; }
        .모델지표 { background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 12px 14px; text-align: center; }
        .모델지표값 { display: block; font-size: 1.3rem; font-weight: 800; color: var(--accent); }
        .모델지표라벨 { display: block; font-size: 0.7rem; color: var(--text-3); margin-top: 3px; }
        .교차검증 { margin: 4px 0 12px; }
        .교차행 { display: grid; grid-template-columns: 110px minmax(0,1fr) 52px; gap: 12px; align-items: center; }
        .교차라벨 { font-size: 0.84rem; font-weight: 600; }
        .교차막대 { height: 8px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 2px; overflow: hidden; }
        .교차채움 { display: block; height: 100%; background: var(--accent); }
        .교차값 { font-family: var(--mono); font-size: 0.86rem; font-weight: 600; text-align: right; font-variant-numeric: tabular-nums; }
        .교차설명 { font-size: 0.79rem; line-height: 1.6; color: var(--text-2); margin-top: 8px; }
        .모델설명 { font-size: 0.86rem; line-height: 1.65; color: var(--text-2); background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 12px 14px; }
        .모델배지-규칙 { background: #fdf2e3; color: #8a5a10; border-color: #e8c98d; }
        .모델라벨칩들 { display: flex; flex-wrap: wrap; gap: 6px; }
        .모델라벨칩 { font-size: 0.72rem; font-weight: 600; padding: 3px 10px; border-radius: 999px; background: var(--surface-2); border: 1px solid var(--border); color: var(--text-2); }
        .해설카드 { display: flex; flex-direction: column; gap: 9px; padding: 14px 16px; }
        .해설머리 { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
        .해설제목 { font-size: 0.86rem; font-weight: 700; color: var(--text); }
        .해설꼬리표 { font-size: 0.68rem; font-weight: 600; padding: 2px 7px; border-radius: 20px; background: var(--surface-2); border: 1px solid var(--border); color: var(--text-3); }
        .해설즉시 { margin-left: auto; font-size: 0.7rem; color: var(--green); font-weight: 600; }
        .해설본문 { font-size: 0.85rem; line-height: 1.68; color: var(--text); }
        .해설대응 { font-size: 0.8rem; line-height: 1.62; color: var(--text-2); background: var(--surface-3); border-left: 3px solid var(--accent); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; padding: 9px 11px; }
        .해설대응 b { color: var(--accent); font-weight: 700; }
        .자산밴드 { max-width: 1760px; margin: 0 auto; padding: 16px 28px 0; }
        .자산카드 { display: flex; flex-direction: column; gap: 12px; }
        .자산입력줄 { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-start; }
        .자산입력 { flex: 1 1 320px; max-width: 520px; min-width: 0; font-family: var(--mono); font-size: 0.82rem; line-height: 1.6; padding: 9px 11px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface-2); color: var(--text); resize: vertical; min-height: 44px; }
        .자산입력:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
        .자산버튼 { font-size: 0.8rem; font-weight: 600; padding: 9px 16px; border: 1px solid var(--accent); background: var(--accent); color: #fff; border-radius: var(--radius-sm); cursor: pointer; font-family: inherit; }
        .자산버튼:hover { filter: brightness(1.08); }
        .자산결론 { font-size: 0.88rem; line-height: 1.6; color: var(--text-2); }
        .자산결론 b { color: var(--red); font-variant-numeric: tabular-nums; }
        .자산결론 b.무사 { color: var(--green); }
        /* 전폭으로 퍼지면 포트와 값이 화면 양 끝으로 벌어져 눈이 못 따라간다. */
        .노출표 { width: 100%; max-width: 780px; border-collapse: collapse; font-size: 0.84rem; }
        .노출표 th { text-align: right; font-weight: 600; color: var(--text-3); font-size: 0.72rem; letter-spacing: .03em; padding: 6px 12px; border-bottom: 1px solid var(--border-strong); white-space: nowrap; }
        .노출표 th:first-child, .노출표 td:first-child { text-align: left; }
        .노출표 td { padding: 8px 12px; border-bottom: 1px solid var(--border); text-align: right; font-variant-numeric: tabular-nums; font-family: var(--mono); color: var(--text-2); }
        .노출표 tr:last-child td { border-bottom: none; }
        /* 고위험을 받고 있는 포트는 한눈에 갈라야 한다. */
        .노출표 td:first-child { border-left: 3px solid transparent; }
        .노출표 tr.위험 td:first-child { border-left-color: var(--red); }
        .노출표 tr.위험 .노출고위험 { color: var(--red); font-weight: 700; }
        .노출표 tr:not(.위험) .노출포트 { color: var(--text-3); font-weight: 600; }
        .노출포트 { font-weight: 700; color: var(--text); font-size: 0.92rem; }
        .패턴밴드 { max-width: 1760px; margin: 0 auto; padding: 16px 28px 0; }
        .패턴헤더 { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 14px; margin-bottom: 12px; }
        .패턴제목 { font-size: 1rem; font-weight: 700; color: var(--text); }
        .패턴요지 { font-size: 0.8rem; color: var(--text-3); }
        .패턴요지 b { color: var(--accent); font-variant-numeric: tabular-nums; }
        /* 좁으면 한 줄에 서너 어절밖에 못 들어가 줄바꿈이 잦다. */
        .패턴그리드 { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 12px; }
        .패턴카드 { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 15px 17px; display: flex; flex-direction: column; gap: 10px; min-width: 0; }
        .패턴상단 { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
        /* 카드의 주 정보는 건수다. 제목처럼 세운다. */
        .패턴건수 { font-size: 1.32rem; font-weight: 800; color: var(--text); font-variant-numeric: tabular-nums; line-height: 1; }
        .패턴건수 span { font-size: 0.78rem; font-weight: 600; color: var(--text-3); margin-left: 2px; }
        .패턴키 { font-family: var(--mono); font-size: 0.76rem; color: var(--text-2); }
        .패턴곁수치 { display: flex; gap: 12px; flex-wrap: wrap; font-size: 0.75rem; color: var(--text-3); font-variant-numeric: tabular-nums; }
        .패턴곁수치 b { font-family: var(--mono); font-weight: 600; color: var(--text-2); }
        .패턴요약 { font-size: 0.86rem; line-height: 1.68; color: var(--text); }
        /* 대응은 "지금 할 일" 이라 요약과 확실히 갈라야 한다. 배경색 차이만으로는
           흰 카드 위에서 거의 안 보여서(surface-2 는 #f8fafc) 좌측 강조선을 쓴다. */
        .패턴대응 { font-size: 0.82rem; line-height: 1.62; color: var(--text-2); background: var(--surface-3); border-left: 3px solid var(--accent); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; padding: 10px 12px; }
        .패턴대응 b { color: var(--accent); font-weight: 700; }
        .패턴기법 { display: flex; flex-wrap: wrap; gap: 5px; }
        .패턴기법 span { font-family: var(--mono); font-size: 0.68rem; padding: 2px 7px; border-radius: 4px; background: var(--surface-2); border: 1px solid var(--border); color: var(--text-3); }
        .맵아이프레임 { width: 100%; height: 640px; border: none; border-radius: 10px; background: #020817; display: block; }
        @media (max-width: 900px) { .맵아이프레임 { height: 440px; } }
        .맵토글 { display: inline-flex; align-items: center; gap: 5px; cursor: pointer; font-size: 0.74rem; color: var(--text-2); background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 5px 11px; }
        .맵토글:hover { border-color: var(--accent); color: var(--accent); }
        .개요밴드 { max-width: 1760px; margin: 0 auto; padding: 24px 28px 0; display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
        .스탯카드 { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow-sm); padding: 15px 18px; display: flex; align-items: center; gap: 14px; width: 100%; text-align: left; cursor: pointer; font-family: inherit; transition: all 0.15s; }
        .스탯카드:hover { border-color: var(--accent-border); transform: translateY(-1px); box-shadow: var(--shadow-md); }
        .스탯카드.활성 { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(99,102,241,0.14); }
        .스탯아이콘 { width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.35rem; flex-shrink: 0; }
        .스탯아이콘.이벤트 { background: var(--accent-soft); color: var(--accent); }
        /* 고위험은 다른 지표와 무게가 다르다 — 건수가 있을 때만 테두리로 드러낸다. */
        .스탯카드.위험강조.주의 { border-color: var(--red-border); }
        .스탯카드.위험강조.주의 .스탯값 { color: var(--red); }
        .스탯아이콘.공격 { background: var(--red-soft); color: var(--red); }
        .스탯아이콘.고위험 { background: var(--amber-soft); color: var(--amber); }
        .스탯아이콘.llm { background: #f5f3ff; color: #7c3aed; }
        .스탯값 { font-size: 1.55rem; font-weight: 800; line-height: 1; color: var(--text); }
        .스탯라벨 { font-size: 0.75rem; color: var(--text-3); margin-top: 5px; }
        .단계카드헤더 { display: flex; align-items: center; gap: 9px; margin-bottom: 13px; }
        .단계번호 { width: 24px; height: 24px; border-radius: 50%; background: var(--accent); color: #fff; font-size: 0.78rem; font-weight: 800; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .단계제목 { font-size: 0.92rem; font-weight: 800; color: var(--text); }
        .단계부제 { font-size: 0.74rem; color: var(--text-3); margin-left: auto; }
        .분류그리드 { display: grid; grid-template-columns: repeat(auto-fit, minmax(125px, 1fr)); gap: 10px; }
        .분류항목 { background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 12px; }
        .분류라벨 { font-size: 0.7rem; color: var(--text-3); display: block; margin-bottom: 4px; }
        .분류값 { font-size: 0.95rem; font-weight: 700; color: var(--text); }
        @media (max-width: 900px) { .개요밴드 { grid-template-columns: repeat(2,1fr); } }
        .카드 { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px 20px; box-shadow: var(--shadow-sm); }
        .섹션헤더 { display: flex; align-items: center; gap: 9px; margin-bottom: 14px; }
        .섹션번호 { width: 22px; height: 22px; border-radius: 7px; background: var(--accent); color: white; font-size: 0.72rem; font-weight: 800; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .섹션제목 { font-size: 0.88rem; font-weight: 700; color: var(--text); }
        .섹션설명 { font-size: 0.75rem; color: var(--text-3); margin-left: auto; display: inline-flex; align-items: center; gap: 4px; }
        /* 바깥 패널에 스크롤을 걸면 목록 스크롤과 겹쳐 중첩 스크롤이 된다.
           페이지가 자연스럽게 스크롤되게 두고, 스크롤은 목록에만 준다. */
        .왼쪽패널 { display: flex; flex-direction: column; gap: 12px; }
        .공격목록 { display: flex; flex-direction: column; gap: 6px; overflow-y: auto;
                    max-height: clamp(320px, calc(100vh - 400px), 640px); padding-right: 4px; }
        .공격목록::-webkit-scrollbar { width: 8px; }
        .공격목록::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 4px; }
        .왼쪽패널::-webkit-scrollbar { width: 4px; }
        .왼쪽패널::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 2px; }
                /* 위험도는 숫자·배지만이 아니라 형태로도 읽혀야 한다 — 왼쪽 띠로 스캔 가능하게. */
        .시나리오버튼 { width: 100%; text-align: left; padding: 10px 13px 10px 15px; border: 1px solid var(--border); border-left: 3px solid var(--border-strong); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; background: var(--surface); cursor: pointer; transition: all 0.16s; display: block; }
        .시나리오버튼.위험띠-CRITICAL { border-left-color: var(--red); }
        .시나리오버튼.위험띠-HIGH     { border-left-color: var(--red); }
        .시나리오버튼.위험띠-MEDIUM   { border-left-color: var(--amber); }
        .시나리오버튼.위험띠-LOW      { border-left-color: var(--border-strong); }
        .시나리오버튼:hover { border-color: var(--accent-border); background: var(--accent-soft); }
        .시나리오버튼.선택됨 { border-color: var(--accent); background: var(--accent-soft); box-shadow: inset 0 0 0 1px var(--accent-border); }
        .시나리오헤더행 { display: flex; align-items: center; gap: 8px; margin-bottom: 3px; }
        .시나리오아이콘 { font-size: 1rem; flex-shrink: 0; display: inline-flex; }
        .시나리오이름 { font-weight: 700; font-size: 0.85rem; color: var(--text); flex: 1; font-family: var(--mono); }
        .시나리오설명 { font-size: 0.74rem; color: var(--text-2); display: block; padding-left: 26px; }
        .위험배지 { font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-radius: 20px; white-space: nowrap; border: 1px solid transparent; }
        .위험배지.높음 { background: var(--red-soft); color: var(--red); border-color: var(--red-border); }
        .위험배지.보통 { background: var(--amber-soft); color: var(--amber); border-color: var(--amber-border); }
        .위험배지.치명 { background: #1e1b2e; color: #fca5a5; }
        .게이지카드제목 { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: 0.88rem; font-weight: 700; color: var(--text); }
        .게이지카드제목 .icon { color: var(--accent); }
        .게이지레이블 { text-align: center; font-size: 0.77rem; color: var(--text-2); margin-top: 6px; }
        #분석시작버튼 { width: 100%; padding: 14px; border-radius: var(--radius-sm); border: none; background: var(--text); color: white; font-size: 0.95rem; font-weight: 700; cursor: pointer; transition: all 0.18s; display: flex; align-items: center; justify-content: center; gap: 8px; }
        #분석시작버튼:hover:not(:disabled) { background: #1e293b; transform: translateY(-1px); box-shadow: 0 6px 18px rgba(15,23,42,0.22); }
        #분석시작버튼:disabled { background: #94a3b8; cursor: not-allowed; transform: none; box-shadow: none; }
        #PDF버튼 { width: 100%; padding: 11px; border-radius: var(--radius-sm); border: none; background: var(--accent); color: white; font-size: 0.88rem; font-weight: 700; cursor: pointer; transition: all 0.18s; display: flex; align-items: center; justify-content: center; gap: 7px; margin-top: 4px; }
        #PDF버튼:hover { background: var(--accent-hover); transform: translateY(-1px); box-shadow: 0 4px 14px rgba(99,102,241,0.3); }
        .오른쪽패널 { display: flex; flex-direction: column; gap: 16px; }
        .그래프카드헤더 { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
        .그래프카드헤더 .제목 { font-size: 0.88rem; font-weight: 700; color: var(--text); display: inline-flex; align-items: center; gap: 8px; }
        .그래프카드헤더 .제목 .icon { color: var(--accent); }
        #네트워크SVG { width: 100%; height: 260px; border-radius: var(--radius-sm); background: linear-gradient(180deg,var(--surface-2) 0%,var(--surface-3) 100%); }
        .그래프범례 { display: flex; gap: 14px; margin-top: 10px; flex-wrap: wrap; align-items: center; }
        .범례항목 { display: flex; align-items: center; gap: 5px; font-size: 0.74rem; color: #64748b; }
        .범례점 { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
        .단계목록 { display: flex; gap: 7px; flex-wrap: wrap; }
        .단계칩 { padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; background: #f1f5f9; color: #94a3b8; transition: all 0.3s; border: 1.5px solid transparent; }
        .단계칩.진행중 { background: #fffbeb; color: #92400e; border-color: #fcd34d; animation: pulse 1.5s infinite; }
        .단계칩.완료 { background: #f0fdf4; color: #166534; border-color: #86efac; }
        .스트리밍헤더 { background: #0f172a; border-radius: 12px 12px 0 0; padding: 10px 16px; display: flex; align-items: center; justify-content: space-between; }
        .스트리밍헤더왼쪽 { display: flex; align-items: center; gap: 8px; }
        .스트리밍점 { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; box-shadow: 0 0 8px #22c55e; animation: pulse 1.5s infinite; }
        .스트리밍제목 { color: #94a3b8; font-size: 0.78rem; font-family: monospace; }
        .스트리밍배지 { background: rgba(99,102,241,0.2); color: #a5b4fc; font-size: 0.68rem; font-weight: 700; padding: 2px 8px; border-radius: 10px; }
        .스트리밍본문 { background: #020817; border-radius: 0 0 12px 12px; padding: 14px 16px; max-height: 220px; overflow-y: auto; }
        #스트리밍텍스트 { font-family: "SF Mono","Fira Code",monospace; font-size: 0.79rem; color: #a5f3fc; line-height: 1.7; white-space: pre-wrap; word-break: break-all; }
        .커서 { display: inline-block; width: 7px; height: 14px; background: #a5f3fc; animation: 깜빡 0.8s infinite; vertical-align: text-bottom; border-radius: 1px; }
        @keyframes 깜빡 { 0%,100%{opacity:1} 50%{opacity:0} }
        .결과카드헤더 { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; padding-bottom: 14px; border-bottom: 2px solid #f1f5f9; }
        .결과카드제목 { font-size: 1rem; font-weight: 800; color: #1e293b; }
        .결과카드부제 { font-size: 0.75rem; color: #94a3b8; margin-left: auto; }
        .요약카드 { background: #f8fafc; border-radius: 12px; padding: 16px; }
        .요약텍스트 { font-size: 0.92rem; line-height: 1.75; color: #1e293b; margin-bottom: 14px; }
        .포인트목록 { list-style: none; display: flex; flex-direction: column; gap: 6px; }
        .포인트목록 li { display: flex; align-items: flex-start; gap: 8px; font-size: 0.83rem; color: #374151; line-height: 1.6; }
        .포인트목록 li::before { content: "▸"; color: #6366f1; flex-shrink: 0; margin-top: 2px; font-size: 0.75rem; }
        .공격명배지 { display: inline-flex; align-items: center; gap: 5px; margin-top: 12px; background: #eef2ff; color: #3730a3; padding: 4px 12px; border-radius: 20px; font-size: 0.78rem; font-weight: 700; border: 1px solid #c7d2fe; }
        .결과그리드 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .분석칩카드 { background: #f8fafc; border-radius: 12px; padding: 14px; }
        .분석칩섹션제목 { font-size: 0.76rem; font-weight: 700; color: #64748b; margin-bottom: 10px; }
        .큰배지 { font-size: 0.85rem; font-weight: 800; padding: 5px 14px; border-radius: 8px; display: inline-block; margin-bottom: 10px; }
        .큰배지.정보수집,.큰배지.취약점탐색 { background: #dbeafe; color: #1d4ed8; }
        .큰배지.침투시도,.큰배지.데이터탈취 { background: #fee2e2; color: #dc2626; }
        .큰배지.서비스방해 { background: #ffedd5; color: #c2410c; }
        .큰배지.불명 { background: #f1f5f9; color: #64748b; }
        .큰배지.초보 { background: #dcfce7; color: #166534; }
        .큰배지.중급 { background: #fef9c3; color: #92400e; }
        .큰배지.고급 { background: #fee2e2; color: #dc2626; }
        .신뢰도바컨테이너 { margin: 10px 0 8px; }
        .신뢰도바컨테이너 .라벨 { font-size: 0.74rem; color: #64748b; margin-bottom: 5px; display: flex; justify-content: space-between; font-weight: 500; }
        .신뢰도바 { height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; }
        .신뢰도바 .채움 { height: 100%; background: linear-gradient(90deg,#6366f1,#8b5cf6); border-radius: 4px; transition: width 0.9s cubic-bezier(0.4,0,0.2,1); }
        .근거설명 { font-size: 0.81rem; color: #475569; line-height: 1.65; margin-top: 6px; }
        .권고카드 { background: #f8fafc; border-radius: 12px; padding: 16px; }
        .우선순위행 { display: flex; align-items: center; gap: 8px; margin-bottom: 14px; font-size: 0.8rem; color: #64748b; font-weight: 500; }
        .권고섹션제목 { font-size: 0.76rem; font-weight: 700; margin-bottom: 7px; }
        .권고섹션제목.즉각 { color: #dc2626; }
        .권고섹션제목.장기 { color: #2563eb; }
        .권고목록 { list-style: none; display: flex; flex-direction: column; gap: 5px; margin-bottom: 14px; }
        .권고목록 li { font-size: 0.81rem; color: #374151; padding: 8px 11px; border-radius: 8px; line-height: 1.55; }
        .권고목록.즉각 li { background: #fff1f2; border-left: 3px solid #f87171; }
        .권고목록.장기 li { background: #eff6ff; border-left: 3px solid #60a5fa; }
        .우선순위배지 { font-size: 0.74rem; font-weight: 700; padding: 3px 10px; border-radius: 20px; }
        .우선순위배지.즉시 { background: #fee2e2; color: #b91c1c; }
        .우선순위배지.시간 { background: #fef9c3; color: #92400e; }
        .우선순위배지.주 { background: #dbeafe; color: #1d4ed8; }
        .리포트서술박스 { background: linear-gradient(135deg,#f0f9ff,#f8f4ff); border-left: 4px solid #6366f1; padding: 16px; border-radius: 0 12px 12px 0; font-size: 0.87rem; line-height: 1.85; color: #1e293b; }
        .결과구분선 { border: none; border-top: 2px solid #f1f5f9; margin: 16px 0; }
        .개관 { padding: 18px 20px 16px; }
        .분포목록 { display: flex; flex-direction: column; gap: 9px; margin-top: 6px; }
        .분포행 { display: grid; grid-template-columns: 116px minmax(0,1fr) 40px 46px; gap: 12px; align-items: center; }
        .분포이름 { font-size: 0.86rem; font-weight: 600; }
        .분포막대 { height: 8px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 2px; overflow: hidden; }
        .분포채움 { display: block; height: 100%; }
        .분포수 { font-family: var(--mono); font-size: 0.86rem; font-weight: 600; text-align: right; font-variant-numeric: tabular-nums; }
        .분포비율 { font-family: var(--mono); font-size: 0.76rem; color: var(--text-2); text-align: right; font-variant-numeric: tabular-nums; }
        .위험배경-CRITICAL, .위험배경-HIGH { background: var(--red); }
        .위험배경-MEDIUM { background: var(--amber); }
        .위험배경-LOW { background: #94a3b8; }
        .위험글자-CRITICAL, .위험글자-HIGH { color: var(--red); }
        .개관도움 { margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border); font-size: 0.8rem; line-height: 1.65; color: var(--text-2); }
        .빈상태 { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 28px 20px; color: var(--text-2); text-align: center; min-height: 150px; }
        .빈상태아이콘 { font-size: 1.8rem; margin-bottom: 10px; color: var(--accent); opacity: 0.7; display: inline-flex; }
        .빈상태제목 { font-size: 1rem; font-weight: 700; color: #64748b; margin-bottom: 8px; }
        .빈상태설명 { font-size: 0.82rem; line-height: 1.7; }
        .빈상태힌트 { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 14px 20px; text-align: left; width: 100%; max-width: 560px; }
        .힌트행 { display: flex; align-items: center; gap: 9px; font-size: 0.8rem; color: var(--text-2); line-height: 1.5; white-space: nowrap; }
        .힌트번호 { width: 19px; height: 19px; border-radius: 50%; background: var(--accent-soft); color: var(--accent); font-size: 0.66rem; font-weight: 800; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .경고박스 { font-size: 0.82rem; line-height: 1.6; color: var(--amber); background: var(--amber-soft); border: 1px solid var(--amber-border); border-radius: var(--radius-sm); padding: 9px 12px; margin: 8px 0; }
        .오류박스 { background: #fff1f2; border: 1px solid #fca5a5; border-radius: 12px; padding: 14px 16px; color: #dc2626; font-size: 0.85rem; line-height: 1.6; }
      `}</style>

      <header>
        <div className="헤더왼쪽">
          <span className="brand-mark"><Shield className="icon" /></span>
          <div>
            <div className="헤더제목"><span>허니팟</span> 공격 분석 시스템</div>
            <div className="헤더부제">허니팟 수집 로그를 분류하고 한국어로 해설합니다</div>
          </div>
        </div>
        <div className="헤더우측">
          <div className="서버상태칩">
            <span className={`dot ${서버상태.연결됨 ? "dot-on" : "dot-off"}`} />
            {서버상태.연결됨
              ? <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><Activity className="icon" style={{ color: "var(--green)" }} /> AI 서버 · {서버상태.모델}</span>
              : <span>서버 연결 안됨</span>}
          </div>
          {사용자 && (
            <div className="세션칩">
              <span className="세션이메일">{사용자}</span>
              <button
                className="로그아웃"
                onClick={async () => { await 로그아웃(); router.replace("/login"); }}
              >
                로그아웃
              </button>
            </div>
          )}
        </div>
      </header>

      {/* ── 24h 개요 통계 밴드 ── */}
      <section className="개요밴드">
        <button className={`스탯카드 ${필터 === "all" ? "활성" : ""}`} onClick={() => set필터("all")} title="전체 로그 보기">
          <span className="스탯아이콘 이벤트"><Database className="icon" /></span>
          <div><div className="스탯값">{개요.total_events.toLocaleString()}</div><div className="스탯라벨">총 이벤트 (24h)</div></div>
        </button>
        <button className={`스탯카드 ${필터 === "attacks" ? "활성" : ""}`} onClick={() => set필터("attacks")} title="분류된 공격만 보기">
          <span className="스탯아이콘 공격"><ShieldAlert className="icon" /></span>
          <div><div className="스탯값">{개요.total_attacks.toLocaleString()}</div><div className="스탯라벨">분류된 공격</div></div>
        </button>
        <button className={`스탯카드 위험강조 ${개요.high_risk > 0 ? "주의" : ""} ${필터 === "highrisk" ? "활성" : ""}`} onClick={() => set필터("highrisk")} title="고위험(점수≥70) 보기">
          <span className="스탯아이콘 고위험"><Flame className="icon" /></span>
          <div><div className="스탯값">{개요.high_risk.toLocaleString()}</div><div className="스탯라벨">고위험 (점수 ≥ 70)</div></div>
        </button>
        <button className={`스탯카드 ${필터 === "llm" ? "활성" : ""}`} onClick={() => set필터("llm")} title="LLM 분석된 로그 보기">
          <span className="스탯아이콘 llm"><Sparkles className="icon" /></span>
          <div><div className="스탯값">{개요.llm_analyzed.toLocaleString()}</div><div className="스탯라벨">LLM 분석 완료</div></div>
        </button>
      </section>

      <div className="레이아웃">
        {/* ── 왼쪽 패널 ── */}
        <div className="왼쪽패널">
          <div className="카드">
            <div className="섹션헤더">
              <div className="섹션번호">1</div>
              <span className="섹션제목">최근 공격 로그</span>
              <span className="섹션설명" style={{ cursor: "pointer" }} onClick={공격목록새로고침} title="새로고침"><RefreshCw className="icon" /> {표시목록.length}건</span>
            </div>
            {필터 !== "all" && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <span className="badge badge-indigo">필터: {필터라벨[필터]}</span>
                <span style={{ fontSize: "0.74rem", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }} onClick={() => set필터("all")}>전체 해제</span>
              </div>
            )}
            <div className="공격목록">
              {표시목록.length === 0 && (
                <div style={{ fontSize: "0.8rem", color: "var(--text-3)", padding: "12px 4px", lineHeight: 1.6 }}>
                  {목록오류
                    ? `로그를 불러오지 못했습니다 (${목록오류})`
                    : "표시할 로그가 없습니다. (필터를 바꾸거나 T-Pot ES 데이터를 확인하세요)"}
                </div>
              )}
              {표시목록.map((a) => (
                <button key={a.사건ID} className={`시나리오버튼 위험띠-${a.위험등급} ${선택공격?.사건ID === a.사건ID ? "선택됨" : ""}`} onClick={() => 공격선택(a)}>
                  <div className="시나리오헤더행">
                    <span className="시나리오아이콘">
                      <AlertTriangle className="icon" style={{ color: a.위험등급 === "MEDIUM" ? "var(--amber)" : a.위험등급 === "LOW" ? "var(--text-3)" : "var(--red)" }} />
                    </span>
                    <span className="시나리오이름">{공격표시명(a)}</span>
                    <span className={`위험배지 ${위험배지클래스[a.위험등급] ?? "보통"}`}>{a.위험등급}</span>
                  </div>
                  <span className="시나리오설명">{a.공격자IP} · {a.허니팟ID} · 위험 {a.위험점수} · {발생시각짧게(a.발생시각)}</span>
                </button>
              ))}
            </div>
          </div>

          {showGauge && 건강점수 !== null && (
            <div className="카드" style={{ padding: "16px 20px 10px" }}>
              <div className="게이지카드제목"><ShieldCheck className="icon" /> 보안 건강 점수</div>
              <svg ref={게이지SVGRef} id="게이지SVG" viewBox="0 0 220 115" style={{ display: "block", width: "100%", overflow: "visible" }} />
              <div className="게이지레이블">
                보안 상태: <strong style={{ color: 활성색 }}>{건강라벨}</strong> &nbsp;·&nbsp; 위험 점수 {선택공격?.위험점수.toFixed(1)}/100
              </div>
            </div>
          )}

          {선택공격 && (해설 || 해설조회중) && (
            <div className="카드 해설카드">
              <div className="해설머리">
                <span className="해설제목">한국어 해설</span>
                {해설?.공유 && (
                  <span className="해설꼬리표" title={해설.패턴키 ?? undefined}>
                    이 유형 공통
                  </span>
                )}
                <span className="해설즉시">저장된 결과 · 추론 없음</span>
              </div>
              {해설조회중 && !해설 && <p className="해설본문">불러오는 중…</p>}
              {해설 && (
                <>
                  <p className="해설본문">{해설.요약}</p>
                  {해설.대응 && <p className="해설대응"><b>대응</b> — {해설.대응}</p>}
                  {해설.기법.length > 0 && (
                    <div className="패턴기법">{해설.기법.map((t) => <span key={t}>{t}</span>)}</div>
                  )}
                </>
              )}
            </div>
          )}

          <button id="분석시작버튼" onClick={분석시작} disabled={분석중 || !선택공격}>
            {분석중 ? <span className="spinner" /> : <Search className="icon" />}
            <span>{분석중 ? "AI가 분석하는 중..." : 해설 ? "더 깊게 분석 (AI 호출)" : "AI 분석 시작"}</span>
          </button>

          {showPDF && (
            <button id="PDF버튼" onClick={PDF저장}>
              <FileDown className="icon" /><span>리포트 PDF 저장</span>
            </button>
          )}
        </div>

        {/* ── 오른쪽 패널 (분석 파이프라인) ── */}
        <div className="오른쪽패널">
          {/* 단계 ① 학습 ML 1차 다중분류 */}
          {선택공격 && (
            <div className="카드">
              <div className="단계카드헤더">
                <span className="단계번호">1</span>
                <span className="단계제목">학습 ML 1차 다중분류</span>
                <span className="단계부제">ml-classifier · {선택공격.공격자IP}</span>
              </div>
              <div className="분류그리드">
                <div className="분류항목"><span className="분류라벨">공격 유형</span><span className="분류값">{공격표시명(선택공격)}</span></div>
                <div className="분류항목"><span className="분류라벨">위험 등급</span><br /><span className={`badge sev-${선택공격.위험등급}`}>{선택공격.위험등급}</span></div>
                <div className="분류항목"><span className="분류라벨">위험 점수</span><span className="분류값">{선택공격.위험점수}/100</span></div>
                <div className="분류항목"><span className="분류라벨">탐지 신뢰도</span><span className="분류값">{Math.round((선택공격.탐지신뢰도 || 0) * 100)}%</span></div>
                <div className="분류항목"><span className="분류라벨">MITRE</span><span className="분류값">{선택공격.MITRE전술 ?? "-"}</span></div>
                <div className="분류항목"><span className="분류라벨">허니팟</span><span className="분류값">{선택공격.허니팟ID}</span></div>
              </div>
            </div>
          )}

          {showGraph && (
            <div className="카드" style={{ padding: "16px 20px 14px" }}>
              <div className="그래프카드헤더">
                <span className="제목"><Share2 className="icon" /> 공격 흐름 시각화</span>
              </div>
              <svg ref={네트워크SVGRef} id="네트워크SVG" />
              <div className="그래프범례">
                <div className="범례항목"><div className="범례점" style={{ background: "#fee2e2", border: "2px solid #ef4444" }} />공격자 IP</div>
                <div className="범례항목"><div className="범례점" style={{ background: "#eef2ff", border: "2px solid #6366f1" }} />허니팟</div>
                <div className="범례항목"><div className="범례점" style={{ background: "#f8fafc", border: "2px solid #cbd5e1" }} />공격 행위 단계</div>
                <div style={{ marginLeft: "auto", fontSize: "0.72rem", color: "#94a3b8" }}>→ 빨간 점: 실시간 공격 흐름</div>
              </div>
            </div>
          )}

          {showSteps && (
            <div className="카드">
              <div className="단계카드헤더">
                <span className="단계번호">2</span>
                <span className="단계제목">LLM 2차 분석</span>
                <span className="단계부제" style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><Clock className="icon" /> 진행 단계</span>
              </div>
              <div className="단계목록">
                {단계이름.map((n, i) => (
                  <div key={n} className={`단계칩 ${단계칩[i]?.상태 ?? "pending"}`}>{i + 1}. {n}</div>
                ))}
              </div>
            </div>
          )}

          {showStreaming && (
            <div className="카드" style={{ padding: 0, overflow: "hidden" }}>
              <div className="스트리밍헤더">
                <div className="스트리밍헤더왼쪽">
                  <Radio className="icon" style={{ color: "#22c55e", animation: "pulse 1.5s infinite" }} />
                  <span className="스트리밍제목">AI 실시간 추론 중...</span>
                </div>
                <span className="스트리밍배지">LIVE</span>
              </div>
              <div className="스트리밍본문" ref={스트리밍본문Ref}>
                <span id="스트리밍텍스트">{스트리밍텍스트}</span>
                {커서보임 && <span className="커서" />}
              </div>
            </div>
          )}

          {결과HTML && (
            <div dangerouslySetInnerHTML={{ __html: 결과HTML }} />
          )}

          {차트HTML === "__RENDER_CHARTS__" && (
            <div className="카드" style={{ marginBottom: 0 }}>
              <div className="결과카드헤더" style={{ marginBottom: 12 }}>
                <span className="결과카드제목" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><BarChart3 className="icon" style={{ color: "var(--accent)" }} /> 위협 분석 차트</span>
                <span className="결과카드부제">AI 분석 지표 시각화</span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, alignItems: "start" }}>
                <div>
                  <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--text-2)", marginBottom: 10, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><Crosshair className="icon" /> 위협 레이더</div>
                  <svg ref={레이더SVGRef} viewBox="0 0 280 260" style={{ width: "100%", display: "block" }} />
                </div>
                <div>
                  <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--text-2)", marginBottom: 10, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><TrendingUp className="icon" /> 분석 지표</div>
                  <svg ref={바차트SVGRef} viewBox="0 0 280 230" style={{ width: "100%", display: "block" }} />
                </div>
              </div>
            </div>
          )}

          {showEmpty && (
            /* 아무것도 선택하지 않았을 때 안내문만 띄우면 넓은 면이 그냥 빈다.
               "지금 전체적으로 무슨 일이 일어나고 있나"는 선택과 무관하게 늘
               유효한 질문이므로, 목록에서 바로 계산한 분포로 채운다. */
            <div className="카드 개관">
              <div className="섹션헤더">
                <div className="섹션번호">2</div>
                <span className="섹션제목">지금 들어오는 공격</span>
                <span className="섹션설명">최근 {표시목록.length}건 기준</span>
              </div>

              {유형분포.length === 0 ? (
                <p className="빈상태설명" style={{ padding: "28px 0" }}>표시할 로그가 없습니다.</p>
              ) : (
                <div className="분포목록">
                  {유형분포.map(([이름, 수, 최고위험]) => (
                    <div className="분포행" key={이름}>
                      <span className={`분포이름 위험글자-${최고위험}`}>{이름}</span>
                      <span className="분포막대">
                        <span
                          className={`분포채움 위험배경-${최고위험}`}
                          style={{ width: `${Math.round((수 / 표시목록.length) * 100)}%` }}
                        />
                      </span>
                      <span className="분포수">{수}</span>
                      <span className="분포비율">{Math.round((수 / 표시목록.length) * 100)}%</span>
                    </div>
                  ))}
                </div>
              )}

              <div className="개관도움">
                왼쪽 목록에서 이벤트를 고르면 분류 근거와 한국어 해설이 여기에 표시됩니다.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── 현재 분류 모델 카드 ── */}
      {모델정보 && (() => {
        // 규칙 모드에는 학습 지표가 존재하지 않는다(/api/model 이 algorithm="rule").
        // "-" 를 나열하면 지표를 못 불러온 것과 구분되지 않으므로 분기한다.
        const 규칙모드 = 모델정보.algorithm === "rule" || 모델정보.accuracy == null;
        return (
        <section className="모델밴드">
          <div className="카드 모델카드">
            <div className="모델헤더">
              <span className="모델아이콘"><BrainCircuit className="icon" /></span>
              <div>
                <div className="모델제목">
                  현재 분류 모델
                  <span className={`모델배지 ${규칙모드 ? "모델배지-규칙" : ""}`}>{규칙모드 ? "규칙 기반" : 모델정보.algorithm}</span>
                </div>
                <div className="모델부제">
                  {규칙모드
                    ? `허니팟 종류와 이벤트 내용으로 판정 · ${모델정보.labels.length}개 유형`
                    : `다중분류 · ${모델정보.labels.length}개 클래스 · ${모델정보.n_features ?? "-"}개 피처`}
                </div>
              </div>
            </div>
            {교차검증 && (
              <div className="교차검증">
                <div className="교차행">
                  <span className="교차라벨">모델·규칙 합의</span>
                  <span className="교차막대">
                    <span className="교차채움" style={{ width: `${교차검증.합의율 ?? 0}%` }} />
                  </span>
                  <span className="교차값">{교차검증.합의율}%</span>
                </div>
                <div className="교차설명">
                  최근 {교차검증.모델관여.toLocaleString()}건에서 모델이 규칙과 같은 답을 낸 비율입니다.
                  {교차검증.불일치 > 0 && (
                    <> 다른 답을 낸 <b>{교차검증.불일치}건</b>은 검토 대상으로 표시됩니다
                    (라벨은 규칙을 따릅니다).</>
                  )}
                </div>
              </div>
            )}
            {규칙모드 ? (
              <div className="모델설명">
                결정론적 규칙으로 판정하므로 정확도·F1 같은 학습 지표가 없습니다.
                학습 모델은 현재 데이터에서 규칙보다 성능이 낮아 비활성 상태입니다.
              </div>
            ) : (
              <>
                <div className="모델지표그리드">
                  {모델정보.holdout_micro != null ? (
                    <>
                      <div className="모델지표"><span className="모델지표값">{(모델정보.holdout_micro * 100).toFixed(1)}%</span><span className="모델지표라벨">규칙 재현</span></div>
                      <div className="모델지표"><span className="모델지표값">{모델정보.holdout_macro != null ? (모델정보.holdout_macro * 100).toFixed(1) + "%" : "—"}</span><span className="모델지표라벨">Macro 평균</span></div>
                    </>
                  ) : (
                    <>
                      <div className="모델지표"><span className="모델지표값">{(모델정보.accuracy! * 100).toFixed(1)}%</span><span className="모델지표라벨">정확도</span></div>
                      <div className="모델지표"><span className="모델지표값">{(모델정보.macro_f1! * 100).toFixed(1)}%</span><span className="모델지표라벨">Macro-F1</span></div>
                    </>
                  )}
                  <div className="모델지표"><span className="모델지표값">{모델정보.n_total.toLocaleString()}</span><span className="모델지표라벨">학습 샘플</span></div>
                  <div className="모델지표"><span className="모델지표값">{모델정보.holdout_n != null ? 모델정보.holdout_n.toLocaleString() : "—"}</span><span className="모델지표라벨">검증 샘플</span></div>
                </div>
                {모델정보.holdout_micro != null && (
                  <div className="모델설명">
                    위 수치는 <b>학습에 쓰지 않은 실제 공격 문서 {모델정보.holdout_n?.toLocaleString()}건</b>에서
                    모델이 규칙과 같은 답을 낸 비율입니다. 학습셋 내부 정확도는
                    {" "}{(모델정보.accuracy! * 100).toFixed(1)}%지만, 정답 라벨을 규칙이 만들기 때문에
                    그 숫자는 &ldquo;규칙을 외웠다&rdquo;는 뜻이라 일반화를 말해주지 못합니다.
                  </div>
                )}
              </>
            )}
            <div className="모델라벨칩들">
              {모델정보.labels.map((l) => <span key={l} className="모델라벨칩">{라벨한글[l] ?? l}</span>)}
            </div>
          </div>
        </section>
        );
      })()}

      {/* ── 내 자산 노출 대조 ── */}
      <section className="자산밴드">
        <div className="카드 자산카드">
          <div>
            <div className="패턴제목">내 자산 노출 대조</div>
            <div className="패턴요지">
              열어둔 포트를 적으면 그 포트가 실제로 얼마나 공격받고 있는지 대조합니다.
              허니팟이 본 것은 &ldquo;우리 대역을 노리는 공격&rdquo;이지 &ldquo;우리가 뚫렸다&rdquo;가
              아닙니다 — 포트를 대야 내 얘기가 됩니다.
            </div>
          </div>
          <div className="자산입력줄">
            <textarea
              id="자산포트입력"
              className="자산입력"
              value={자산입력}
              onChange={(e) => set자산입력(e.target.value)}
              placeholder="웹서버 80, 443&#10;DB 3306, 5432&#10;파일서버 445"
              aria-label="자산 포트 목록"
              rows={2}
            />
            <button type="button" className="자산버튼" disabled={자산저장중}
                    onClick={() => 노출조회(자산입력)}>
              {자산저장중 ? "저장 중…" : "대조"}
            </button>
          </div>

          {노출 && 노출.노출목록.length > 0 && (
            <>
              <p className="자산결론">
                {노출.위험포트수 > 0 ? (
                  <>열어둔 포트 중 <b>{노출.위험포트수}개</b>가 고위험 공격을 받고 있습니다.</>
                ) : (
                  <>열어둔 포트에서 <b className="무사">고위험 공격은 관측되지 않았습니다.</b></>
                )}{" "}
                최근 1년 · 해당 이벤트 {노출.해당이벤트.toLocaleString()}건.
              </p>
              <div style={{ overflowX: "auto" }}>
                <table className="노출표">
                  <thead>
                    <tr>
                      <th scope="col">포트</th><th scope="col">공격</th><th scope="col">고위험</th>
                      <th scope="col">공격 IP</th><th scope="col">최고 점수</th><th scope="col">주 유형</th>
                    </tr>
                  </thead>
                  <tbody>
                    {노출.노출목록.map((n) => (
                      <tr key={n.포트} className={n.위험 ? "위험" : undefined}>
                        <td className="노출포트">{n.포트}</td>
                        <td>{n.공격.toLocaleString()}</td>
                        <td className="노출고위험">{n.고위험.toLocaleString()}</td>
                        <td>{n.공격IP수.toLocaleString()}</td>
                        <td>{n.최고점수}</td>
                        <td>{n.주라벨 ? (라벨한글[n.주라벨] ?? n.주라벨) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="교차설명">
                포트 목록은 <b>내 계정</b>에 저장됩니다. 다른 기기에서 로그인해도 따라오고,
                다른 사용자는 볼 수 없습니다.
              </p>
            </>
          )}
        </div>
      </section>

      {/* ── 공격 패턴 (해설 단위) ── */}
      {패턴 && 패턴.패턴목록.length > 0 && (
        <section className="패턴밴드">
          <div className="패턴헤더">
            <span className="패턴제목">공격 패턴</span>
            <span className="패턴요지">
              고위험 <b>{패턴.사건합계.toLocaleString()}</b>건이{" "}
              <b>{패턴.패턴수}</b>개 패턴입니다. 같은 패턴은 한 번만 해설하고 나눠 씁니다
              {패턴.건당덮는수 ? <> — 해설 1건이 평균 <b>{패턴.건당덮는수}</b>건을 덮습니다</> : null}.
            </span>
          </div>
          <div className="패턴그리드">
            {패턴.패턴목록.map((p) => (
              <article key={p.키} className="패턴카드">
                <div className="패턴상단">
                  <span className="패턴건수">{p.건수.toLocaleString()}<span>건</span></span>
                  {p.위험등급 && (
                    <span className={`위험배지 ${위험배지클래스[p.위험등급] ?? "보통"}`}>
                      {p.위험등급}
                    </span>
                  )}
                  <span className="패턴키">
                    {p.레거시
                      ? "패턴 재사용 이전에 건별로 해설된 문서"
                      : <>{p.허니팟} · {라벨한글[p.라벨] ?? p.라벨} · 포트 {p.포트}</>}
                  </span>
                </div>
                <div className="패턴곁수치">
                  <span>공격 IP <b>{p.공격IP수.toLocaleString()}</b>개</span>
                  {p.위협점수 != null && <span>위협 점수 <b>{p.위협점수}</b></span>}
                </div>
                {p.요약 && <p className="패턴요약">{p.요약}</p>}
                {p.대응 && <p className="패턴대응"><b>대응</b> — {p.대응}</p>}
                {p.기법.length > 0 && (
                  <div className="패턴기법">{p.기법.map((t) => <span key={t}>{t}</span>)}</div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      {/* ── T-Pot 실시간 어택맵 (접기/펼치기) ── */}
      <section className="맵섹션">
        <div className="카드" style={{ padding: "16px 20px 14px" }}>
          <div className="그래프카드헤더">
            <span className="제목"><Globe className="icon" /> T-Pot 실시간 공격 지도</span>
            <span className="맵토글" onClick={() => set맵펼침(!맵펼침)}>
              {맵펼침 ? <><ChevronUp className="icon" /> 접기</> : <><ChevronDown className="icon" /> 펼치기</>}
            </span>
          </div>
          {맵펼침 && (
            <>
              <iframe src="/tpot-map/" title="T-Pot Attack Map" className="맵아이프레임" />
              <div style={{ fontSize: "0.72rem", color: "var(--text-3)", marginTop: 8 }}>
                ※ 공격 아크는 실시간 이벤트가 들어올 때 그려집니다. 조용하면 지도만 표시됩니다.
              </div>
            </>
          )}
        </div>
      </section>

    </>
  );
}
