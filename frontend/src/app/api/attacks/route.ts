// GET /api/attacks?view=ml|llm — T-Pot ES 공격 로그 목록.
// Spring threat-console 백엔드를 서버사이드로 프록시 후 공격로그입력 형태로 매핑.
//   view=ml (기본): ml-analysis-* (분류 로그 전체, 공격+정상). 개요 "총/공격/고위험" 필터용.
//   view=llm       : llm-analysis-* (LLM 분석된 로그). 개요 "LLM 분석" 필터용.

import { NextResponse, type NextRequest } from "next/server";
import type { 공격로그입력, 공격유형코드, 위험등급코드 } from "@/types/input";
import { 인증헤더값, 인증실패통과 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

/** 로그인 토큰을 백엔드로 그대로 전달한다(없으면 헤더를 붙이지 않는다). */
function 인증전달(req: NextRequest): Record<string, string> | undefined {
  const auth = 인증헤더값(req);
  return auth ? { Authorization: auth } : undefined;
}

// 9-class ML 모델 라벨(label_names.pkl) → 공격유형코드.
// classify.py가 model.predict() 정수(0-8)를 label_names로 이름 매핑해 ml_label에 기록한 값과 일치.
const 유형맵: Record<string, 공격유형코드> = {
  "Normal": "NORMAL",
  "Recon": "RECON",
  "Brute Force": "BRUTE_FORCE",
  "Intrusion": "INTRUSION",
  "Malware": "MALWARE",
  "Web Attack": "WEB_ATTACK",
  "Service Attack": "SERVICE_ATTACK",
  "ICS Attack": "ICS_ATTACK",
  "Etc": "UNKNOWN",
};

function 등급계산(score: number): 위험등급코드 {
  if (score >= 85) return "CRITICAL";
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

// 공통 필드 추출
function base(r: Record<string, unknown>, score: number, conf: number): 공격로그입력 {
  const ts = String(r["@timestamp"] ?? new Date().toISOString());
  const ip = String(r["src_ip"] ?? "0.0.0.0");
  const label = String(r["ml_label"] ?? "");
  const honeypot = String(r["honeypot"] ?? "unknown");
  const port = r["dest_port"] != null ? Number(r["dest_port"]) : undefined;
  return {
    사건ID: `ES-${ts.slice(0, 19)}-${ip}`,
    허니팟ID: honeypot,
    발생시각: ts,
    공격자IP: ip,
    공격유형: 유형맵[label] ?? "UNKNOWN",
    위험점수: score,
    탐지신뢰도: conf,
    위험등급: 등급계산(score),
    MITRE전술: r["mitre_technique"] ? String(r["mitre_technique"]) : undefined,
    대상URI: port ? `:${port}` : undefined,
    행위시퀀스: label ? [`${honeypot} 접속`, label] : [],
    요청횟수: 1,
    // llm-analysis-* 문서의 _id 와 같다. 화면이 "이 사건에 이미 해설이 있는가" 를
    // 그룹 키 계산 없이 바로 물을 수 있게 그대로 실어 보낸다.
    ...({ _ml_label: label, _doc_id: r["source_doc_id"] ?? null } as Record<string, unknown>),
  };
}

// ml-analysis-* 행 → 입력 (+ _is_attack)
// ml_multi_conf 는 classify.py 가 0~100 으로 쓴다(max_prob * 100). 입력 타입의
// 탐지신뢰도는 0~1 이므로 여기서 정규화한다 — 안 하면 UI 가 다시 ×100 해서
// "탐지 신뢰도 9990%" 가 된다.
function mapMl(r: Record<string, unknown>): 공격로그입력 {
  const out = base(r, Number(r["mitre_score"] ?? 0), Number(r["ml_multi_conf"] ?? 0) / 100);
  return { ...out, ...({ _is_attack: r["ml_is_attack"] !== false } as Record<string, unknown>) };
}

// llm-analysis-* 행 → 입력 (위험점수=risk_score, 위험등급=severity, summary 포함)
function mapLlm(r: Record<string, unknown>): 공격로그입력 {
  const score = Number(r["risk_score"] ?? r["mitre_score"] ?? 0);
  const out = base(r, score, 0.9);
  const sev = r["severity"] ? String(r["severity"]) as 위험등급코드 : 등급계산(score);
  return {
    ...out,
    위험등급: sev,
    ...({ _is_attack: true, _summary: r["summary_ko"] ?? "" } as Record<string, unknown>),
  };
}

export async function GET(req: NextRequest) {
  const view = new URL(req.url).searchParams.get("view") === "llm" ? "llm" : "ml";
  const path = view === "llm" ? "/api/export/llm" : "/api/export/ml";
  try {
    const res = await fetch(`${API}${path}?format=json`, { cache: "no-store", headers: 인증전달(req) });
    // 인증 실패는 아래 빈-응답 처리로 덮지 않고 그대로 올린다(세션쿠키.ts 참조).
    const 인증거부 = 인증실패통과(res.status);
    if (인증거부) return 인증거부;

    if (!res.ok) return NextResponse.json({ 공격목록: [], 오류: `backend ${res.status}` });
    const rows = (await res.json()) as Record<string, unknown>[];
    const arr = Array.isArray(rows) ? rows : [];
    const list = (view === "llm" ? arr.map(mapLlm) : arr.map(mapMl)).slice(0, 100);
    return NextResponse.json({ 공격목록: list, 건수: list.length, view });
  } catch (e) {
    return NextResponse.json({ 공격목록: [], 오류: String(e) });
  }
}
