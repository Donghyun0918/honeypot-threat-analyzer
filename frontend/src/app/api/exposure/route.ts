// GET /api/exposure?ports=445,22 — 내 자산의 포트가 실제로 얼마나 얻어맞는가.
//
// 허니팟 데이터의 약점은 그것이 "남의 얘기" 라는 점이다 — 우리 대역을 노리는
// 공격이지 우리가 뚫렸다는 뜻이 아니다. 값이 서려면 고객 자산과 연결해야 한다:
// "445 를 노린 공격이 107,551건인데, 당신 서버 3대에 445 가 열려 있다".
//
// 파이프라인은 이미 dest_port 를 뽑고 있으므로 필요한 것은 포트 목록뿐이다.
// ML 도 LLM 도 쓰지 않는다.

import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값, 인증실패통과 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

type 노출 = {
  port: number; events: number; high_risk: number;
  ip_count: number; max_score: number; top_label?: string;
};

export async function GET(req: NextRequest) {
  const sp = new URL(req.url).searchParams;
  const ports = sp.get("ports") ?? "";
  const since = sp.get("since");
  const auth = 인증헤더값(req);

  if (!ports.trim()) return NextResponse.json({ 노출목록: [], 조회포트수: 0, 해당이벤트: 0 });

  const qs = new URLSearchParams({ ports });
  if (since) qs.set("since", since);

  try {
    const res = await fetch(`${API}/api/exposure?${qs}`, {
      cache: "no-store",
      headers: auth ? { Authorization: auth } : undefined,
      signal: AbortSignal.timeout(10_000),
    });
    // 인증 실패는 아래 빈-응답 처리로 덮지 않고 그대로 올린다(세션쿠키.ts 참조).
    const 인증거부 = 인증실패통과(res.status);
    if (인증거부) return 인증거부;

    if (!res.ok) return NextResponse.json({ 노출목록: [], 오류: `백엔드 ${res.status}` });

    const d = (await res.json()) as { items?: 노출[]; checked?: number; matched_events?: number };
    const 노출목록 = (d.items ?? []).map((i) => ({
      포트: i.port,
      공격: i.events ?? 0,
      고위험: i.high_risk ?? 0,
      공격IP수: i.ip_count ?? 0,
      최고점수: i.max_score ?? 0,
      주라벨: i.top_label ?? null,
      // 고위험이 한 건이라도 있으면 "지금 실제로 노려지는 포트" 다.
      위험: (i.high_risk ?? 0) > 0,
    }));

    return NextResponse.json({
      노출목록,
      조회포트수: d.checked ?? 노출목록.length,
      해당이벤트: d.matched_events ?? 0,
      // 열어둔 포트 중 실제로 고위험 공격을 받은 것이 몇 개인가 — 한 줄 결론.
      위험포트수: 노출목록.filter((p) => p.위험).length,
    });
  } catch {
    return NextResponse.json({ 노출목록: [], 오류: "백엔드에 연결할 수 없습니다." });
  }
}
