// GET /api/event-source?id=... — 사건 원본(logstash-*)에서 추린 판단 근거.
//
// "더 깊게 분석" 이 모델에 IDS 서명·실행 명령·페이로드를 실어 보내려고 부른다.
// 분류 결과(ml-analysis-*)만으로 물으면 모델이 빈 칸을 근거로 판단한다
// ("페이로드 없음 → 초보"). 원본을 못 찾으면 found=false 를 그대로 돌려주고,
// 화면은 그 사실을 프롬프트에 적는다.

import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

export async function GET(req: NextRequest) {
  const id = new URL(req.url).searchParams.get("id");
  const auth = 인증헤더값(req);
  if (!auth) return NextResponse.json({ found: false }, { status: 401 });
  if (!id) return NextResponse.json({ found: false });

  try {
    const res = await fetch(`${API}/api/event-source?id=${encodeURIComponent(id)}`, {
      cache: "no-store",
      headers: { Authorization: auth },
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return NextResponse.json({ found: false });
    return NextResponse.json(await res.json());
  } catch {
    return NextResponse.json({ found: false });
  }
}
