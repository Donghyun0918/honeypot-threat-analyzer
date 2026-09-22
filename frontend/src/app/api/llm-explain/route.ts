// GET /api/llm-explain?id=... — 사건 하나의 **이미 만들어둔** 한국어 해설.
//
// 온디맨드 추론 정책의 핵심이다. llm-analyzer 는 패턴당 한 번만 모델을 부르지만
// 결과는 사건마다 문서로 남긴다. 그래서 고위험 사건 대부분은 이미 해설이 있고,
// 화면은 **추론 없이 0초에** 그걸 보여줄 수 있다. 모델을 부르는 것(/api/analyze/*)은
// 해설이 아직 없거나 더 깊은 리포트를 원할 때뿐이다.

import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

export async function GET(req: NextRequest) {
  const id = new URL(req.url).searchParams.get("id");
  const auth = 인증헤더값(req);
  if (!auth) return NextResponse.json({ found: false }, { status: 401 });
  if (!id) return NextResponse.json({ found: false });

  try {
    const res = await fetch(`${API}/api/llm-explain?id=${encodeURIComponent(id)}`, {
      cache: "no-store",
      headers: { Authorization: auth },
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return NextResponse.json({ found: false });

    const d = await res.json();
    if (!d?.found) return NextResponse.json({ found: false });

    return NextResponse.json({
      found: true,
      요약: d.summary_ko ?? "",
      대응: d.solution_ko ?? "",
      위험등급: d.severity ?? null,
      기법: Array.isArray(d.ttp_inferred) ? d.ttp_inferred : [],
      패턴키: d.llm_group_key ?? null,
      // 이 해설이 같은 패턴의 다른 사건과 공유되는 것인지. 화면이 "이 유형의
      // 설명" 이라고 말해줘야 사용자가 사건별 맞춤 문장으로 오해하지 않는다.
      공유: d.llm_group_reused === true,
      모델: d.llm_model ?? null,
    });
  } catch {
    return NextResponse.json({ found: false });
  }
}
