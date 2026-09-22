// GET /api/ml-stats — 분류 통계. 모델 카드의 "실제 합의율"에 쓴다.
//
// 학습 지표(holdout 정확도)는 학습 분포 안에서만 유효하고, 이 프로젝트에서는
// 정답 라벨을 규칙에서 뽑았기 때문에 특히 부풀려져 보인다. 운영에서 의미 있는
// 숫자는 "지금 들어오는 문서에 대해 모델이 규칙과 얼마나 합의하는가"다.
// 그 값은 model_used 집계에서 바로 나온다.

import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값, 인증실패통과 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

export async function GET(req: NextRequest) {
  // 창을 정하지 않으면 백엔드 기본값(THREAT_CONSOLE_WINDOW_SHORT)을 따른다.
  const since = new URL(req.url).searchParams.get("since");
  const auth = 인증헤더값(req);

  try {
    const res = await fetch(`${API}/api/ml-stats${since ? `?since=${encodeURIComponent(since)}` : ""}`, {
      cache: "no-store",
      headers: auth ? { Authorization: auth } : undefined,
      signal: AbortSignal.timeout(8_000),
    });
    // 인증 실패는 아래 빈-응답 처리로 덮지 않고 그대로 올린다(세션쿠키.ts 참조).
    const 인증거부 = 인증실패통과(res.status);
    if (인증거부) return 인증거부;

    if (!res.ok) {
      return NextResponse.json({ 오류: `백엔드 ${res.status}` }, { status: 200 });
    }
    const d = await res.json();

    // model_used 값의 뜻:
    //   ml+rule         모델과 규칙이 같은 답 → 신뢰도 높은 건
    //   rule(dissent)   모델이 다른 답 → 사람이 볼 만한 건
    //   rule(low-conf)  모델이 확신하지 못함
    //   rule            모델이 없거나 실패
    const 집계: Record<string, number> = {};
    for (const b of (d.model_used ?? []) as { key: string; count: number }[]) {
      집계[b.key] = b.count;
    }
    const 합의 = 집계["ml+rule"] ?? 0;
    const 불일치 = 집계["rule(dissent)"] ?? 0;
    const 저신뢰 = 집계["rule(low-conf)"] ?? 0;
    const 모델관여 = 합의 + 불일치 + 저신뢰;

    return NextResponse.json({
      labels: d.labels ?? [],
      honeypots: d.honeypots ?? [],
      model_used: d.model_used ?? [],
      교차검증: {
        모델관여,
        합의,
        불일치,
        저신뢰,
        // 모델이 관여한 건 중 규칙과 같은 답을 낸 비율.
        합의율: 모델관여 > 0 ? Math.round((합의 / 모델관여) * 1000) / 10 : null,
      },
    });
  } catch {
    return NextResponse.json({ 오류: "백엔드에 연결할 수 없습니다." }, { status: 200 });
  }
}
