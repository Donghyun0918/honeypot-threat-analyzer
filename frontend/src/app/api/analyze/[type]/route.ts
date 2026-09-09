// POST /api/analyze/[type] — 단건 분석 API (Spring 연동용)
// 예: /api/analyze/사건요약, /api/analyze/의도분석, etc.

import { NextRequest, NextResponse } from "next/server";
import { 분석서비스 } from "@/lib/llm-service";
import { 프롬프트맵 } from "@/lib/prompts";
import type { 공격로그입력 } from "@/types/input";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ type: string }> }
) {
  const { type } = await params;
  const 분석유형 = decodeURIComponent(type);

  if (!(분석유형 in 프롬프트맵) && 분석유형 !== "전체리포트") {
    return NextResponse.json(
      { error: `알 수 없는 분석 유형: ${분석유형}` },
      { status: 400 }
    );
  }

  try {
    const body = await req.json() as { 로그?: 공격로그입력 } | 공격로그입력;
    const 로그 = ("로그" in body && body.로그 ? body.로그 : body) as 공격로그입력;
    const 결과 = await 분석서비스._재시도호출(프롬프트맵[분석유형]?.(로그) ?? "");
    return NextResponse.json(결과);
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
