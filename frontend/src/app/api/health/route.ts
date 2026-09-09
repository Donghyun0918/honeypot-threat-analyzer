// GET /api/health — 서버 상태 확인 (FastAPI /상태 → Next.js API route)

import { NextResponse } from "next/server";
import { 분석서비스 } from "@/lib/llm-service";

export async function GET() {
  const 연결됨 = await 분석서비스.서버상태확인();
  const 제공자 = 분석서비스.provider.이름;
  return NextResponse.json({
    서비스상태: 연결됨 ? "정상" : `${제공자} 연결 안됨`,
    제공자,
    Ollama연결: 연결됨, // (대시보드 호환) 제공자 무관 연결 여부
    사용모델: 분석서비스.모델,
  });
}
