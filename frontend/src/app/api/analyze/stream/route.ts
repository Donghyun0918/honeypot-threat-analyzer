// POST /api/analyze/stream — 실시간 스트리밍 분석 (FastAPI /분석/스트리밍 → Next.js)

import { NextRequest } from "next/server";
import { 분석서비스 } from "@/lib/llm-service";
import type { 공격로그입력 } from "@/types/input";

interface 스트리밍요청본문 {
  분석유형: string;
  로그: 공격로그입력;
}

export async function POST(req: NextRequest) {
  const body = (await req.json()) as 스트리밍요청본문;
  const { 분석유형, 로그 } = body;

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      try {
        for await (const 이벤트 of 분석서비스.스트리밍분석(로그, 분석유형)) {
          const data = `data: ${JSON.stringify(이벤트)}\n\n`;
          controller.enqueue(encoder.encode(data));
        }
      } catch (e) {
        const 오류 = JSON.stringify({ 유형: "오류", 메시지: String(e) });
        controller.enqueue(encoder.encode(`data: ${오류}\n\n`));
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "X-Accel-Buffering": "no",
      Connection: "keep-alive",
    },
  });
}
