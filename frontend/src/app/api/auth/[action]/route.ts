// POST /api/auth/signup · /api/auth/login — Spring 인증 API 프록시.
//
// 브라우저가 Spring 을 직접 부르면 백엔드 주소가 노출되고 CORS 설정도 따로
// 필요하다. 대시보드의 다른 데이터 경로(/api/overview, /api/attacks)와 같은
// 방식으로 서버 라우트에서 중계한다.

import { NextRequest, NextResponse } from "next/server";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

const 경로: Record<string, string> = {
  signup: "/api/users/signup",
  login: "/api/users/login",
};

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ action: string }> }
) {
  const { action } = await params;
  const 대상 = 경로[action];
  if (!대상) {
    return NextResponse.json({ message: "알 수 없는 요청입니다." }, { status: 404 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ message: "요청 형식이 올바르지 않습니다." }, { status: 400 });
  }

  try {
    const res = await fetch(API + 대상, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // 백엔드가 응답하지 않을 때 사용자를 무한정 기다리게 두지 않는다.
      signal: AbortSignal.timeout(10_000),
    });

    // 백엔드는 오류를 { message, status } 로 준다. 그대로 전달해
    // 화면이 "이미 사용 중인 이메일입니다" 같은 문장을 그대로 쓰게 한다.
    const text = await res.text();
    const payload = text ? JSON.parse(text) : {};
    return NextResponse.json(payload, { status: res.status });
  } catch (e) {
    const 시간초과 = e instanceof Error && e.name === "TimeoutError";
    return NextResponse.json(
      {
        message: 시간초과
          ? "서버 응답이 지연되고 있습니다. 잠시 후 다시 시도해주세요."
          : "서버에 연결할 수 없습니다. 백엔드가 실행 중인지 확인해주세요.",
      },
      { status: 503 }
    );
  }
}
