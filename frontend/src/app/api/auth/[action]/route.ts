// POST /api/auth/signup · /api/auth/login — Spring 인증 API 프록시.
//
// 브라우저가 Spring 을 직접 부르면 백엔드 주소가 노출되고 CORS 설정도 따로
// 필요하다. 대시보드의 다른 데이터 경로(/api/overview, /api/attacks)와 같은
// 방식으로 서버 라우트에서 중계한다.

import { NextRequest, NextResponse } from "next/server";
import { 쿠키심기, 쿠키지우기 } from "@/lib/세션쿠키";

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

  // 로그아웃은 Spring 을 부를 것이 없다. 쿠키가 httpOnly 라 브라우저 JS 가
  // 지울 수 없으므로, 서버가 만료된 쿠키를 내려보내는 것이 로그아웃이다.
  if (action === "logout") {
    return 쿠키지우기(NextResponse.json({ ok: true }));
  }

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

    // 로그인 성공 — 토큰은 httpOnly 쿠키로만 내려보낸다.
    //
    // **본문에서 token 을 빼는 것이 이 변경의 핵심이다.** 브라우저 JS 가 한 번이라도
    // 토큰을 손에 쥐면 localStorage 든 변수든 어딘가에 남고, XSS 한 번에 새어
    // 나간다. 화면은 토큰을 알 필요가 없다 — 쿠키는 브라우저가 알아서 붙인다.
    if (action === "login" && res.ok && typeof payload?.token === "string") {
      const { token, ...나머지 } = payload as { token: string } & Record<string, unknown>;
      const out = NextResponse.json({ ...나머지, ok: true }, { status: res.status });
      return 쿠키심기(out, token);
    }

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
