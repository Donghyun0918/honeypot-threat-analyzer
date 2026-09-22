// 서버 전용 — JWT 를 httpOnly 쿠키로 다룬다.
//
// **왜 바꿨나.** 전에는 로그인 응답의 토큰을 브라우저 JS 가 받아 localStorage 에
// 넣고, 요청마다 Authorization 헤더에 실었다. 그러면 **JS 가 토큰을 읽을 수 있고**,
// XSS 가 한 번이라도 나면 토큰이 통째로 나간다. 이 프로젝트는 대시보드에 외부
// 문자열(공격자가 넣은 명령·페이로드·LLM 해설)을 그대로 띄우는 화면이 여럿이라,
// 그 위험을 안고 갈 이유가 없다.
//
// httpOnly 쿠키는 **JS 에서 읽히지 않는다.** 브라우저가 알아서 실어 보내고,
// Next 서버 라우트만 꺼내 Spring 으로 넘긴다.
//
// **SameSite=Lax 인 이유.** 쿠키는 헤더와 달리 브라우저가 자동으로 붙이므로
// CSRF 가 생긴다. Lax 는 다른 사이트에서 시작된 POST 에 쿠키를 붙이지 않는다 —
// 이 앱의 상태 변경은 전부 POST(/api/assets, /api/analyze/*)라 이것으로 막힌다.
// Strict 로 하면 외부 링크를 타고 들어올 때 로그인이 풀린 것처럼 보인다.

import { NextRequest, NextResponse } from "next/server";

export const 쿠키이름 = "jsp_token";

/** 기본 수명(초). 백엔드 JWT_EXPIRATION_MINUTES 기본값(60분)과 맞춘다. */
const 기본수명초 = 60 * 60;

/**
 * 요청에서 토큰을 꺼낸다.
 *
 * 쿠키를 먼저 보고, 없으면 Authorization 헤더를 본다. 헤더도 받는 이유는
 * 두 가지다 — 쿠키 전환 전에 로그인해 둔 브라우저가 한 번은 더 동작해야 하고,
 * 스크립트(integration-tests)가 헤더로 부른다.
 */
export function 토큰꺼내기(req: NextRequest): string | null {
  const c = req.cookies.get(쿠키이름)?.value;
  if (c) return c;

  const auth = req.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

/**
 * Spring 으로 넘길 Authorization 헤더 값(`Bearer ...`). 토큰이 없으면 null.
 *
 * 라우트들이 `const auth = req.headers.get("authorization")` 로 쓰던 자리를
 * 그대로 대체한다 — 그래서 반환 타입이 string | null 이다.
 */
export function 인증헤더값(req: NextRequest): string | null {
  const t = 토큰꺼내기(req);
  return t ? `Bearer ${t}` : null;
}

/** Spring 으로 넘길 Authorization 헤더. 토큰이 없으면 빈 객체. */
export function 전달헤더(req: NextRequest): Record<string, string> {
  const t = 토큰꺼내기(req);
  return t ? { Authorization: `Bearer ${t}` } : {};
}

/**
 * 백엔드 응답이 인증 실패면 그대로 내보낼 응답을 만든다(아니면 null).
 *
 * **데이터 오류와 인증 실패를 갈라야 한다.** 프록시 라우트들은 백엔드가 실패하면
 * 빈 목록에 200 을 실어 보낸다 — 화면이 깨지는 대신 "아직 없음" 을 보여주려는
 * 것이고, 데이터 문제에는 맞는 처리다. 그런데 **로그인이 풀린 경우까지 200 으로
 * 덮으면**, 로그아웃한 사용자가 로그인 화면 대신 0 으로 채워진 대시보드를 본다.
 * 세션이 끝난 것을 "데이터가 없음" 으로 보여주는 셈이다.
 */
export function 인증실패통과(status: number): NextResponse | null {
  if (status !== 401 && status !== 403) return null;
  return NextResponse.json({ message: "인증이 필요합니다." }, { status });
}

/** 로그인 성공 응답에 쿠키를 심는다. */
export function 쿠키심기(res: NextResponse, token: string, 수명초 = 기본수명초): NextResponse {
  res.cookies.set({
    name: 쿠키이름,
    value: token,
    httpOnly: true,      // JS 에서 읽히지 않는다 — 이게 핵심이다
    sameSite: "lax",     // CSRF 방어(위 주석 참조)
    path: "/",
    maxAge: 수명초,
    // HTTPS 로 서비스할 때만 켠다. 시연은 http://localhost 라, 여기서 무조건
    // true 로 두면 **쿠키가 아예 저장되지 않아 로그인이 안 된다.**
    secure: process.env.COOKIE_SECURE === "true",
  });
  return res;
}

/** 로그아웃 — 쿠키를 즉시 만료시킨다. */
export function 쿠키지우기(res: NextResponse): NextResponse {
  res.cookies.set({
    name: 쿠키이름,
    value: "",
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
    secure: process.env.COOKIE_SECURE === "true",
  });
  return res;
}
