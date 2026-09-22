// GET /api/auth/me — 토큰이 유효한지 확인하고 사용자 식별자를 돌려준다.
//
// 대시보드가 진입할 때 토큰이 실제로 살아 있는지 확인하는 용도다.
// localStorage 에 값이 남아 있어도 만료됐거나 서버 서명 키가 바뀌었으면
// 무효이므로, 값의 존재만으로 로그인 상태를 판단하면 안 된다.

import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

export async function GET(req: NextRequest) {
  const auth = 인증헤더값(req);
  if (!auth) {
    return NextResponse.json({ message: "인증이 필요합니다." }, { status: 401 });
  }

  try {
    const res = await fetch(`${API}/api/users/me`, {
      headers: { Authorization: auth },
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });

    if (!res.ok) {
      return NextResponse.json(
        { message: "로그인이 만료되었습니다. 다시 로그인해주세요." },
        { status: 401 }
      );
    }

    // 백엔드는 이메일 문자열을 그대로 준다.
    const email = (await res.text()).trim();
    return NextResponse.json({ email });
  } catch {
    return NextResponse.json(
      { message: "인증 서버에 연결할 수 없습니다." },
      { status: 503 }
    );
  }
}
