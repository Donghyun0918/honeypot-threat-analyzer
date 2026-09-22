// GET/PUT /api/assets — 내 자산 포트 목록.
//
// 브라우저(localStorage)에 두면 기기를 바꿀 때마다 사라진다. 여러 사람이 같은
// 센서를 공유하는 형태에서는 공격 데이터는 공유하되 **자산 대조는 계정별**이라야
// 하므로 백엔드에 둔다. 사용자 식별은 토큰으로만 하고 경로에 id 를 받지 않는다.

import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

function 인증전달(req: NextRequest): Record<string, string> | undefined {
  const auth = 인증헤더값(req);
  return auth ? { Authorization: auth } : undefined;
}

export async function GET(req: NextRequest) {
  const auth = 인증전달(req);
  if (!auth) return NextResponse.json({ message: "로그인이 필요합니다." }, { status: 401 });
  try {
    const res = await fetch(`${API}/api/assets`, {
      cache: "no-store", headers: auth, signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return NextResponse.json({ rawText: "" }, { status: res.status });
    return NextResponse.json(await res.json());
  } catch {
    return NextResponse.json({ message: "백엔드에 연결할 수 없습니다." }, { status: 503 });
  }
}

export async function PUT(req: NextRequest) {
  const auth = 인증전달(req);
  if (!auth) return NextResponse.json({ message: "로그인이 필요합니다." }, { status: 401 });
  try {
    const body = await req.text();
    const res = await fetch(`${API}/api/assets`, {
      method: "PUT",
      headers: { ...auth, "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(8_000),
    });
    const 본문 = await res.json().catch(() => ({}));
    return NextResponse.json(본문, { status: res.status });
  } catch {
    return NextResponse.json({ message: "백엔드에 연결할 수 없습니다." }, { status: 503 });
  }
}
