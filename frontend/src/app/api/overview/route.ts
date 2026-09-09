// GET /api/overview — T-Pot 24시간 개요 통계.
// Spring threat-console 백엔드(/api/overview)를 서버사이드로 프록시.
// 반환: { since, total_events, total_attacks, high_risk, llm_analyzed }

import { NextResponse } from "next/server";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

export async function GET(req: Request) {
  try {
    // 로그인 토큰을 백엔드로 그대로 넘긴다. 지금은 이 엔드포인트가 permitAll
    // 이지만(순정 T-Pot 배포에서도 쓰인다), 권한을 조이더라도 화면이 그대로
    // 동작하도록 미리 실어 보낸다.
    const auth = req.headers.get("authorization");
    const res = await fetch(`${API}/api/overview`, {
      cache: "no-store",
      headers: auth ? { Authorization: auth } : undefined,
    });
    if (!res.ok) {
      return NextResponse.json({ total_events: 0, total_attacks: 0, high_risk: 0, llm_analyzed: 0, 오류: `backend ${res.status}` });
    }
    return NextResponse.json(await res.json());
  } catch (e) {
    return NextResponse.json({ total_events: 0, total_attacks: 0, high_risk: 0, llm_analyzed: 0, 오류: String(e) });
  }
}
