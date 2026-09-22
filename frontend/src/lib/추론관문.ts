/**
 * LLM 추론 엔드포인트의 인증 · 쿼터 · 동시 실행 관문.
 *
 * `/api/analyze/*` 는 인증 없이 열려 있었다. `:8002` 에 닿는 누구나 추론을
 * 돌릴 수 있었고, 본문(로그)이 그대로 프롬프트에 들어가므로 **입력도 호출자가
 * 정했다.** `.env` 에 외부 제공자 키(OpenAI·Anthropic·Gemini)를 넣어 쓰는
 * 구성이면 남의 크레딧을 태우는 프록시가 된다. Spring 쪽 permitAll 을 닫았던
 * 것과 같은 종류의 구멍이 Next 라우트에 남아 있었다.
 *
 * 동시 실행을 함께 막는 이유: 실측으로 ollama 가 **직렬화**된다. 단독 요청은
 * 60초인데 동시 2건이면 두 번째가 82초 걸렸다 — 첫 번째를 기다린 것이다.
 * 이용자 열 명이 동시에 누르면 마지막 사람은 10분을 기다리고, 그동안 브라우저는
 * 아무 말도 하지 않는다. 기다리게 두느니 **바로 거절하는 편이 낫다.**
 */
import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

/** 창 길이(분)와 창당 허용 횟수. 건당 60초라 분당 1건이 사실상 상한이다. */
const 창분 = Number(process.env.LLM_QUOTA_WINDOW_MIN ?? 10);
const 창당허용 = Number(process.env.LLM_QUOTA_PER_WINDOW ?? 5);
/** 동시에 추론 중일 수 있는 요청 수. ollama 가 직렬화하므로 1~2 가 현실적이다. */
const 동시허용 = Number(process.env.LLM_MAX_CONCURRENT ?? 2);

// 프로세스 메모리에 둔다. **재기동하면 초기화되고 복제본 간에 공유되지 않는다** —
// 단일 인스턴스 배포를 전제한 값이다. 여러 대로 늘리면 Postgres 나 Redis 로
// 옮겨야 한다(사용자 테이블은 이미 Postgres 에 있다).
const 사용기록 = new Map<string, number[]>();
let 실행중 = 0;

export type 관문결과 =
  | { 통과: true; 사용자: string; 해제: () => void }
  | { 통과: false; 응답: NextResponse };

function 거절(status: number, message: string, extra?: Record<string, unknown>) {
  return NextResponse.json({ message, ...extra }, { status });
}

/**
 * 토큰을 검증하고 쿼터·동시 실행을 확인한다.
 *
 * 통과하면 반드시 `해제()` 를 부를 것 — 안 부르면 동시 실행 슬롯이 샌다.
 */
export async function 추론관문통과(req: NextRequest): Promise<관문결과> {
  const auth = 인증헤더값(req);
  if (!auth) {
    return { 통과: false, 응답: 거절(401, "로그인이 필요합니다.") };
  }

  // 서명 검증은 백엔드가 한다. 프론트가 직접 하려면 JWT_SECRET 을 프론트
  // 컨테이너까지 내려야 하는데, 그건 키가 퍼지는 쪽이라 피한다.
  let 사용자: string;
  try {
    const res = await fetch(`${API}/api/users/me`, {
      headers: { Authorization: auth },
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) {
      return { 통과: false, 응답: 거절(401, "로그인이 만료되었습니다. 다시 로그인해주세요.") };
    }
    사용자 = (await res.text()).trim();
    if (!사용자) {
      return { 통과: false, 응답: 거절(401, "사용자를 확인할 수 없습니다.") };
    }
  } catch {
    return { 통과: false, 응답: 거절(503, "인증 서버에 연결할 수 없습니다.") };
  }

  // ── 쿼터 ──
  const 지금 = Date.now();
  const 창시작 = 지금 - 창분 * 60_000;
  const 이력 = (사용기록.get(사용자) ?? []).filter((t) => t > 창시작);
  if (이력.length >= 창당허용) {
    const 다음 = Math.ceil((이력[0] + 창분 * 60_000 - 지금) / 1000);
    return {
      통과: false,
      응답: 거절(429, `분석 요청이 ${창분}분당 ${창당허용}회로 제한됩니다. ${다음}초 후 다시 시도하세요.`,
                 { 재시도초: 다음, 창분, 창당허용 }),
    };
  }

  // ── 동시 실행 ──
  if (실행중 >= 동시허용) {
    return {
      통과: false,
      응답: 거절(503, "다른 분석이 진행 중입니다. 잠시 후 다시 시도하세요.",
                 { 실행중, 동시허용 }),
    };
  }

  이력.push(지금);
  사용기록.set(사용자, 이력);
  실행중 += 1;

  let 해제됨 = false;
  return {
    통과: true,
    사용자,
    해제: () => {
      // 스트리밍은 정상 종료·오류·클라이언트 이탈 어디로든 끝날 수 있다.
      // 한 요청이 슬롯을 두 번 반납하면 카운터가 음수로 흘러 제한이 무력해진다.
      if (해제됨) return;
      해제됨 = true;
      실행중 = Math.max(0, 실행중 - 1);
    },
  };
}
