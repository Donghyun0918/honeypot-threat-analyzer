// 브라우저 쪽 토큰 보관.
//
// 로그인하면 백엔드가 준 JWT 를 여기 담고, 보호된 API 를 부를 때 꺼내 쓴다.
// localStorage 는 사생활 보호 모드나 저장 차단 설정에서 접근 자체가 예외를
// 던지므로 모든 호출을 감싼다 — 저장이 안 되는 것과 앱이 죽는 것은 다르다.

const 키 = "jsp.token";

export function 토큰읽기(): string | null {
  try {
    return localStorage.getItem(키);
  } catch {
    return null;
  }
}

export function 토큰저장(token: string): void {
  try {
    localStorage.setItem(키, token);
  } catch {
    /* 저장이 막혀도 이번 세션 동안은 메모리로 동작한다 */
  }
}

export function 토큰지우기(): void {
  try {
    localStorage.removeItem(키);
  } catch {
    /* 무시 */
  }
}

/** 보호된 API 호출용 헤더. 토큰이 없으면 빈 객체를 준다. */
export function 인증헤더(): Record<string, string> {
  const t = 토큰읽기();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

/** 토큰을 실어 보내는 fetch. 401/403 이면 토큰을 버린다(만료·위조). */
export async function 인증fetch(input: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(input, {
    ...init,
    headers: { ...(init.headers ?? {}), ...인증헤더() },
  });
  if (res.status === 401 || res.status === 403) {
    토큰지우기();
  }
  return res;
}
