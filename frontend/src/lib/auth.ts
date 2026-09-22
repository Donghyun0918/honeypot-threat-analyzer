// 브라우저 쪽 세션 처리.
//
// **토큰을 더는 여기서 들고 있지 않는다.** 전에는 로그인 응답의 JWT 를
// localStorage 에 넣고 요청마다 Authorization 헤더로 실었다. 그러면 JS 가
// 토큰을 읽을 수 있고, XSS 가 한 번이라도 나면 그대로 새어 나간다 — 대시보드는
// 공격자가 남긴 문자열(명령·페이로드)과 LLM 해설을 화면에 띄우는 곳이라 그
// 위험을 안고 갈 이유가 없었다.
//
// 지금은 서버가 httpOnly 쿠키로 내려주고(`lib/세션쿠키.ts`), 브라우저가 알아서
// 실어 보낸다. 그래서 이 파일에는 **토큰을 만지는 함수가 없다.**

/**
 * 세션을 실어 보내는 fetch.
 *
 * 쿠키는 같은 출처면 자동으로 붙지만 `credentials` 를 명시해 둔다 — 기본값이
 * 바뀌거나 다른 출처로 옮길 때 조용히 인증이 빠지는 것을 막는다.
 *
 * 401/403 이면 세션이 없거나 만료된 것이다. 쿠키는 JS 가 지울 수 없으므로
 * 서버에 지워달라고 한 뒤(`/api/auth/logout`) 호출한 쪽이 화면을 정한다.
 */
export async function 인증fetch(input: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(input, { ...init, credentials: "same-origin" });
  if (res.status === 401 || res.status === 403) {
    await 로그아웃().catch(() => {});
  }
  return res;
}

/** 서버에 쿠키를 만료시켜 달라고 한다. httpOnly 라 JS 로는 못 지운다. */
export async function 로그아웃(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
}

/**
 * 지금 로그인돼 있는지.
 *
 * 쿠키를 읽을 수 없으니 **서버에 물어보는 수밖에 없다.** 전에는 localStorage 에
 * 값이 있는지로 판단했는데, 그건 사실 "값이 남아 있는지" 였을 뿐 만료·서명 키
 * 교체를 알지 못했다 — 이제는 물어보는 쪽이 정확하기까지 하다.
 */
export async function 로그인상태(): Promise<boolean> {
  try {
    const res = await fetch("/api/auth/me", { credentials: "same-origin", cache: "no-store" });
    return res.ok;
  } catch {
    return false;
  }
}
