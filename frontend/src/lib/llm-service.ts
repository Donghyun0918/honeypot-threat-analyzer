/**
 * LLM 분석 서비스
 * - 일반 분석 (단건 응답)
 * - 스트리밍 분석 (토큰 단위 실시간 전송)
 *
 * 제공자(Ollama/OpenAI/Anthropic/Gemini)는 llm-providers.ts 의 추상화에 위임.
 * 환경변수 LLM_PROVIDER 로 선택하며, 이 서비스의 분석 로직은 제공자와 무관하게 동일.
 * (services/llm_service.py → TypeScript)
 */

import type { 공격로그입력 } from "@/types/input";
import {
  프롬프트맵,
  분석단계이름,
  전체리포트_프롬프트,
} from "@/lib/prompts";
import { 제공자생성, type LLM제공자 } from "@/lib/llm-providers";

const 최대재시도 = 2;

/**
 * 한자가 섞였는가.
 *
 * 사이드카(`prompt_ko.py` 의 `_has_cjk`)와 같은 규칙이다 — 한중일 통합 한자
 * 영역만 본다. 한글과 영문 기술 용어는 통과한다.
 *
 * 모델이 한국어 지시를 받고도 "攻擊者" 처럼 한자를 섞어 내는 일이 있었고,
 * 보고서 8장이 그걸 조용한 실패로 기록했다. 그런데 그 수정은 파이썬 사이드카
 * 에만 들어갔고 **이 경로는 그대로였다** — 대시보드에서 누르는 버튼이 이쪽이다.
 */
export function 한자포함(텍스트: string): boolean {
  return /[\u4e00-\u9fff]/.test(텍스트);
}

/**
 * 모델이 실패했을 때 쓸 최소 결과.
 *
 * 사이드카의 `fallback_result` 와 같은 자리다. 화면이 빈 칸을 그리면 "분석
 * 결과가 없다" 가 아니라 "분석했는데 내용이 없다" 로 보이므로, 왜 비었는지를
 * 문장으로 채운다. 위험도는 여기서도 **모델이 아니라 점수에서** 가져온다.
 */
export function 폴백결과(로그: 공격로그입력, 사유: string): Record<string, unknown> {
  const 유형 = 로그.공격유형 ?? "미분류";
  const 포트 = 로그.대상URI ? ` 포트 ${String(로그.대상URI).replace(/^:/, "")}` : "";
  return {
    요약: `${로그.공격자IP ?? "알 수 없는 출발지"} 에서 ${유형} 유형의 접근이` +
          `${포트} 관측됐습니다. 자동 해설을 만들지 못해 분류 결과만 표시합니다.`,
    대응: "원본 이벤트와 허니팟 로그를 직접 확인하십시오.",
    위험등급: 로그.위험등급 ?? null,
    실패사유: 사유,
  };
}

function JSON추출(텍스트: string): Record<string, unknown> {
  let s = 텍스트.replace(/```(?:json)?\s*/g, "").replace(/```\s*$/g, "").trim();
  const m = s.match(/\{[\s\S]*\}/);
  if (m) s = m[0];
  const 결과 = JSON.parse(s) as Record<string, unknown>;
  // 파싱은 됐는데 한자가 섞인 응답은 **성공으로 치면 안 된다.** 재시도 대상이다.
  if (한자포함(JSON.stringify(결과))) {
    throw new Error("응답에 한자가 섞여 있습니다");
  }
  return 결과;
}

export class LLM분석서비스 {
  readonly provider: LLM제공자;
  readonly 모델: string;

  constructor(provider: LLM제공자 = 제공자생성()) {
    this.provider = provider;
    this.모델 = provider.모델;
  }

  // ─── 내부: 재시도 호출 (제공자 단건 호출 위임) ──────────────────────────

  /**
   * 한 번 호출하고, 실패하면 재시도한다.
   *
   * `로그` 를 받으면 재시도를 다 쓴 뒤 예외 대신 **폴백 결과**를 돌려준다 —
   * 화면이 빈 칸을 그리는 것보다 왜 비었는지 말하는 편이 낫다.
   */
  async _재시도호출(프롬프트: string, 로그?: 공격로그입력): Promise<Record<string, unknown>> {
    let lastError: unknown;
    for (let i = 0; i <= 최대재시도; i++) {
      try {
        const 원문 = await this.provider.호출(프롬프트);
        return JSON추출(원문);
      } catch (e) {
        lastError = e;
      }
    }
    if (로그) return 폴백결과(로그, String(lastError).slice(0, 200));
    throw new Error(`JSON 파싱 실패: ${String(lastError)}`);
  }

  // ─── 스트리밍: 단일 분석 ─────────────────────────────────────────────────

  async *_단일스트리밍(
    로그: 공격로그입력,
    분석유형: string
  ): AsyncGenerator<Record<string, unknown>> {
    const 프롬프트fn = 프롬프트맵[분석유형];
    if (!프롬프트fn) {
      yield { 유형: "오류", 메시지: `알 수 없는 분석 유형: ${분석유형}` };
      return;
    }
    const 프롬프트 = 프롬프트fn(로그);
    let 전체텍스트 = "";

    for await (const [token, done] of this.provider.스트리밍(프롬프트)) {
      if (token) {
        전체텍스트 += token;
        yield { 유형: "토큰", 텍스트: token };
      }
      if (done) break;
    }

    try {
      const 결과 = JSON추출(전체텍스트);
      yield { 유형: "완료", 결과, 분석유형 };
    } catch (e) {
      // 스트리밍은 토큰이 이미 화면에 나간 뒤라 되돌릴 수 없다. 한자가 섞였거나
      // 파싱이 깨졌다는 것을 **말해주고** 폴백으로 대체한다 — 그대로 두면
      // 사용자는 한자 섞인 문장을 정상 결과로 읽는다.
      const 한자였나 = 한자포함(전체텍스트);
      yield {
        유형: "경고",
        메시지: 한자였나
          ? "모델 응답에 한자가 섞여 아래 결과로 대체했습니다."
          : `결과를 해석하지 못해 아래로 대체했습니다: ${String(e).slice(0, 120)}`,
      };
      yield { 유형: "완료", 결과: 폴백결과(로그, String(e).slice(0, 200)), 분석유형 };
    }
  }

  // ─── 스트리밍: 전체 리포트 (5단계) ─────────────────────────────────────

  async *_전체리포트스트리밍(
    로그: 공격로그입력
  ): AsyncGenerator<Record<string, unknown>> {
    const 단계목록 = ["사건요약", "의도분석", "숙련도분석", "대응권고"];
    const 수집결과: Record<string, Record<string, unknown>> = {};
    const 총단계 = 5;

    for (let i = 0; i < 단계목록.length; i++) {
      const 유형 = 단계목록[i];
      yield { 유형: "단계시작", 단계: i + 1, 총단계, 이름: 분석단계이름[유형] };

      const 프롬프트 = 프롬프트맵[유형](로그);
      let 전체텍스트 = "";

      for await (const [token, done] of this.provider.스트리밍(프롬프트)) {
        if (token) {
          전체텍스트 += token;
          yield { 유형: "토큰", 텍스트: token };
        }
        if (done) break;
      }

      try {
        const 결과 = JSON추출(전체텍스트);
        수집결과[유형] = 결과;
        yield { 유형: "단계완료", 단계: i + 1, 이름: 분석단계이름[유형], 결과 };
      } catch (e) {
        // 한 단계가 깨졌다고 리포트 전체를 버리지 않는다. 그전까지 나온 단계는
        // 멀쩡하고, 사용자는 이미 토큰이 흐르는 것을 봤다 — 여기서 return 하면
        // 화면이 중간에서 멈춘 채로 남는다.
        const 사유 = 한자포함(전체텍스트)
          ? `${분석단계이름[유형]} 응답에 한자가 섞였습니다`
          : `${분석단계이름[유형]} 파싱 실패: ${String(e).slice(0, 120)}`;
        yield { 유형: "경고", 메시지: `${사유} — 이 단계는 대체 내용으로 채웁니다.` };
        수집결과[유형] = 폴백결과(로그, 사유);
        yield { 유형: "단계완료", 단계: i + 1, 이름: 분석단계이름[유형], 결과: 수집결과[유형] };
      }
    }

    // 5단계: 리포트 서술
    yield { 유형: "단계시작", 단계: 5, 총단계, 이름: "리포트 서술 생성" };

    const 서술프롬프트 = 전체리포트_프롬프트(
      로그,
      수집결과["사건요약"] ?? {},
      수집결과["의도분석"] ?? {},
      수집결과["숙련도분석"] ?? {},
      수집결과["대응권고"] ?? {}
    );
    let 서술텍스트 = "";

    for await (const [token, done] of this.provider.스트리밍(서술프롬프트)) {
      if (token) {
        서술텍스트 += token;
        yield { 유형: "토큰", 텍스트: token };
      }
      if (done) break;
    }

    let 서술결과: Record<string, unknown>;
    try {
      서술결과 = JSON추출(서술텍스트);
    } catch {
      // JSON 이 아니면 원문을 그대로 쓰던 자리다. 그런데 원문에 한자가 섞여
      // 있으면 그대로 화면에 나간다 — JSON추출이 막아도 이 경로로 새어 나왔다.
      if (한자포함(서술텍스트)) {
        yield { 유형: "경고", 메시지: "리포트 서술에 한자가 섞여 대체했습니다." };
        서술결과 = { 리포트서술: String(폴백결과(로그, "서술에 한자 혼입").요약) };
      } else {
        서술결과 = { 리포트서술: 서술텍스트 };
      }
    }

    yield {
      유형: "완료",
      분석유형: "전체리포트",
      결과: {
        사건요약: 수집결과["사건요약"] ?? {},
        의도분석: 수집결과["의도분석"] ?? {},
        숙련도분석: 수집결과["숙련도분석"] ?? {},
        대응권고: 수집결과["대응권고"] ?? {},
        리포트서술: 서술결과["리포트서술"] ?? "",
        생성시각: new Date().toISOString(),
        사용모델: this.모델,
      },
    };
  }

  // ─── 공개: 스트리밍 분석 진입점 ─────────────────────────────────────────

  async *스트리밍분석(
    로그: 공격로그입력,
    분석유형: string
  ): AsyncGenerator<Record<string, unknown>> {
    if (!(분석유형 in 프롬프트맵) && 분석유형 !== "전체리포트") {
      yield { 유형: "오류", 메시지: `알 수 없는 분석 유형: ${분석유형}` };
      return;
    }

    const 이름 = 분석단계이름[분석유형] ?? "전체 리포트";
    yield { 유형: "시작", 메시지: `${이름} 시작...` };

    if (분석유형 === "전체리포트") {
      yield* this._전체리포트스트리밍(로그);
    } else {
      yield* this._단일스트리밍(로그, 분석유형);
    }
  }

  // ─── 서버 상태 확인 ──────────────────────────────────────────────────────

  async 서버상태확인(): Promise<boolean> {
    return this.provider.상태확인();
  }
}

// 싱글톤 인스턴스
export const 분석서비스 = new LLM분석서비스();
