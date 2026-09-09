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

function JSON추출(텍스트: string): Record<string, unknown> {
  let s = 텍스트.replace(/```(?:json)?\s*/g, "").replace(/```\s*$/g, "").trim();
  const m = s.match(/\{[\s\S]*\}/);
  if (m) s = m[0];
  return JSON.parse(s) as Record<string, unknown>;
}

export class LLM분석서비스 {
  readonly provider: LLM제공자;
  readonly 모델: string;

  constructor(provider: LLM제공자 = 제공자생성()) {
    this.provider = provider;
    this.모델 = provider.모델;
  }

  // ─── 내부: 재시도 호출 (제공자 단건 호출 위임) ──────────────────────────

  async _재시도호출(프롬프트: string): Promise<Record<string, unknown>> {
    let lastError: unknown;
    for (let i = 0; i <= 최대재시도; i++) {
      try {
        const 원문 = await this.provider.호출(프롬프트);
        return JSON추출(원문);
      } catch (e) {
        lastError = e;
      }
    }
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
      yield { 유형: "오류", 메시지: `결과 파싱 실패: ${String(e)}` };
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
        yield { 유형: "오류", 메시지: `${분석단계이름[유형]} 파싱 실패: ${String(e)}` };
        return;
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
      서술결과 = { 리포트서술: 서술텍스트 };
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
