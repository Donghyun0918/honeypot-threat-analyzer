/**
 * 프론트 LLM 경로의 방어 회귀 테스트.
 *
 * 사이드카(prompt_ko.py)에는 한자 차단과 폴백이 있는데 **이 경로에는 없었다.**
 * 보고서 8장이 한자 혼입을 조용한 실패로 기록해두고 수정은 파이썬에만 넣은
 * 것이다. 대시보드에서 누르는 버튼이 이쪽을 쓰므로 시연에서 바로 드러날
 * 자리였다.
 *
 * 준비물 없이 돈다(node 내장 test runner):
 *   node --test frontend/tests/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// TypeScript 를 그대로 불러올 수 없으므로 소스에서 함수 본문을 떼어내 평가한다.
// 빌드 산출물에 의존하면 테스트가 빌드를 먼저 요구하게 되고, 그러면 아무도
// 돌리지 않는다(사이드카 테스트를 표준 라이브러리만으로 만든 것과 같은 이유).
const 원본 = readFileSync(new URL("../src/lib/llm-service.ts", import.meta.url), "utf-8");

function 함수떼기(이름) {
  // 정규식 없이 문자열로 찾는다 — 이스케이프가 꼬이면 테스트가 대상이 아니라
  // 자기 자신 때문에 실패한다.
  const 머리 = `export function ${이름}(`;
  const i = 원본.indexOf(머리);
  if (i < 0) throw new Error(`${이름} 를 소스에서 찾지 못했다`);

  const 인자끝 = 원본.indexOf(")", i + 머리.length);
  const 인자 = 원본.slice(i + 머리.length, 인자끝)
    .split(",").map((a) => a.split(":")[0].trim()).filter(Boolean);

  let 시작 = 원본.indexOf("{", 인자끝), 깊이 = 0, 끝 = 시작;
  for (; 끝 < 원본.length; 끝++) {
    if (원본[끝] === "{") 깊이++;
    else if (원본[끝] === "}") { 깊이--; if (깊이 === 0) break; }
  }
  const 본문 = 원본.slice(시작 + 1, 끝)
    .replace(/:\s*(string|boolean|Record<string,\s*unknown>|공격로그입력)(?=[,)\s=])/g, "")
    .replace(/\s+as\s+\w+/g, "");
  return new Function(...인자, 본문);
}

const 한자포함 = 함수떼기("한자포함");
const 폴백결과 = 함수떼기("폴백결과");

// ── 한자 차단 ────────────────────────────────────────────────────────────
// 모델이 한국어 지시를 받고도 "攻擊者" 처럼 섞어 내는 일이 있었다.
test("한자가 섞이면 잡아낸다", () => {
  assert.equal(한자포함("공격자가 攻擊을 시도했습니다"), true);
  assert.equal(한자포함("中國에서 온 접속"), true);
});

test("순수 한국어와 영문 기술 용어는 통과한다", () => {
  assert.equal(한자포함("공격자가 SSH 포트 22로 접속을 시도했습니다"), false);
  assert.equal(한자포함("SMB(445) 취약점을 노린 DoublePulsar 백도어"), false);
  assert.equal(한자포함(""), false);
});

// 한글 자모·기호는 한자 영역이 아니다. 여기서 오탐이 나면 멀쩡한 응답을
// 전부 폴백으로 바꿔버린다.
test("한글과 기호를 한자로 오인하지 않는다", () => {
  assert.equal(한자포함("ㄱㄴㄷ 가나다 ①② ※ → 「」"), false);
});

// ── 폴백 ─────────────────────────────────────────────────────────────────
// 화면이 빈 칸을 그리면 "결과가 없다" 가 아니라 "분석했는데 내용이 없다" 로
// 보인다. 왜 비었는지를 문장으로 채워야 한다.
test("폴백은 필드를 비워두지 않는다", () => {
  const r = 폴백결과({ 공격자IP: "203.0.113.9", 공격유형: "INTRUSION", 위험등급: "HIGH" }, "모델 없음");
  assert.ok(r.요약 && String(r.요약).length > 10, "요약이 비었다");
  assert.ok(r.대응 && String(r.대응).length > 5, "대응이 비었다");
  assert.equal(r.실패사유, "모델 없음");
});

// 위험도는 모델이 아니라 점수에서 온다(보고서 7장). 폴백도 그 규칙을 지켜야
// 하므로 입력으로 받은 등급을 그대로 쓴다 — 여기서 새로 지어내면 안 된다.
test("폴백은 위험등급을 지어내지 않는다", () => {
  assert.equal(폴백결과({ 위험등급: "CRITICAL" }, "x").위험등급, "CRITICAL");
  assert.equal(폴백결과({}, "x").위험등급, null);
});

// 폴백 문장 자체에 한자가 있으면 한자를 막으려다 한자를 넣는 셈이 된다.
test("폴백 문장에도 한자가 없다", () => {
  const r = 폴백결과({ 공격자IP: "203.0.113.9", 공격유형: "MALWARE" }, "실패");
  assert.equal(한자포함(String(r.요약) + String(r.대응)), false);
});
