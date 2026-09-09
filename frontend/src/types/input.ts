// LLM 분석을 위한 공격 로그 입력 타입 (models/input.py → TypeScript)

export type 공격유형코드 =
  // ML 모델(9-class CICIDS LightGBM) 카테고리 — ml_label과 1:1 (attacks/route.ts 유형맵)
  | "NORMAL"
  | "RECON"
  | "BRUTE_FORCE"
  | "INTRUSION"
  | "MALWARE"
  | "WEB_ATTACK"
  | "SERVICE_ATTACK"
  | "ICS_ATTACK"
  // 세부 웹/네트워크 공격 코드 (기존 — 하위호환 유지)
  | "SQL_INJECTION"
  | "XSS"
  | "COMMAND_INJECTION"
  | "PATH_TRAVERSAL"
  | "PORT_SCAN"
  | "DDOS"
  | "RCE"
  | "SSRF"
  | "UNKNOWN";

export type 위험등급코드 = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface 공격로그입력 {
  // 기본 식별 정보
  사건ID: string;
  허니팟ID: string;
  발생시각: string; // ISO 8601

  // 공격자 정보
  공격자IP: string;
  공격자국가?: string;
  공격자포트?: number;

  // 공격 분류 (ML 모델 결과)
  공격유형: 공격유형코드;
  위험점수: number; // 0~100
  탐지신뢰도: number; // 0~1
  위험등급: 위험등급코드;

  // 표준 프레임워크 매핑 결과
  OWASP분류?: string;
  MITRE전술?: string;

  // 원본 공격 데이터
  페이로드?: string;
  대상URI?: string;
  HTTP메서드?: string;
  사용자에이전트?: string;

  // 행위 시퀀스
  행위시퀀스: string[];
  요청횟수: number;
  세션지속시간?: number;
}
