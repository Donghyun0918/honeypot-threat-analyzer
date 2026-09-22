"use client";

// 파이프라인 도식 — 랜딩 "구조" 절의 본론.
//
// 4단 표가 "무엇을 받아 무엇을 내는가" 를 적어둔 것이라면, 이 도식은 그게
// 실제로 어떻게 흐르는지다. 어디서 갈라지고 어디가 막히는지는 글로는 안 보인다.
//
// 데이터: AWS 에 띄운 T-Pot 이 2026-04-27 ~ 05-06 (10일) 동안 실제로 받은
// 공격 로그다. 2026-09-14 에 logstash 로 ES 에 색인하고 파이프라인을 완주시킨
// 뒤 집계했다. p0f(170만 행)는 수동 핑거프린팅이라 제외.
//
// 입자 하나는 로그 500건이다. 100만 건을 1:1 로 그릴 수 없어 축척을 뒀고,
// 비율·분기·적체는 실측 그대로다.
//
// 색은 globals.css 토큰을 쓴다. CRITICAL 만 --red 보다 깊은 자주인데,
// 대시보드의 sev-CRITICAL 이 HIGH(--red) 보다 어두운 것과 같은 규칙이다.

import { useEffect, useRef, useState, useCallback } from "react";
import type { ReactNode } from "react";

/* ── 실측 ───────────────────────────────────────────────────────────────────
   집계 대상은 `ml-analysis-*` 중 **수집 창(2026-04-27 ~ 05-06)** 안의 문서만이다.
   인덱스 전체를 그냥 세면 09-09 시연 표본 1,736건과 지금 들어오는 라이브
   트래픽이 함께 잡혀 수치가 매일 움직인다 — 처음에 그렇게 재서 1,028,698 /
   24,373 / 45,744 로 잘못 적었다. 창을 고정해야 재현된다.

       GET ml-analysis-*&#47;_search
       {"query":{"range":{"@timestamp":{"gte":"2026-04-27","lt":"2026-05-07"}}}}

   수집 창 바깥으로는 logstash-1970.01.01 15,376건이 더 있는데, honeytrap 의
   attackers.json(누적 집계 파일)이라 타임스탬프가 없다. 개별 공격 이벤트가
   아니므로 분류 대상이 아니다.

   **모델 판:** 2026-09-15 에 교차검증 모델을 v4(CSV 세션조인 학습) → v5(실 ES
   문서 25만행 학습)로 교체하고 전량 재분류했다. 아래 이견 수치는 v5 기준이다.
   v4 때는 이견이 126,756건(87.6% 합의)이었는데, 그 대부분이 모델 쪽 오답이었다
   — 자세한 경위는 docker/ml-classifier/training/DATASET_FINDINGS.md §6. */
const 축척 = 500;          // 입자 1개 = 로그 500건

/* 라벨 — 건수·이견 전부 ES 집계값. 전체·고위험·이견수는 여기서 파생시킨다.
   숫자를 두 군데 적으면 한 군데만 고치게 된다(위 주석의 사고가 그거였다). */
const 라벨들 = [
  { 이름: "Etc",         점수: 0,  기법: "—",     건수: 566_099, 이견: 1,   등급: null as null | "crit" | "high" },
  { 이름: "Recon",       점수: 32, 기법: "T1046", 건수: 392_668, 이견: 101, 등급: null },
  { 이름: "Malware",     점수: 92, 기법: "T1105", 건수: 24_455,  이견: 414, 등급: "crit" as const },
  { 이름: "Brute Force", 점수: 65, 기법: "T1110", 건수: 23_061,  이견: 72,  등급: null },
  { 이름: "Intrusion",   점수: 85, 기법: "T1059", 건수: 20_620,  이견: 194, 등급: "high" as const },
];
const 색인 = (n: string) => 라벨들.findIndex((k) => k.이름 === n);
const 이견율 = (k: typeof 라벨들[number]) => k.이견 / k.건수;

const 전체 = 라벨들.reduce((a, k) => a + k.건수, 0);        // 1,026,903
const 고위험 = 라벨들.filter((k) => k.점수 >= 70).reduce((a, k) => a + k.건수, 0);  // 45,075
const 탈락수 = 전체 - 고위험;                                // 981,828
const 이견수 = 라벨들.reduce((a, k) => a + k.이견, 0);       // 782
const 저신뢰 = 0;                                            // model_used=rule(low-conf)
// 이견 782건의 수집 지점 분해 — Suricata 707 · Heralding 67 · Cowrie 8.
// 한 곳에 몰려 있다는 게 이 수치의 요점이라 따로 둔다.
const 이견Suricata = 707;
const 합의수 = 전체 - 이견수 - 저신뢰;                       // 1,026,121
const 공격수 = 전체 - 라벨들[색인("Etc")].건수;              // 460,804 — Etc 만 공격 아님
const 고유IP = 24_346;
const geoip적용 = 840_260;                                   // logstash-* 창 내 geoip.country_name 보유
const 지점수 = 18;                                           // 수집 지점 종류 (허니팟 16 + Suricata + Fatt)

// LLM 처리 가능량 — 실측. exaone3.5:7.8b 를 CPU 로 돌려 10건 배치를 두 번
// 재보니 건당 60.3초 · 61.4초였다(README 의 27초는 3B 기준이다).
const 건당초 = 61;
const LLM일처리 = Math.round(86_400 / 건당초);   // 1,416
const 수집일수 = 10;
const LLM처리 = LLM일처리 * 수집일수;            // 14,160
const LLM적체 = 고위험 - LLM처리;                // 30,915
const 소진일 = (고위험 / LLM일처리).toFixed(1);  // 31.8
const 게이트없이일 = Math.round(전체 * 건당초 / 86_400);  // 725

const 백분 = (n: number, 모수 = 전체) => ((n / 모수) * 100).toFixed(1);

/* 수집 지점 × 라벨 — 실제 교차표. 18종을 4갈래로 묶었다.
   Cowrie 의 Intrusion 이 0 인 것은 오류가 아니다 — 실제 10일간 cowrie 세션에서
   규칙이 침입으로 올린 건이 한 건도 없었다. 학습셋의 cowrie Intrusion 공백
   (DATASET_FINDINGS §4)과 같은 사실의 다른 얼굴이다. */
const 출처들 = [
  { 경로: "s1", 이름: "Suricata",   합계: 727_868,
    분포: { Etc: 565_266, Recon: 141_929, Intrusion: 19_959, Malware: 714 } as Record<string, number> },
  { 경로: "s2", 이름: "Cowrie",     합계: 92_859,
    분포: { Recon: 89_771, "Brute Force": 3_072, Malware: 16 } as Record<string, number> },
  { 경로: "s3", 이름: "Honeytrap",  합계: 79_092,
    분포: { Recon: 79_092 } as Record<string, number> },
  { 경로: "s4", 이름: "기타 15종",  합계: 127_084,
    분포: { Recon: 81_876, Malware: 23_725, "Brute Force": 19_989, Etc: 833, Intrusion: 661 } as Record<string, number> },
];

/* ── 색 (globals.css 토큰) ────────────────────────────────────────────────── */
const 색 = {
  원본: "#94a3b8",   // --text-3
  분류: "#0f6b78",   // --accent
  이견: "#9a5f0c",   // --amber
  high: "#9e3a31",   // --red — 대시보드 sev-HIGH 와 동일
  crit: "#5f1d33",   // sev-CRITICAL 이 HIGH 보다 어두운 규칙을 따름
  탈락: "#c9d2dc",   // --border-strong
};

/* ── 구간별 이동 시간 (1× 기준, 초) ───────────────────────────────────────── */
const 소요: Record<string, number> = {
  s1: 0.95, s2: 0.95, s3: 0.95, s4: 0.95, a: 0.75, b: 0.75, c: 0.7, d: 0.6, e: 0.62,
  이견드롭: 0.85, 탈락드롭: 0.9,
};

const 유입시간 = 42;

type 문서 = { 라벨: typeof 라벨들[number]; 경로: string };
type 입자 = { c: SVGCircleElement; 경로: { el: SVGPathElement; len: number }; t: number; d: number; 끝: () => void };

function 난수(seed: number) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** 실측 교차표를 축척으로 나눠 입자 목록을 만든다. */
function 문서목록(): 문서[] {
  const list: 문서[] = [];
  for (const src of 출처들) {
    for (const [라벨명, n] of Object.entries(src.분포)) {
      const i = 색인(라벨명);
      if (i < 0) continue;
      for (let k = 0; k < Math.round(n / 축척); k++) list.push({ 라벨: 라벨들[i], 경로: src.경로 });
    }
  }
  const r = 난수(20260914);
  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [list[i], list[j]] = [list[j], list[i]];
  }
  return list;
}

const 쉼표 = (n: number) => Math.round(n).toLocaleString("en-US");

/* ── 단계 상세 ────────────────────────────────────────────────────────────── */
const 상세: Record<string, { 제목: string; 부제: string; 항목: [string, string][]; 메모: string }> = {
  수집: {
    제목: `수집 지점 ${지점수}종`, 부제: "AWS EC2 T-Pot · 2026-04-27 ~ 05-06 (10일)",
    항목: [["Suricata", "727,868 · NSM, ET 룰셋 경보"], ["Cowrie", "92,859 · SSH · Telnet"],
           ["Honeytrap", "79,092 · TCP 범용"], ["기타 15종", "127,084 · Fatt · Dionaea · Sentrypeer …"],
           ["고유 공격 IP", 쉼표(고유IP)], ["출력", "logstash-YYYY.MM.DD"]],
    메모: `10일간 받은 실제 공격이다. 출발지 상위는 미국 299,877 · 브라질 99,817 · 영국 55,733 · 중국 47,853 순. Suricata 한 대가 전체의 ${백분(727_868)}%를 만드는데, 이건 허니팟이 아니라 네트워크 전체를 보는 센서라 그렇다. p0f(170만 행)는 수동 핑거프린팅이라 색인에서 뺐다.`,
  },
  logstash: {
    제목: "logstash-2026.04.27 ~ 05.06", 부제: "원본 로그 인덱스 10개",
    항목: [["문서", 쉼표(전체)], ["보존", "일자별 인덱스"], ["enrichment", "geoip · ASN · IP 평판"],
           ["geoip 적용", `${쉼표(geoip적용)} (${백분(geoip적용)}%)`], ["폴링", "ES_SOURCE_INDEX=logstash-*"]],
    메모: "T-Pot 의 logstash 가 포트·프로토콜·행동 필드를 한 문서에 합쳐 넣는다. 학습용 CSV 는 이게 여러 행에 흩어져 있어 모델이 쓸 수 없었는데(train/serve skew), ES 경로엔 그 문제가 없다. 보관 로그가 4개월 전이라 BOOTSTRAP_WINDOW 를 now-1y 로 올려야 보인다 — 기본값 now-24h 로는 한 건도 안 잡힌다.",
  },
  분류: {
    제목: "ml-classifier", 부제: "분류 사이드카 · 30초 주기",
    항목: [["주기", "30초 POLL_INTERVAL_SEC"], ["배치", "1,000 BATCH_SIZE"], ["임계", "0.5 CONF_THRESHOLD"],
           ["합의", `${쉼표(합의수)} (${백분(합의수)}%)`], ["이견", `${쉼표(이견수)} (${백분(이견수)}%)`],
           ["저신뢰", `${쉼표(저신뢰)} (${(저신뢰 / 전체 * 100).toFixed(2)}%)`]],
    메모: `규칙이 라벨을 정하고 LightGBM 은 교차검증만 한다. 모델은 라벨을 뒤집지 못하고 ml_label_raw 에 자기 판단만 남긴다. 이견은 ${쉼표(이견수)}건(${(이견수 / 전체 * 100).toFixed(2)}%)뿐이고 ${쉼표(이견Suricata)}건이 Suricata 다. 패턴도 한 방향이다 — 규칙이 Malware(414) · Intrusion(194) 이라 한 것을 모델이 Recon 으로 낮춰 본다. 교차검증의 값어치는 합의율 자체가 아니라 이 ${쉼표(이견수)}건이 검토 큐로 떠오른다는 데 있다.`,
  },
  분기: {
    제목: "ml-analysis-2026.04.27 ~ 05.06", 부제: "분류 결과 인덱스 — 파이프라인의 분기점",
    항목: [...라벨들.map((k) => [k.이름, `${쉼표(k.건수)} · ${k.점수}점 · ${k.기법 === "—" ? "공격 아님" : k.기법}`] as [string, string]),
           ["공격 판정", `${쉼표(공격수)} (${백분(공격수)}%)`]],
    메모: `여기서 길이 갈린다. 전량 ${쉼표(전체)}건은 대시보드 개요·ML 통계로 바로 읽히고, 70점 이상 ${쉼표(고위험)}건만 LLM 으로 넘어간다. 절반 이상(${쉼표(라벨들[색인("Etc")].건수)})이 Etc 인데, 규칙이 공격 유형으로 매핑하지 못한 Suricata 경보들이다 — 실데이터에서 새로 드러난 몫이다.`,
  },
  게이트: {
    제목: "mitre_score ≥ 70", 부제: "llm-analyzer 의 MIN_SCORE — 유일한 필터",
    항목: [["통과", `${쉼표(고위험)} (${백분(고위험)}%)`], ["정지", `${쉼표(탈락수)} (${백분(탈락수)}%)`],
           ["통과 구성", `Malware ${쉼표(라벨들[색인("Malware")].건수)} + Intrusion ${쉼표(라벨들[색인("Intrusion")].건수)}`],
           ["설정", ".env LLM_MIN_SCORE"]],
    메모: `게이트가 ${백분(탈락수)}%를 막는다. 없으면 ${쉼표(전체)}건 전부가 건당 ${건당초}초 추론으로 들어가 약 ${쉼표(게이트없이일)}일이 걸린다. ${쉼표(고위험)}건으로 줄여도 ${소진일}일이다 — 게이트는 최적화가 아니라 이 파이프라인이 성립하기 위한 조건이다.`,
  },
  해설: {
    제목: "llm-analyzer", 부제: "한국어 해설 사이드카 · 60초 주기",
    항목: [["모델", "exaone3.5:7.8b · Ollama · CPU"], ["배치", "10 BATCH_SIZE"],
           ["처리량", `건당 ${건당초}초 → 하루 ${쉼표(LLM일처리)}건`], ["대상", `${쉼표(고위험)}건`],
           ["전량 소진", `${소진일}일`], ["위험도", "점수에서 파생 (LLM 아님)"]],
    메모: `여기가 병목이고 실데이터에서 격차가 분명해졌다. ${수집일수}일간 ${쉼표(고위험)}건의 고위험이 쌓이는 동안 소화할 수 있는 건 ${쉼표(LLM처리)}건 — 수집 속도를 따라가지 못해 ${쉼표(LLM적체)}건이 남는다. 위험도는 맡기지 않는다: 3B 가 고위험 10건 중 10건을 낮게 매겼고 7B 로 올려도 2/10 였다. 모델 크기 문제가 아니라 애초에 맡길 일이 아니었다.`,
  },
  보고: {
    제목: "llm-analysis-*", 부제: "한국어 해설 인덱스",
    항목: [["CRITICAL 대상", `${쉼표(라벨들[색인("Malware")].건수)} · 92점 Malware`],
           ["HIGH 대상", `${쉼표(라벨들[색인("Intrusion")].건수)} · 85점 Intrusion`],
           ["임계", "90점↑ CRITICAL · 70점↑ HIGH"], ["severity_source", "score"],
           ["출력", "summary_ko · solution_ko"]],
    메모: `Malware 92점은 CRITICAL, Intrusion 85점은 HIGH 로 갈린다 — 임계 한 줄이 ${쉼표(고위험)}건을 ${쉼표(라벨들[색인("Malware")].건수)} / ${쉼표(라벨들[색인("Intrusion")].건수)} 로 나눈다. 이 인덱스의 실제 적재량은 스택을 얼마나 돌렸느냐에 달렸다. 도식의 완료 수는 실측 처리량(하루 ${쉼표(LLM일처리)}건)에 수집 기간 ${수집일수}일을 곱한 값이다.`,
  },
  제시: {
    제목: "백엔드 · 대시보드", 부제: "Spring Boot :8091 → Next.js :8002",
    항목: [["/api/overview", "← ml-analysis-*"], ["/api/ml-stats", "← ml-analysis-*"],
           ["/api/llm-recent", "← llm-analysis-*"], ["/api/llm-stats", "← llm-analysis-*"],
           ["집계 창", "THREAT_CONSOLE_WINDOW_SHORT"], ["인증", "JWT"]],
    메모: `대시보드는 두 인덱스를 각각 읽는다. 개요는 전량 ${쉼표(전체)} 기준, LLM 카드만 해설된 건 기준이라 두 숫자가 어긋나 보이는 건 버그가 아니다. 보관 로그는 몇 달 전이라 집계 창을 env 로 빼 두었다 — 기본 24시간으로는 화면이 전부 0 이 된다.`,
  },
};

export default function 파이프라인도식() {
  const svgRef = useRef<SVGSVGElement>(null);
  const 그룹Ref = useRef<SVGGElement>(null);
  const 컨테이너Ref = useRef<HTMLDivElement>(null);

  const [선택, 선택변경] = useState<string>("해설");
  const [재생중, 재생변경] = useState(false);
  const [속도, 속도변경] = useState(1);
  const [끝남, 끝남변경] = useState(false);

  const 재생Ref = useRef(false);
  const 속도Ref = useRef(1);
  useEffect(() => { 재생Ref.current = 재생중; }, [재생중]);
  useEffect(() => { 속도Ref.current = 속도; }, [속도]);

  const 리셋Ref = useRef<() => void>(() => {});

  useEffect(() => {
    const svg = svgRef.current;
    const g = 그룹Ref.current;
    if (!svg || !g) return;
    const 그룹: SVGGElement = g;   // 중첩 함수 안에서 narrowing 이 풀리지 않도록

    const NS = "http://www.w3.org/2000/svg";
    const 경로: Record<string, { el: SVGPathElement; len: number }> = {};
    for (const id of ["s1", "s2", "s3", "s4", "a", "b", "c", "d", "e", "이견드롭", "탈락드롭"]) {
      const el = svg.querySelector<SVGPathElement>(`#p-${id}`);
      if (el) 경로[id] = { el, len: el.getTotalLength() };
    }
    const $ = (id: string) => svg.querySelector<SVGElement>(`#x-${id}`);
    const 칸 = {
      logstash: $("nlog"), 합의: $("n합의"), 이견카드: $("n이견2"), 분기: $("n분기"),
      보고: $("n보고"), 대기: $("n대기"), 이견: $("n이견"), 탈락: $("n탈락"),
      간선완료: $("e완료"), 간선고위험: $("e고위험"), 간선탈락: $("e탈락"),
      큐칸: $("큐칸"),
    };
    const 상태글 = document.getElementById("x-상태글");
    const 막대 = ["etc", "rc", "mw", "bf", "in"].map((k) => svg.querySelector<SVGRectElement>(`#bar-${k}`));
    const 활성키 = ["수집", "분류", "분기", "해설", "보고"];
    const 활성 = 활성키.map((k) => svg.querySelector<SVGRectElement>(`#act-${k}`));

    const 문서들 = 문서목록();
    const 총입자 = 문서들.length;
    const 완료입자 = Math.round(LLM처리 / 축척);
    const 크리입자 = Math.round((라벨들[색인("Malware")].건수 / 고위험) * 완료입자);
    const 추론속도 = 완료입자 / (유입시간 + 8);   // 유입보다 느리게 → 줄이 쌓인다

    let 입자들: 입자[] = [];
    const 풀: SVGCircleElement[] = [];
    const 열기: Record<string, number> = {};
    let S = 초기();

    function 초기() {
      return { t: 0, 발생: 0, 수집: 0, 분류: 0, 분기: 0, 이견: 0, 고위험: 0, 탈락: 0,
               대기: 0, 배출: 0, 완료: 0, 누적: 0, 끝: false,
               라벨수: [0, 0, 0, 0, 0] };
    }
    function 비우기() {
      while (그룹.firstChild) 풀.push(그룹.removeChild(그룹.firstChild) as SVGCircleElement);
      입자들 = [];
    }
    function 리셋() {
      비우기(); S = 초기();
      for (const k of 활성키) 열기[k] = 0;
      끝남변경(false); 그리기();
    }
    리셋Ref.current = 리셋;

    /** 축척 반올림 오차를 실측값으로 맞춘 최종 상태 */
    function 확정() {
      S.끝 = true;
      S.수집 = 전체; S.분류 = 전체; S.분기 = 전체;
      S.이견 = 이견수; S.고위험 = 고위험; S.탈락 = 탈락수;
      S.대기 = LLM적체; S.완료 = LLM처리;
      S.라벨수 = 라벨들.map((k) => k.건수);
    }
    function 마지막상태() {
      비우기(); S = 초기(); S.발생 = 총입자; S.배출 = 완료입자;
      확정();
      for (const k of 활성키) 열기[k] = 0;
      끝남변경(true); 그리기();
    }

    /* ── 입자 ─────────────────────────────────────────────── */
    function 내보내기(경로명: string, 색값: string, 끝콜백: () => void) {
      let c = 풀.pop();
      if (!c) { c = document.createElementNS(NS, "circle") as SVGCircleElement; c.setAttribute("r", "3.1"); }
      c.setAttribute("fill", 색값);
      그룹.appendChild(c);
      입자들.push({ c, 경로: 경로[경로명], t: 0, d: 소요[경로명], 끝: 끝콜백 });
    }
    function 회수(c: SVGCircleElement) {
      그룹.removeChild(c);
      if (풀.length < 500) 풀.push(c);
    }
    const 두드리기 = (k: string) => { 열기[k] = Math.min(1, (열기[k] ?? 0) + 0.09); };

    /* ── 단계 전이 ────────────────────────────────────────── */
    const 이견주사위 = 난수(7411);

    function 단계수집(doc: 문서) {
      내보내기(doc.경로, 색.원본, () => {
        S.수집 += 축척; 두드리기("수집");
        내보내기("a", 색.원본, () => 단계분류(doc));
      });
    }
    function 단계분류(doc: 문서) {
      S.분류 += 축척; 두드리기("분류");
      S.라벨수[라벨들.indexOf(doc.라벨)] += 축척;
      if (이견주사위() < 이견율(doc.라벨)) {
        S.이견 += 축척;
        내보내기("이견드롭", 색.이견, () => {});
      }
      내보내기("b", 색.분류, () => {
        S.분기 += 축척; 두드리기("분기");
        내보내기("c", 색.분류, () => 단계게이트(doc));
      });
    }
    function 단계게이트(doc: 문서) {
      if (doc.라벨.점수 >= 70) {
        S.고위험 += 축척;
        내보내기("d", doc.라벨.등급 === "crit" ? 색.crit : 색.high, () => { S.대기 += 축척; 두드리기("해설"); });
      } else {
        내보내기("탈락드롭", 색.탈락, () => { S.탈락 += 축척; });
      }
    }
    function 단계해설(등급: "crit" | "high") {
      내보내기("e", 등급 === "crit" ? 색.crit : 색.high, () => {
        S.완료 += 축척; 두드리기("보고");
      });
    }

    /* ── 그리기 ───────────────────────────────────────────── */
    const 글 = (el: SVGElement | null, v: string) => { if (el) el.textContent = v; };
    function 그리기() {
      글(칸.logstash, 쉼표(S.수집));
      글(칸.합의, 쉼표(Math.max(0, S.분류 - S.이견)));
      글(칸.이견카드, 쉼표(S.이견));
      글(칸.분기, 쉼표(S.분기));
      글(칸.보고, 쉼표(S.완료));
      글(칸.대기, 쉼표(S.대기));
      글(칸.이견, 쉼표(S.이견));
      글(칸.탈락, 쉼표(S.탈락));
      글(칸.간선완료, 쉼표(S.완료));
      글(칸.간선고위험, 쉼표(S.고위험));
      글(칸.간선탈락, 쉼표(S.탈락));

      const 합 = S.라벨수.reduce((a, b) => a + b, 0) || 1;
      let x = 484;
      for (let i = 0; i < 5; i++) {
        const w = (S.라벨수[i] / 합) * (S.분기 / 전체) * 82;
        막대[i]?.setAttribute("x", x.toFixed(1));
        막대[i]?.setAttribute("width", Math.max(0, w).toFixed(1));
        x += w;
      }

      const h = Math.min(1, S.대기 / LLM적체) * 112;
      칸.큐칸?.setAttribute("y", (302 - h).toFixed(1));
      칸.큐칸?.setAttribute("height", h.toFixed(1));

      for (let i = 0; i < 활성키.length; i++) 활성[i]?.setAttribute("opacity", ((열기[활성키[i]] ?? 0) * 0.9).toFixed(2));

      if (상태글) 상태글.textContent = S.끝
        ? `재생 완료 — 고위험 ${쉼표(고위험)}건 중 ${쉼표(LLM적체)}건 적체 · 전량 소진에 ${소진일}일`
        : `${쉼표(S.수집)} / ${쉼표(전체)}  ·  적체 ${쉼표(S.대기)}`;
    }

    /* ── 루프 ─────────────────────────────────────────────── */
    let raf = 0, 직전 = 0;
    function 프레임(now: number) {
      raf = requestAnimationFrame(프레임);
      const 생dt = 직전 ? Math.min((now - 직전) / 1000, 0.06) : 0;
      직전 = now;
      for (const k of 활성키) 열기[k] = Math.max(0, (열기[k] ?? 0) - 생dt * 2.2);
      if (!재생Ref.current || S.끝) { if (생dt) 그리기(); return; }
      const dt = 생dt * 속도Ref.current;
      S.t += dt;

      const 목표 = Math.min(총입자, Math.floor((S.t / 유입시간) * 총입자));
      while (S.발생 < 목표) { 단계수집(문서들[S.발생]); S.발생++; }

      S.누적 += dt * 추론속도;
      while (S.누적 >= 1 && S.대기 >= 축척 && S.배출 < 완료입자) {
        S.누적 -= 1; S.대기 -= 축척; S.배출++;
        단계해설(S.배출 <= 크리입자 ? "crit" : "high");
      }

      for (let i = 입자들.length - 1; i >= 0; i--) {
        const p = 입자들[i];
        p.t += dt / p.d;
        if (p.t >= 1) { 회수(p.c); 입자들.splice(i, 1); p.끝(); }
        else {
          const e = 1 - Math.pow(1 - p.t, 1.55);   // 도착 직전 감속
          const pt = p.경로.el.getPointAtLength(e * p.경로.len);
          p.c.setAttribute("cx", pt.x.toFixed(1));
          p.c.setAttribute("cy", pt.y.toFixed(1));
        }
      }

      if (S.발생 >= 총입자 && 입자들.length === 0 && S.배출 >= 완료입자) {
        확정();
        끝남변경(true);
      }
      그리기();
    }

    const 움직임끄기 = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (움직임끄기) 마지막상태(); else 리셋();

    let 시작한적 = false;
    const io = new IntersectionObserver((es) => {
      for (const e of es) {
        if (움직임끄기) return;
        if (e.isIntersecting) { if (!시작한적) { 시작한적 = true; 리셋(); } 재생변경(true); }
        else 재생변경(false);
      }
    }, { threshold: 0.25 });
    if (컨테이너Ref.current) io.observe(컨테이너Ref.current);

    raf = requestAnimationFrame(프레임);
    return () => { cancelAnimationFrame(raf); io.disconnect(); };
  }, []);

  const 다시 = useCallback(() => { 리셋Ref.current(); 재생변경(true); }, []);
  const d = 상세[선택];

  const 노드 = (키: string, 자식: ReactNode) => (
    <g
      className={`도식노드${선택 === 키 ? " 선택" : ""}`}
      tabIndex={0} role="button" aria-label={`${상세[키].제목} 상세`}
      onClick={() => 선택변경(키)}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); 선택변경(키); } }}
    >
      {자식}
    </g>
  );

  return (
    <div className="도식" ref={컨테이너Ref}>
      <div className="도식머리">
        <div className="도식제목">
          <h3>100만 건이 흐르는 모양<span className="출처배지">실측</span></h3>
          <p>
            AWS T-Pot 이 2026-04-27 ~ 05-06 에 실제로 받은 공격 로그 {쉼표(전체)}건 ·
            고유 공격 IP {쉼표(고유IP)}개. 입자 하나는 로그 {축척}건이다.
          </p>
        </div>
        <div className="도식조작">
          <button type="button" onClick={() => (끝남 ? 다시() : 재생변경(!재생중))}>
            {끝남 ? "다시 재생" : 재생중 ? "일시정지" : "재생"}
          </button>
          <div className="속도" role="group" aria-label="재생 속도">
            {[0.5, 1, 2].map((v) => (
              <button key={v} type="button" aria-pressed={속도 === v} onClick={() => 속도변경(v)}>{v}×</button>
            ))}
          </div>
        </div>
      </div>

      <div className="도식판">
        <svg ref={svgRef} className="도식svg" viewBox="0 0 1180 468" role="img"
          aria-label={`수집 지점 ${지점수}종이 ${수집일수}일간 받은 공격 로그 ${쉼표(전체)}건이 logstash 인덱스와 ml-classifier 를 지나 ml-analysis 인덱스에 쌓이고, mitre_score 70점 게이트에서 ${쉼표(고위험)}건만 llm-analyzer 로 넘어가는 흐름도. 게이트에서 ${쉼표(탈락수)}건이 정지하고, 분류 단계에서 ${쉼표(이견수)}건이 검토 큐로 표시된다. LLM 은 하루 ${쉼표(LLM일처리)}건만 처리할 수 있어 ${쉼표(LLM적체)}건이 적체된다.`}>
          <defs>
            <marker id="화살" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <polygon points="0,1 8,4 0,7" fill="#c9d2dc" />
            </marker>
            <marker id="화살읽기" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <polygon points="0,1 8,4 0,7" fill="#0f6b78" />
            </marker>
          </defs>

          {/* ── 쓰기 배선 ── */}
          <path id="p-s1" className="선" d="M116,177 C142,177 138,246 160,246" markerEnd="url(#화살)" />
          <path id="p-s2" className="선" d="M116,223 C142,223 140,246 160,246" markerEnd="url(#화살)" />
          <path id="p-s3" className="선" d="M116,269 C142,269 140,246 160,246" markerEnd="url(#화살)" />
          <path id="p-s4" className="선" d="M116,315 C142,315 138,246 160,246" markerEnd="url(#화살)" />
          <path id="p-a" className="선" d="M262,246 L306,246" markerEnd="url(#화살)" />
          <path id="p-b" className="선" d="M430,246 L474,246" markerEnd="url(#화살)" />
          <path id="p-c" className="선" d="M576,246 L620,246" markerEnd="url(#화살)" />
          <path id="p-d" className="선" d="M668,246 L712,246" markerEnd="url(#화살)" />
          <path id="p-e" className="선" d="M836,246 L880,246" markerEnd="url(#화살)" />
          <path id="p-이견드롭" className="선점" d="M368,302 L368,370" />
          <path id="p-탈락드롭" className="선점" d="M644,276 L644,370" />

          {/* ── 읽기 배선 ── */}
          <path className="선읽기" d="M525,211 L525,120 Q525,108 537,108 L1076,108 Q1088,108 1088,120 L1088,190" markerEnd="url(#화살읽기)" />
          <path className="선읽기" d="M982,246 L1026,246" markerEnd="url(#화살읽기)" />
          <text className="간선 강조" x="806" y="99" textAnchor="middle">{`전량 ${쉼표(전체)} 집계 — /api/overview · /api/ml-stats`}</text>

          {/* ── 간선 수량 ── */}
          <text className="간선" x="284" y="238" textAnchor="middle">{쉼표(전체)}</text>
          <text className="간선" x="452" y="238" textAnchor="middle">{쉼표(전체)}</text>
          <text className="간선" x="598" y="238" textAnchor="middle">{쉼표(전체)}</text>
          <text className="간선 고위험" id="x-e고위험" x="690" y="238" textAnchor="middle">{쉼표(고위험)}</text>
          <text className="간선 강조" id="x-e완료" x="858" y="238" textAnchor="middle">{쉼표(LLM처리)}</text>
          <text className="간선 이견" x="376" y="334" textAnchor="start">{쉼표(이견수)}</text>
          <text className="간선" id="x-e탈락" x="652" y="334" textAnchor="start">{쉼표(탈락수)}</text>

          {/* ── 01 수집 ── */}
          {노드("수집", <>
            <text className="단번호" x="12" y="152">01 수집</text>
            {출처들.map((s, i) => (
              <g key={s.이름}>
                <rect className="칩" x="12" y={163 + i * 46} width="104" height="28" rx="3" />
                <text className="출처" x="21" y={181 + i * 46}>{s.이름}</text>
                <text className="출처수" x="107" y={181 + i * 46} textAnchor="end">{쉼표(s.합계)}</text>
              </g>
            ))}
            <rect id="act-수집" className="활성" x="12" y="331" width="104" height="2" opacity="0" />
            <rect className="타격" x="12" y="152" width="104" height="181" />
          </>)}

          {/* ── logstash-* ── */}
          {노드("logstash", <>
            <rect className="칩 큰칩" x="160" y="211" width="102" height="70" rx="3" />
            <text className="이름" x="211" y="231" textAnchor="middle">logstash-*</text>
            <text className="수" id="x-nlog" x="211" y="253" textAnchor="middle">0</text>
            <text className="잔글" x="211" y="270" textAnchor="middle">10일 · 인덱스 10개</text>
            <rect className="타격" x="160" y="211" width="102" height="70" />
          </>)}

          {/* ── 02 분류 ── */}
          {노드("분류", <>
            <text className="단번호" x="306" y="182">02 분류</text>
            <rect className="판" x="306" y="190" width="124" height="112" rx="4" />
            <text className="이름" x="368" y="211" textAnchor="middle">ml-classifier</text>
            <text className="잔글" x="368" y="226" textAnchor="middle">규칙이 라벨, 모델은 검증</text>
            <text className="설정" x="368" y="241" textAnchor="middle">30초 · 1,000건</text>
            <rect x="318" y="251" width="100" height="7" rx="1.5" fill="#9a5f0c" />
            {/* 폭 100 이 전체. 합의 비율만큼 채운다 — 숫자를 손으로 적으면
                수치가 바뀔 때 막대만 옛 비율로 남는다(87.6 이 그랬다). */}
            <rect x="318" y="251" width={(합의수 / 전체 * 100).toFixed(1)} height="7" rx="1.5" fill="#0f6b78" />
            <text className="설정" x="318" y="273">합의 <tspan id="x-n합의">0</tspan></text>
            <text className="설정 이견" x="418" y="273" textAnchor="end">이견 <tspan id="x-n이견2">0</tspan></text>
            <text className="잔글" x="368" y="290" textAnchor="middle">{백분(합의수)}% / {(이견수 / 전체 * 100).toFixed(2)}%</text>
            <rect id="act-분류" className="활성" x="306" y="300" width="124" height="2" opacity="0" />
            <rect className="타격" x="306" y="182" width="124" height="120" />
          </>)}

          {/* ── ml-analysis-* ── */}
          {노드("분기", <>
            <rect className="칩 큰칩" x="474" y="211" width="102" height="70" rx="3" />
            <text className="이름" x="525" y="231" textAnchor="middle">ml-analysis-*</text>
            <text className="수" id="x-n분기" x="525" y="252" textAnchor="middle">0</text>
            <rect x="484" y="260" width="82" height="6" rx="1" fill="#eef1f5" />
            <rect id="bar-etc" x="484" y="260" width="0" height="6" fill="#c9d2dc" />
            <rect id="bar-rc"  x="484" y="260" width="0" height="6" fill="#94a3b8" />
            <rect id="bar-mw"  x="484" y="260" width="0" height="6" fill="#5f1d33" />
            <rect id="bar-bf"  x="484" y="260" width="0" height="6" fill="#0f6b78" />
            <rect id="bar-in"  x="484" y="260" width="0" height="6" fill="#9e3a31" />
            <text className="잔글" x="525" y="277" textAnchor="middle">라벨 5종 · 분기점</text>
            <rect id="act-분기" className="활성" x="474" y="279" width="102" height="2" opacity="0" />
            <rect className="타격" x="474" y="211" width="102" height="70" />
          </>)}

          {/* ── 게이트 ── */}
          {노드("게이트", <>
            <text className="설정" x="644" y="199" textAnchor="middle">mitre_score</text>
            <text className="간선 고위험" x="644" y="211" textAnchor="middle">≥ 70</text>
            <polygon className="깔때기" points="620,224 668,241 668,259 620,268" />
            <rect className="타격" x="612" y="190" width="64" height="92" />
          </>)}

          {/* ── 03 해설 ── */}
          {노드("해설", <>
            <text className="단번호" x="712" y="182">03 해설</text>
            <rect className="큐바탕" x="698" y="190" width="8" height="112" rx="2" />
            <rect id="x-큐칸" className="큐참" x="698" y="302" width="8" height="0" rx="2" />
            <rect className="판" x="712" y="190" width="124" height="112" rx="4" />
            <text className="이름" x="774" y="211" textAnchor="middle">llm-analyzer</text>
            <text className="설정" x="774" y="225" textAnchor="middle">exaone3.5:7.8b</text>
            <text className="설정" x="774" y="238" textAnchor="middle">Ollama · CPU · 직렬</text>
            <text className="잔글 고위험" x="774" y="253" textAnchor="middle">하루 {쉼표(LLM일처리)}건이 한계</text>
            <text className="잔글" x="774" y="272" textAnchor="middle">적체</text>
            <text className="수 위험" id="x-n대기" x="774" y="291" textAnchor="middle">0</text>
            <rect id="act-해설" className="활성" x="712" y="300" width="124" height="2" opacity="0" />
            <rect className="타격" x="698" y="182" width="138" height="120" />
          </>)}

          {/* ── llm-analysis-* ── */}
          {노드("보고", <>
            <rect className="칩 큰칩" x="880" y="211" width="102" height="70" rx="3" />
            <text className="이름" x="931" y="231" textAnchor="middle">llm-analysis-*</text>
            <text className="수" id="x-n보고" x="931" y="253" textAnchor="middle">0</text>
            <text className="잔글" x="931" y="270" textAnchor="middle">10일간 처리 가능량</text>
            <rect id="act-보고" className="활성" x="880" y="279" width="102" height="2" opacity="0" />
            <rect className="타격" x="880" y="211" width="102" height="70" />
          </>)}

          {/* ── 04 제시 ── */}
          {노드("제시", <>
            <text className="단번호" x="1026" y="182">04 제시</text>
            <rect className="판" x="1026" y="190" width="124" height="112" rx="4" />
            <text className="이름" x="1088" y="213" textAnchor="middle">대시보드</text>
            <text className="설정" x="1088" y="229" textAnchor="middle">Spring :8091</text>
            <text className="설정" x="1088" y="242" textAnchor="middle">Next.js :8002</text>
            <line x1="1040" y1="253" x2="1136" y2="253" stroke="#dde3ea" strokeWidth="1" />
            <text className="잔글" x="1088" y="269" textAnchor="middle">개요는 전량 기준</text>
            <text className="잔글" x="1088" y="284" textAnchor="middle">LLM 카드만 해설분 기준</text>
            <rect className="타격" x="1026" y="182" width="124" height="120" />
          </>)}

          {/* ── 수집함 ── */}
          <rect className="함" x="316" y="370" width="104" height="54" rx="3" />
          <text className="함이름 이견" x="368" y="388" textAnchor="middle">검토 큐</text>
          <text className="수 이견" id="x-n이견" x="368" y="407" textAnchor="middle">0</text>
          <text className="잔글" x="368" y="419" textAnchor="middle">ml_dissent — 라벨은 유지</text>

          <rect className="함" x="592" y="370" width="104" height="54" rx="3" />
          <text className="함이름" x="644" y="388" textAnchor="middle">게이트 정지</text>
          <text className="수" id="x-n탈락" x="644" y="407" textAnchor="middle">0</text>
          <text className="잔글" x="644" y="419" textAnchor="middle">Etc · Recon · Brute Force</text>

          <text className="잔글" x="368" y="442" textAnchor="middle">{쉼표(이견수)}건 — 대부분 Suricata, 모델이 한 단계 낮춰 봤다</text>
          <text className="잔글" x="644" y="442" textAnchor="middle">전체의 95.6% · 게이트 없으면 LLM 에 {쉼표(게이트없이일)}일치가 들어간다</text>

          <g ref={그룹Ref} />
        </svg>
      </div>

      <div className="도식범례">
        <span className="범"><svg width="30" height="9"><line x1="0" y1="4.5" x2="30" y2="4.5" stroke="#c9d2dc" strokeWidth="1.6" /><circle cx="15" cy="4.5" r="3.1" fill="#0f6b78" /></svg>쓰기 — 문서가 실제로 이동</span>
        <span className="범"><svg width="30" height="9"><line x1="0" y1="4.5" x2="30" y2="4.5" stroke="#0f6b78" strokeWidth="1.4" strokeDasharray="5 6" /></svg>읽기 — 대시보드가 조회</span>
        <span className="범"><i style={{ background: 색.이견 }} />모델 이견</span>
        <span className="범"><i style={{ background: 색.high }} />HIGH · 85점</span>
        <span className="범"><i style={{ background: 색.crit }} />CRITICAL · 92점</span>
        <span className="상태" id="x-상태글">{쉼표(전체)}건 리플레이</span>
      </div>

      <p className="도식출처">
        AWS EC2 에 띄운 T-Pot 이 <b>2026-04-27 ~ 05-06 (10일)</b> 동안 받은 실제 공격 로그다.
        2026-09-14 에 logstash 로 색인해 파이프라인을 완주시킨 뒤 집계했다 — 고유 공격 IP {쉼표(고유IP)}개,
        출발지 상위는 미국·브라질·영국·중국 순. 다만 <b>LLM 완료 수는 측정값이 아니라 처리량 추정</b>이다
        (실측 하루 {쉼표(LLM일처리)}건 × 10일). 실제 <code>llm-analysis-*</code> 적재량은 스택을 얼마나 돌렸는지에
        달렸고, 대시보드의 값이 실측이다.
      </p>

      <div className="도식상세">
        <div>
          <h4>{d.제목}</h4>
          <p className="상세부제">{d.부제}</p>
          <dl className="상세표">
            {d.항목.map(([k, v]) => (<div key={k}><dt>{k}</dt><dd>{v}</dd></div>))}
          </dl>
        </div>
        <p className="상세메모">{d.메모}</p>
      </div>

      <style>{`
        .도식 { margin: 26px 0 4px; }

        .도식머리 { display: flex; align-items: flex-end; gap: 20px; flex-wrap: wrap; margin-bottom: 14px; }
        .도식제목 h3 { font-size: 1.06rem; font-weight: 700; letter-spacing: -0.01em; display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
        .출처배지 {
          font-family: var(--mono); font-size: 0.63rem; font-weight: 600; letter-spacing: 0.02em;
          color: var(--accent); background: var(--accent-soft); border: 1px solid var(--accent-border);
          border-radius: 20px; padding: 2px 9px;
        }
        .도식제목 p { font-size: 0.82rem; color: var(--text-3); margin-top: 3px; max-width: 74ch; }
        .도식조작 { display: flex; gap: 8px; margin-left: auto; }
        .도식조작 > button {
          font-size: 0.78rem; font-weight: 600; color: var(--text-2);
          background: var(--surface); border: 1px solid var(--border-strong);
          border-radius: var(--radius-sm); padding: 6px 14px; cursor: pointer; transition: all 0.16s;
        }
        .도식조작 > button:hover { border-color: var(--accent); color: var(--accent); background: var(--accent-soft); }
        .속도 { display: flex; border: 1px solid var(--border-strong); border-radius: var(--radius-sm); overflow: hidden; background: var(--surface); }
        .속도 button {
          border: 0; border-left: 1px solid var(--border); background: transparent; cursor: pointer;
          font-family: var(--mono); font-size: 0.74rem; font-weight: 500; color: var(--text-2); padding: 6px 11px;
        }
        .속도 button:first-child { border-left: 0; }
        .속도 button[aria-pressed="true"] { background: var(--accent); color: #fff; }

        .도식판 {
          overflow-x: auto; background: var(--surface); border: 1px solid var(--border);
          border-radius: var(--radius); box-shadow: var(--shadow-sm); padding: 8px 12px 4px;
        }
        .도식svg { display: block; width: 100%; min-width: 1000px; height: auto; }

        .도식svg .단번호 { font-family: var(--mono); font-size: 9.5px; font-weight: 600; fill: var(--accent); letter-spacing: 0.06em; }
        .도식svg .이름 { font-family: var(--mono); font-size: 11.5px; font-weight: 600; fill: var(--text); }
        .도식svg .수 { font-family: var(--mono); font-size: 13px; font-weight: 600; fill: var(--text); font-variant-numeric: tabular-nums; }
        .도식svg .설정 { font-family: var(--mono); font-size: 9px; fill: var(--text-2); }
        .도식svg .잔글 { font-size: 9px; fill: var(--text-3); }
        .도식svg .간선 { font-family: var(--mono); font-size: 9.5px; font-weight: 500; fill: var(--text-3); font-variant-numeric: tabular-nums; }
        .도식svg .출처 { font-size: 10px; font-weight: 500; fill: var(--text-2); }
        .도식svg .출처수 { font-family: var(--mono); font-size: 9.5px; font-weight: 500; fill: var(--text-3); font-variant-numeric: tabular-nums; }
        .도식svg .함이름 { font-size: 10px; font-weight: 600; fill: var(--text-2); }
        .도식svg .강조 { fill: var(--accent); }
        .도식svg .고위험 { fill: ${색.high}; }
        .도식svg .위험 { fill: ${색.crit}; }
        .도식svg .이견 { fill: ${색.이견}; }

        .도식svg .판 { fill: var(--surface); stroke: var(--border-strong); stroke-width: 1; }
        .도식svg .칩 { fill: var(--surface-2); stroke: var(--border); stroke-width: 1; }
        .도식svg .큰칩 { fill: var(--surface); }
        .도식svg .함 { fill: none; stroke: var(--border-strong); stroke-width: 1; stroke-dasharray: 3 3; }
        .도식svg .선 { fill: none; stroke: var(--border-strong); stroke-width: 1.4; stroke-linecap: round; }
        .도식svg .선점 { fill: none; stroke: var(--border-strong); stroke-width: 1; stroke-dasharray: 2 4; }
        .도식svg .선읽기 { fill: none; stroke: var(--accent); stroke-width: 1.3; stroke-dasharray: 5 6; opacity: 0.8; animation: 흐름 1.5s linear infinite; }
        @keyframes 흐름 { to { stroke-dashoffset: -11; } }
        .도식svg .깔때기 { fill: var(--amber-soft); stroke: ${색.high}; stroke-width: 1.3; }
        .도식svg .큐바탕 { fill: var(--surface-3); stroke: var(--border); stroke-width: 0.8; }
        .도식svg .큐참 { fill: ${색.high}; }
        .도식svg .활성 { fill: var(--accent); }
        .도식svg .타격 { fill: transparent; }

        .도식노드 { cursor: pointer; }
        .도식노드:hover .판, .도식노드:hover .칩 { stroke: var(--accent); stroke-width: 1.6; }
        .도식노드.선택 .판, .도식노드.선택 .칩 { stroke: var(--accent); stroke-width: 2; }
        .도식노드:focus { outline: none; }
        .도식노드:focus-visible .판, .도식노드:focus-visible .칩 { stroke: var(--accent); stroke-width: 2; }

        .도식범례 { display: flex; gap: 20px; flex-wrap: wrap; align-items: center; font-size: 0.76rem; color: var(--text-2); margin-top: 11px; }
        .범 { display: flex; align-items: center; gap: 7px; }
        .범 svg { flex: none; display: block; }
        .범 i { width: 9px; height: 9px; border-radius: 50%; flex: none; }
        .도식범례 .상태 { margin-left: auto; font-family: var(--mono); font-size: 0.72rem; color: var(--text-3); font-variant-numeric: tabular-nums; }

        .도식출처 {
          margin-top: 11px; font-size: 0.78rem; line-height: 1.7; color: var(--text-2);
          background: var(--surface-2); border: 1px solid var(--border);
          border-left: 2px solid var(--accent);
          border-radius: var(--radius-sm); padding: 10px 14px;
        }
        .도식출처 b { color: var(--text); font-weight: 600; }
        .도식출처 code { font-family: var(--mono); font-size: 0.92em; color: var(--accent); }

        .도식상세 {
          margin-top: 14px; background: var(--surface-2); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 18px 20px;
          display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1.1fr); gap: 24px;
        }
        .도식상세 h4 { font-family: var(--mono); font-size: 0.92rem; font-weight: 600; letter-spacing: -0.01em; word-break: break-all; }
        .상세부제 { font-size: 0.76rem; color: var(--text-3); margin: 2px 0 13px; }
        .상세표 { display: flex; flex-direction: column; gap: 4px; font-size: 0.78rem; }
        .상세표 > div { display: grid; grid-template-columns: minmax(84px, auto) 1fr; gap: 14px; }
        .상세표 dt { color: var(--text-3); }
        .상세표 dd { font-family: var(--mono); color: var(--text-2); font-variant-numeric: tabular-nums; word-break: break-word; }
        .상세메모 { font-size: 0.84rem; line-height: 1.75; color: var(--text-2); border-left: 2px solid var(--accent); padding-left: 15px; }

        @media (max-width: 860px) {
          .도식상세 { grid-template-columns: 1fr; gap: 18px; }
          .도식조작 { margin-left: 0; }
        }
        @media (prefers-reduced-motion: reduce) {
          .도식svg .선읽기 { animation: none; }
        }
      `}</style>
    </div>
  );
}
