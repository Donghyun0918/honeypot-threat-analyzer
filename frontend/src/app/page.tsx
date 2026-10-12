// 랜딩 — 프로젝트 소개.
// 제품 판매 페이지가 아니라 "무엇을 왜 만들었고 무엇이 검증됐는가"를 보여주는 면이다.
// 수치는 2026-09-14 집계 기준이다. AWS T-Pot 이 2026-04-27~05-06 에 실제로
// 받은 공격 로그 1,026,903건을 색인하고 파이프라인을 완주시킨 결과. 실시간
// 값은 대시보드에 있다.
//
// 모양은 소개 사이트(honeypot-intro)를 따른다 — 커튼, 히어로 배경, 흐르는 띠,
// 번호 머리표, 스크롤 등장. 문구와 수치는 이 저장소의 실측을 그대로 둔다.

import Link from "next/link";
import 파이프라인도식 from "@/components/파이프라인도식";
import IntroCurtain from "@/components/intro/IntroCurtain";
import ScrollHud from "@/components/intro/ScrollHud";
import RevealObserver from "@/components/intro/RevealObserver";
import HeroBackdrop from "@/components/intro/HeroBackdrop";
import Marquee from "@/components/intro/Marquee";
import ParallaxWord from "@/components/intro/ParallaxWord";
import Nav from "@/components/intro/Nav";

const P = ["var(--p0)", "var(--p1)", "var(--p2)", "var(--p3)"];
const hue = (i: number) => P[i % P.length];

/* 파이프라인 각 단이 무엇을 받아 무엇을 내는지. 랜딩의 본론. */
const 단계 = [
  {
    n: "001",
    이름: "수집",
    주체: "T-Pot · 허니팟 25종",
    설명: "일부러 취약하게 열어둔 미끼 시스템이 공격을 그대로 기록한다. 실제 서비스가 아니므로 들어오는 접속은 정의상 전부 비정상이다.",
    출력: "logstash-*",
  },
  {
    n: "002",
    이름: "분류",
    주체: "ml-classifier",
    설명: "허니팟 종류와 이벤트 내용으로 공격 유형을 판정하고 MITRE ATT&CK 위협 점수를 매긴다. 30초 주기로 새 이벤트만 처리한다.",
    출력: "ml-analysis-*",
  },
  {
    n: "003",
    이름: "해설",
    주체: "llm-analyzer",
    설명: "위협 점수 70점 이상인 건만 골라 한국어 요약과 대응 방안을 만든다. LLM 호출은 비싸므로 볼 가치가 있는 것만 통과시킨다.",
    출력: "llm-analysis-*",
  },
  {
    n: "004",
    이름: "제시",
    주체: "대시보드 · 어택맵",
    설명: "분류 결과와 해설을 한국어 화면으로 올린다. 출발지에서 센서로 향하는 공격을 지도 위에 실시간으로 그린다.",
    출력: "브라우저",
  },
];

/* 만들면서 실제로 측정한 것들. 홍보 문구 대신 숫자를 둔다.
   라이브 값이 아니라 2026-09-14 집계 기준이다 — 소개 면이 스택 가동 여부에
   따라 0 으로 보이면 안 된다. 실시간은 대시보드에 있다.

   출처: AWS T-Pot 이 2026-04-27~05-06(10일) 동안 받은 실제 공격 로그를
   `ml-analysis-*` 에서 **그 창으로 한정해** 집계한 값이다. 인덱스 전체를 세면
   09-09 시연 표본과 라이브 트래픽이 섞여 수치가 매일 움직인다 — 같은 값을
   파이프라인도식도 쓰므로 고칠 땐 두 곳을 함께 본다.

   합의율은 2026-09-15 에 교차검증 모델을 v4 → v5(실 ES 문서 학습)로 교체하고
   전량 재분류한 뒤의 값이다. v4 때는 87.6%(이견 126,756건)였고 그 대부분이
   모델 쪽 오답이었다 — DATASET_FINDINGS.md §6. */
const 검증 = [
  { 값: "1,026,903", 단위: "건", 라벨: "EVENTS", 이름: "수집 이벤트", 설명: "10일 · 수집 지점 18종" },
  { 값: "24,346", 단위: "개", 라벨: "UNIQUE IPS", 이름: "고유 공격 IP", 설명: "미국·브라질·영국 순" },
  { 값: "45,075", 단위: "건", 라벨: "HIGH RISK", 이름: "고위험 선별", 설명: "전체의 4.4%" },
  { 값: "99.9", 단위: "%", 라벨: "AGREEMENT", 이름: "규칙·모델 합의", 설명: "이견 782건 · 검토 대상" },
];

const 발견 = [
  {
    질문: "한국어 해설은 쓸 만한가",
    답: <>고위험 60건 전부 성공, 폴백 0건. 다만 모델이 한국어에 한자를 섞는 일이 있어 <b>출력을 검사해 재시도</b>하도록 했다.</>,
    경고: false,
  },
  {
    질문: "학습 모델을 켤 수 있는가",
    답: <>아직 아니다. 규칙 대비 일치율이 <b>61.4%</b> 에 그친다. 학습 정답을 규칙에서 뽑았으니 모델의 천장이 규칙 재현이고, 켜면 오히려 품질이 떨어진다.</>,
    경고: true,
  },
  {
    질문: "LLM 이 위험도를 정할 수 있는가",
    답: <>못 한다. 고위험 문서 10건에서 <b>10건 모두</b> 실제보다 낮게 매겼고, 판정 예시를 넣어도 그대로였다. 그래서 위험도는 점수에서 계산하고 모델에게는 문장만 맡긴다.</>,
    경고: true,
  },
  {
    질문: "데이터 문제는 어디였나",
    답: <>내보낸 로그에서 포트는 접속 행에, 명령은 다른 행에 흩어져 있었다. 세션 단위로 합치자 일치율이 <b>35.4% → 61.4%</b> 로 올랐다.</>,
    경고: false,
  },
];

const 스택 = [
  ["T-Pot 24.04.1", "허니팟 25종 통합 배포판"],
  ["Elasticsearch", "로그 저장·집계"],
  ["Logstash", "정규화 · geoip"],
  ["LightGBM", "다중분류 모델"],
  ["MITRE ATT&CK", "위협 점수 체계"],
  ["Ollama", "로컬 LLM 추론"],
  ["Spring Boot", "인증 · 권한"],
  ["Next.js 15", "한국어 대시보드"],
  ["PostgreSQL", "사용자 · 로그 영속"],
  ["Docker Compose", "컨테이너 10개"],
];

function Kicker({ no, label, suffix }: { no: string; label: string; suffix?: string }) {
  return (
    <div data-reveal className="ix-kicker">
      <span className="no">{no}</span>
      <span>{label}</span>
      <span data-rule className="rule" />
      {suffix && <span>{suffix}</span>}
    </div>
  );
}

function Watermark({ no }: { no: string }) {
  return <span className="lp-워터마크" aria-hidden="true">{no}</span>;
}

export default function 랜딩() {
  return (
    <>
      <style>{`
        .lp { --gutter: clamp(16px, 3vw, 40px); position: relative; overflow-x: hidden; background: var(--bg); font-family: var(--display); }
        .lp p, .lp .본문 { font-family: var(--font); }

        /* ── 상단 내비 ── */
        .ix-nav {
          position: fixed; left: 0; right: 0; top: 0; z-index: 80;
          display: flex; align-items: center; justify-content: space-between; gap: 16px;
          padding: 16px clamp(16px, 3vw, 40px);
          background: linear-gradient(to bottom, rgba(6,6,7,0.92), rgba(6,6,7,0));
        }
        .ix-nav-logo { display: flex; align-items: center; gap: 10px; font-family: var(--display); font-size: 17px; font-weight: 700; letter-spacing: -0.02em; }
        .ix-nav-links { display: flex; flex-wrap: wrap; justify-content: flex-end; align-items: center; gap: 10px; }
        @media (max-width: 640px) { .ix-nav-links .pill-nav:not(.주) { display: none; } }

        /* ── 히어로 ── */
        .lp-hero { position: relative; overflow: hidden; padding: clamp(96px, 16vh, 168px) var(--gutter) clamp(52px, 8vh, 96px); }
        .lp-hero > *:not(:first-child) { position: relative; z-index: 1; }
        .lp-hero-top { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 20px; font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.2em; color: rgba(244,244,241,0.42); }
        .lp-hero-name {
          display: inline-flex; align-items: center; gap: 12px; font-family: var(--font); font-weight: 700; color: #fff;
          font-size: clamp(17px, 1.9vw, 24px); letter-spacing: -0.015em;
          text-shadow: 0 2px 18px rgba(6,6,7,0.95), 0 0 6px rgba(6,6,7,0.9);
        }
        .lp-hero-name i { display: block; width: 10px; height: 10px; border-radius: 50%; background: var(--accent); }
        .lp-hero-chip { border-radius: 999px; border: 1px solid rgba(244,244,241,0.2); background: var(--bg); padding: 6px 14px; font-weight: 500; color: var(--text); }

        .lp-hero h1 { margin-top: 24px; display: grid; font-weight: 700; line-height: 1; letter-spacing: -0.045em; font-size: clamp(40px, 8.4vw, 132px); }
        .lp-줄 { display: block; overflow: hidden; padding-bottom: 0.04em; }
        /* 한글 글리프는 라틴보다 위아래로 길어 1.06em 칸이면 다음 단어 머리가 비친다.
           칸을 1.2em 으로 키우고 굴리는 보폭도 같이 맞춘다. */
        @keyframes k-roll-kr {
          0%, 20% { transform: translateY(0); }
          27%, 47% { transform: translateY(-1.2em); }
          54%, 74% { transform: translateY(-2.4em); }
          81%, 100% { transform: translateY(-3.6em); }
        }
        .lp-외곽 { color: transparent; -webkit-text-stroke: 1.4px rgba(244,244,241,0.55); line-height: 1.2; }
        .lp-돌림 { display: block; height: 1.2em; line-height: 1.2; overflow: hidden; color: var(--accent); }
        .lp-돌림 > span { display: block; animation: k-roll-kr 9s 2.9s cubic-bezier(.76,0,.24,1) infinite; }
        .lp-돌림 > span > span { display: block; height: 1.2em; }

        .lp-태그줄 { margin-top: 18px; display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }
        .lp-스티커 { display: inline-block; rotate: -4deg; border-radius: 999px; background: var(--accent); color: var(--on-accent); padding: 8px 16px; font-family: var(--mono); font-size: 10.5px; font-weight: 500; letter-spacing: 0.16em; }
        .lp-태그줄 > span:last-child { font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.2em; color: rgba(244,244,241,0.38); }

        .lp-요약 { margin-top: clamp(24px, 4vh, 44px); max-width: 50ch; line-height: 1.85; color: rgba(244,244,241,0.66); font-size: clamp(14px, 1.2vw, 17px); }
        .lp-요약 b { color: var(--text); font-weight: 600; }
        .lp-요약 code { color: var(--accent); }

        .lp-cta { margin-top: clamp(28px, 4vh, 40px); display: flex; flex-wrap: wrap; gap: 10px; font-family: var(--mono); font-size: 12px; }
        .lp-cta a { border-radius: 999px; padding: 16px 24px; font-weight: 600; transition: all .3s var(--ease); }
        .lp-cta a:hover { transform: translateY(-3px); }
        .lp-cta .주 { background: var(--accent); color: var(--on-accent); font-weight: 700; }
        .lp-cta .부 { border: 1px solid rgba(244,244,241,0.18); color: rgba(244,244,241,0.88); }
        .lp-cta .부:hover { background: rgba(244,244,241,0.08); }

        .lp-지표 { margin-top: clamp(36px, 7vh, 64px); display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
        .lp-지표칸 { display: grid; gap: 8px; border-radius: 20px; border: 1px solid rgba(244,244,241,0.10); background: var(--surface); padding: 22px; }
        .lp-지표칸 .라벨 { font-family: var(--mono); font-size: 10px; letter-spacing: 0.18em; color: rgba(244,244,241,0.40); }
        .lp-지표칸 .값 { font-weight: 700; letter-spacing: -0.03em; font-size: clamp(26px, 2.6vw, 36px); font-variant-numeric: tabular-nums; line-height: 1.1; }
        .lp-지표칸 .값 em { font-style: normal; font-size: 0.42em; font-weight: 500; color: rgba(244,244,241,0.5); margin-left: 4px; letter-spacing: 0; }
        .lp-지표칸 .설명 { font-family: var(--font); font-size: 12px; line-height: 1.6; color: rgba(244,244,241,0.5); }
        .lp-지표주 { margin-top: 12px; font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.12em; color: rgba(244,244,241,0.34); text-align: right; }

        /* ── 공통 섹션 ── */
        .lp-sec { padding: clamp(72px, 12vh, 140px) var(--gutter); }
        .lp-sec.면 { background: var(--bg-2); border-top: 1px solid rgba(244,244,241,0.08); border-bottom: 1px solid rgba(244,244,241,0.08); padding: clamp(60px, 10vh, 120px) var(--gutter); }
        .lp-눈썹 { display: block; margin-bottom: 14px; font-family: var(--mono); font-size: 11px; letter-spacing: 0.2em; color: var(--accent); }
        .lp-sec h2 { font-weight: 700; line-height: 1.05; letter-spacing: -0.04em; font-size: clamp(28px, 4.2vw, 60px); }
        .lp-sec h2 .강조 { color: var(--accent); }
        .lp-도입 { margin-top: 24px; max-width: 46ch; font-size: 14.5px; line-height: 1.9; color: rgba(244,244,241,0.6); }
        .lp-도입 b { color: var(--text); font-weight: 600; }
        .lp-머리줄 { margin-top: clamp(24px, 5vh, 48px); display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between; gap: 24px; }
        .lp-워터마크 {
          display: block; font-weight: 700; line-height: 0.8; letter-spacing: -0.05em; color: transparent;
          font-size: clamp(56px, 10vw, 150px); -webkit-text-stroke: 1.4px rgba(244,244,241,0.18);
        }
        @media (max-width: 640px) { .lp-워터마크 { display: none; } }

        /* ── 001 문제 ── */
        .lp-문제 { margin-top: clamp(24px, 5vh, 48px); display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: clamp(28px, 5vw, 80px); }
        .lp-대비 { display: grid; gap: 10px; align-content: start; }
        .lp-대비칸 { display: grid; grid-template-columns: 62px 1fr; gap: 16px; border-radius: 22px; border: 1px solid rgba(244,244,241,0.10); background: var(--surface); padding: clamp(24px, 2.4vw, 30px); }
        .lp-대비칸 .번호 { font-family: var(--mono); font-size: 12px; letter-spacing: 0.16em; color: var(--accent); }
        .lp-대비칸.미해결 .번호 { color: var(--amber); }
        .lp-대비칸 h3 { font-family: var(--font); font-weight: 600; line-height: 1.45; font-size: clamp(16px, 1.6vw, 20px); }
        .lp-대비칸 p { margin-top: 10px; font-size: 13px; line-height: 1.8; color: rgba(244,244,241,0.54); }
        .lp-코드 {
          margin-top: 16px; font-family: var(--mono); font-size: 12px; line-height: 1.75; color: rgba(244,244,241,0.7);
          background: var(--bg); border: 1px solid rgba(244,244,241,0.10); border-radius: 14px;
          padding: 14px 16px; overflow-x: auto; white-space: pre;
        }
        .lp-코드 .키 { color: var(--p1); }
        .lp-코드 .값 { color: var(--p3); }

        /* ── 002 파이프라인 ── */
        .lp-타임라인 { position: relative; margin-top: clamp(32px, 7vh, 64px); max-width: 1080px; padding-left: clamp(22px, 3.4vw, 48px); }
        .lp-타임라인::before { content: ''; position: absolute; top: 14px; bottom: 14px; left: 0; width: 1px; background: rgba(244,244,241,0.14); }
        .lp-단들 { display: grid; gap: 10px; }
        .lp-단 {
          position: relative; display: grid; align-items: center; gap: clamp(14px, 3vw, 40px);
          grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr) auto;
          border-radius: 20px; border: 1px solid rgba(244,244,241,0.09); background: var(--surface); padding: clamp(20px, 2vw, 26px);
          transition: all .3s ease-out;
        }
        .lp-단:hover { transform: translateX(6px); border-color: var(--accent); }
        .lp-단::before {
          content: ''; position: absolute; top: 50%; translate: 0 -50%; width: 10px; height: 10px; border-radius: 50%;
          background: var(--accent); left: calc(-1 * clamp(22px, 3.4vw, 48px) - 4.5px);
        }
        .lp-단 .머리 { display: flex; align-items: baseline; gap: 14px; }
        .lp-단 .번호 { font-family: var(--mono); font-size: 11px; letter-spacing: 0.16em; color: rgba(244,244,241,0.36); }
        .lp-단 .이름 { font-family: var(--font); font-weight: 600; letter-spacing: -0.02em; font-size: clamp(17px, 1.9vw, 25px); }
        .lp-단 .몸 { display: grid; gap: 6px; }
        .lp-단 .주체 { font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; }
        .lp-단 .설명 { font-family: var(--font); font-size: 13px; line-height: 1.75; color: rgba(244,244,241,0.56); }
        .lp-단 .출력 { font-family: var(--mono); font-size: 11px; color: var(--accent); border: 1px solid var(--accent-border); background: var(--accent-soft); padding: 5px 12px; border-radius: 999px; white-space: nowrap; }
        @media (max-width: 860px) { .lp-단 { grid-template-columns: 1fr; } .lp-단 .출력 { justify-self: start; } }
        .lp-도식감쌈 { margin-top: clamp(32px, 6vh, 56px); }

        /* ── 003 검증 ── */
        .lp-발견 { margin-top: clamp(28px, 6vh, 52px); display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); }
        .lp-발견 article { display: grid; align-content: start; gap: 12px; min-height: 220px; border-radius: 24px; border: 1px solid rgba(244,244,241,0.10); background: var(--surface); padding: clamp(24px, 2.6vw, 36px); }
        .lp-발견 .꼬리 { font-family: var(--mono); font-size: 10px; letter-spacing: 0.18em; color: rgba(244,244,241,0.45); }
        .lp-발견 .꼬리 b { font-weight: 500; }
        .lp-발견 .질문 { font-family: var(--font); font-weight: 600; line-height: 1.35; font-size: clamp(18px, 2vw, 23px); }
        .lp-발견 .답 { font-size: 13.5px; line-height: 1.8; color: rgba(244,244,241,0.62); }
        .lp-발견 .답 b { color: var(--text); font-weight: 600; }
        .lp-발견 article.강조 { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
        .lp-발견 article.강조 .꼬리, .lp-발견 article.강조 .답 { color: rgba(6,6,7,0.66); }
        .lp-발견 article.강조 .답 b { color: var(--on-accent); }

        /* ── 004 스택 ── */
        .lp-스택 { margin-top: clamp(28px, 6vh, 48px); display: flex; flex-wrap: wrap; gap: 10px; }
        .lp-스택 > div {
          display: grid; gap: 4px; border-radius: 18px; border: 1px solid rgba(244,244,241,0.14); padding: 14px 20px;
          transition: all .3s var(--ease); background: var(--surface);
        }
        .lp-스택 > div:hover { transform: translateY(-3px); background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
        .lp-스택 > div:hover .역할 { color: rgba(6,6,7,0.62); }
        .lp-스택 .이름 { font-family: var(--mono); font-size: 14px; font-weight: 500; }
        .lp-스택 .역할 { font-family: var(--font); font-size: 12px; color: rgba(244,244,241,0.5); transition: color .3s; }

        /* ── 푸터 ── */
        .lp-발 { padding: clamp(44px, 8vh, 96px) var(--gutter) 64px; }
        .lp-발 .워드 { font-weight: 700; line-height: 0.86; letter-spacing: -0.06em; font-size: clamp(40px, 9vw, 130px); }
        .lp-발 .워드 span { color: var(--accent); }
        .lp-발줄 { margin-top: 26px; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 16px; font-family: var(--mono); font-size: 11px; letter-spacing: 0.14em; color: rgba(244,244,241,0.4); }
        .lp-발줄 a { color: var(--accent); }
        .lp-발줄 a:hover { text-decoration: underline; }
      `}</style>

      <IntroCurtain />
      <ScrollHud />
      <RevealObserver />
      <Nav />

      <main id="top" className="lp">
        {/* ── 히어로 ── */}
        <header className="lp-hero">
          <HeroBackdrop />

          <div data-reveal className="lp-hero-top">
            <span className="lp-hero-name"><i />허니팟 기반 사이버 공격 분석 시스템</span>
            <span className="lp-hero-chip">2026 CAPSTONE / GRADUATION PROJECT</span>
          </div>

          <h1>
            <span className="lp-줄">
              <span style={{ display: "block", animation: "k-line 1.1s 1.5s cubic-bezier(.16,1,.3,1) both" }}>
                공격은 이미 기록된다.
              </span>
            </span>
            <span className="lp-줄">
              <span
                style={{ display: "flex", alignItems: "flex-start", gap: "0.24em", animation: "k-line 1.1s 1.64s cubic-bezier(.16,1,.3,1) both" }}
              >
                <span className="lp-외곽">이제</span>
                <span className="lp-돌림">
                  <span>
                    <span>분류한다.</span>
                    <span>해설한다.</span>
                    <span>보여준다.</span>
                    <span>분류한다.</span>
                  </span>
                </span>
              </span>
            </span>
          </h1>

          <div data-reveal className="lp-태그줄">
            <span className="lp-스티커">CAPSTONE 2026</span>
            <span>HONEYPOT × MITRE ATT&amp;CK × LOCAL LLM</span>
          </div>

          <p data-reveal className="lp-요약">
            허니팟은 공격을 유인해 빠짐없이 기록한다. 문제는 그 기록이
            <code> cowrie.login.failed </code> 같은 영문 원시 이벤트라는 것이다.
            이 시스템은 그것을 <b>공격 유형·위협 점수·한국어 대응 방안</b>까지
            자동으로 옮긴다.
          </p>

          <div data-reveal className="lp-cta">
            <Link href="/dashboard" className="주">대시보드 열기 →</Link>
            <a href="#구조" className="부">#어떻게_동작하나</a>
            <a href="#검증" className="부">#측정한_것</a>
          </div>

          <div data-reveal className="lp-지표">
            {검증.map((m, i) => (
              <div key={m.라벨} className="lp-지표칸 card-lift">
                <span className="라벨">| {m.라벨} · {m.이름}</span>
                <span className="값" style={{ color: hue(i) }}>
                  {m.값}<em>{m.단위}</em>
                </span>
                <span className="설명">{m.설명}</span>
              </div>
            ))}
          </div>
          <div data-reveal className="lp-지표주">2026-09-09 실측 · 실시간 값은 대시보드에서</div>
        </header>

        <Marquee text="T-POT 24.04.1 · 1,026,903 EVENTS · 25 HONEYPOTS · RULE-BASED CLASSIFIER · MITRE ATT&CK · OLLAMA LOCAL LLM · 한국어 해설 ·" />

        {/* ── 001 문제 ── */}
        <section className="lp-sec">
          <Kicker no="001" label="ISSUE" />
          <div className="lp-문제">
            <div data-reveal>
              <span className="lp-눈썹">WHY</span>
              <h2>
                수집은 해결됐고,
                <br />
                <span className="강조">해석이</span>
                <br />
                비어 있었다
              </h2>
              <p className="lp-도입">
                T-Pot 은 허니팟 25종을 묶어 Elasticsearch 에 로그를 쌓아준다.
                인프라로서는 완성도가 높다. 그런데 운영자가 마주하는 화면은 영문
                Kibana 이고, 그 안의 항목은 이런 모양이다.
              </p>
            </div>
            <div className="lp-대비">
              <div data-reveal className="lp-대비칸 card-lift">
                <span className="번호">DONE</span>
                <div>
                  <h3>이미 되어 있는 것</h3>
                  <p>
                    허니팟 25종이 SSH·SMB·웹·산업제어 프로토콜까지 받아내고,
                    Logstash 가 형식을 맞추고 IP 를 좌표로 바꿔 적재한다.
                    오탐이 거의 없는 공격 데이터가 계속 쌓인다.
                  </p>
                </div>
              </div>
              <div data-reveal className="lp-대비칸 미해결 card-lift">
                <span className="번호">TODO</span>
                <div>
                  <h3>사람이 해야 했던 것</h3>
                  <p>
                    이 이벤트가 정찰인지 침입인지, 얼마나 급한지, 지금 뭘 해야 하는지.
                    판단하려면 허니팟별 이벤트 스키마와 MITRE ATT&amp;CK 체계를
                    이미 알고 있어야 한다.
                  </p>
                  <pre className="lp-코드">
{"{ "}<span className="키">&quot;eventid&quot;</span>: <span className="값">&quot;cowrie.login.failed&quot;</span>,{"\n"}
{"  "}<span className="키">&quot;username&quot;</span>: <span className="값">&quot;root&quot;</span>, <span className="키">&quot;password&quot;</span>: <span className="값">&quot;123456&quot;</span>,{"\n"}
{"  "}<span className="키">&quot;src_ip&quot;</span>: <span className="값">&quot;203.0.113.10&quot;</span>, <span className="키">&quot;dst_port&quot;</span>: <span className="값">22</span> {"}"}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── 002 구조 ── */}
        <section className="lp-sec 면" id="구조">
          <Kicker no="002" label="PIPELINE" suffix="4 STAGES" />
          <div className="lp-머리줄">
            <div data-reveal>
              <span className="lp-눈썹">FLOW</span>
              <h2>
                네 단을 거쳐
                <br />
                한국어 보고가 된다
              </h2>
              <p className="lp-도입">
                각 단은 자기 인덱스에만 쓴다. 그래서 단계별로 다시 돌릴 수 있고,
                한 단이 멈춰도 앞 단의 결과는 그대로 남는다.
                <b> T-Pot 본체는 어느 단에서도 수정하지 않는다.</b>
              </p>
            </div>
            <Watermark no="002" />
          </div>

          <div className="lp-타임라인">
            <div className="lp-단들">
              {단계.map((s, i) => (
                <div data-reveal className="lp-단" key={s.n}>
                  <div className="머리">
                    <span className="번호">{s.n}</span>
                    <span className="이름">{s.이름}</span>
                  </div>
                  <div className="몸">
                    <span className="주체" style={{ color: hue(i) }}>{s.주체}</span>
                    <span className="설명">{s.설명}</span>
                  </div>
                  <span className="출력">{s.출력}</span>
                </div>
              ))}
            </div>
          </div>

          {/* 표가 "무엇을 받아 무엇을 내는가" 라면, 도식은 그게 실제로 어떻게
              흐르는지다. 어디서 갈라지고 어디가 막히는지는 글로는 안 보인다. */}
          <div data-reveal className="lp-도식감쌈">
            <파이프라인도식 />
          </div>
        </section>

        {/* ── 003 검증 ── */}
        <section className="lp-sec" id="검증">
          <Kicker no="003" label="FINDINGS" suffix="4 MEASUREMENTS" />
          <div className="lp-머리줄">
            <div data-reveal>
              <span className="lp-눈썹">MEASURED</span>
              <h2>만들면서 측정한 것</h2>
              <p className="lp-도입">
                기능을 늘리는 것보다 <b>무엇이 되고 무엇이 안 되는지</b> 가르는 데
                시간을 더 썼다. 아래는 추정이 아니라 실제로 재본 결과다.
              </p>
            </div>
            <Watermark no="003" />
          </div>
          <div className="lp-발견">
            {발견.map((f, i) => (
              <article key={f.질문} data-reveal className={`card-lift ${i === 0 ? "강조" : ""}`}>
                <span className="꼬리">
                  {String(i + 1).padStart(3, "0")} /{" "}
                  <b style={{ color: i === 0 ? undefined : f.경고 ? "var(--amber)" : "var(--accent)" }}>
                    {f.경고 ? "LIMIT" : "WORKS"}
                  </b>
                </span>
                <span className="질문">{f.질문}</span>
                <p className="답">{f.답}</p>
              </article>
            ))}
          </div>
        </section>

        {/* ── 004 스택 ── */}
        <section className="lp-sec 면" id="스택">
          <Kicker no="004" label="TECH STACK" suffix={`${스택.length} TOOLS`} />
          <div className="lp-머리줄">
            <div data-reveal>
              <span className="lp-눈썹">BUILT WITH</span>
              <h2>쓴 것과 만든 것</h2>
              <p className="lp-도입">
                허니팟 운영·로그 정규화·저장은 검증된 도구에 맡기고,
                비어 있던 <b>분류·해석·제시</b> 세 층에만 코드를 썼다.
              </p>
            </div>
            <Watermark no="004" />
          </div>
          <div data-reveal className="lp-스택">
            {스택.map(([이름, 역할]) => (
              <div key={이름}>
                <span className="이름">{이름}</span>
                <span className="역할">{역할}</span>
              </div>
            ))}
          </div>
        </section>

        <Marquee
          text="#STAYSECURE · T-POT · COWRIE · SURICATA · 99.9% AGREEMENT · SPRING BOOT + NEXT.JS · 정사평 ·"
          direction="right"
          variant="subtle"
        />

        <footer className="lp-발">
          <ParallaxWord>
            <div className="워드">정사평<span>.</span></div>
          </ParallaxWord>
          <div className="lp-발줄">
            <span>허니팟 기반 사이버 공격 분석 시스템 · 캡스톤 디자인 졸업작품</span>
            <Link href="/dashboard">대시보드 →</Link>
          </div>
        </footer>
      </main>
    </>
  );
}
