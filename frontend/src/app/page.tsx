// 랜딩 — 프로젝트 소개.
// 제품 판매 페이지가 아니라 "무엇을 왜 만들었고 무엇이 검증됐는가"를 보여주는 면이다.
// 수치는 2026-09-09 검증 시점의 실측 기준값이다. 실시간 값은 대시보드에 있다.

import Link from "next/link";

/* 파이프라인 각 단이 무엇을 받아 무엇을 내는지. 랜딩의 본론. */
const 단계 = [
  {
    n: "01",
    이름: "수집",
    주체: "T-Pot · 허니팟 25종",
    설명: "일부러 취약하게 열어둔 미끼 시스템이 공격을 그대로 기록한다. 실제 서비스가 아니므로 들어오는 접속은 정의상 전부 비정상이다.",
    출력: "logstash-*",
  },
  {
    n: "02",
    이름: "분류",
    주체: "ml-classifier",
    설명: "허니팟 종류와 이벤트 내용으로 공격 유형을 판정하고 MITRE ATT&CK 위협 점수를 매긴다. 30초 주기로 새 이벤트만 처리한다.",
    출력: "ml-analysis-*",
  },
  {
    n: "03",
    이름: "해설",
    주체: "llm-analyzer",
    설명: "위협 점수 70점 이상인 건만 골라 한국어 요약과 대응 방안을 만든다. LLM 호출은 비싸므로 볼 가치가 있는 것만 통과시킨다.",
    출력: "llm-analysis-*",
  },
  {
    n: "04",
    이름: "제시",
    주체: "대시보드 · 어택맵",
    설명: "분류 결과와 해설을 한국어 화면으로 올린다. 출발지에서 센서로 향하는 공격을 지도 위에 실시간으로 그린다.",
    출력: "브라우저",
  },
];

/* 만들면서 실제로 측정한 것들. 홍보 문구 대신 숫자를 둔다.
   라이브 값이 아니라 2026-09-09 검증 시점의 기준값이다 — 소개 면이
   스택 가동 여부에 따라 0 으로 보이면 안 된다. 실시간은 대시보드에 있다. */
const 검증 = [
  { 값: "222", 단위: "건", 라벨: "수집 이벤트", 설명: "logstash-* 적재" },
  { 값: "221", 단위: "건", 라벨: "분류 완료", 설명: "고위험 83건 선별" },
  { 값: "60", 단위: "건", 라벨: "한국어 해설", 설명: "실패·폴백 0건" },
  { 값: "4", 단위: "종", 라벨: "사이드카", 설명: "T-Pot 본체 무수정" },
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

export default function 랜딩() {
  return (
    <>
      <style>{`
        .lp { --gutter: clamp(24px, 6vw, 88px); }
        .lp a { text-decoration: none; }

        /* ── 상단 바 ── */
        .lp-bar {
          position: sticky; top: 0; z-index: 50;
          display: flex; align-items: baseline; gap: 16px;
          padding: 18px var(--gutter);
          background: var(--chrome); border-bottom: 1px solid var(--chrome-border);
        }
        .lp-bar .팀 {
          font-weight: 700; font-size: 0.95rem; letter-spacing: -0.01em; color: #fff;
        }
        .lp-bar .프로젝트 {
          font-family: var(--mono); font-size: 0.74rem; letter-spacing: 0.06em;
          color: var(--chrome-accent);
        }
        .lp-bar .우측 { margin-left: auto; display: flex; gap: 20px; align-items: baseline; }
        .lp-bar .우측 a {
          font-family: var(--mono); font-size: 0.78rem; color: var(--chrome-text-2);
          padding-bottom: 2px; border-bottom: 1px solid transparent;
        }
        .lp-bar .우측 a:hover { color: #fff; border-bottom-color: var(--chrome-accent); }

        /* ── 히어로: 가운데 정렬 대신 좌측 정렬 2단 ── */
        .lp-hero {
          padding: clamp(56px, 9vw, 104px) var(--gutter) clamp(40px, 6vw, 72px);
          border-bottom: 1px solid var(--border);
          display: grid; grid-template-columns: minmax(0, 1.62fr) minmax(0, 1fr);
          gap: clamp(32px, 5vw, 72px); align-items: end;
        }
        @media (max-width: 900px) { .lp-hero { grid-template-columns: 1fr; align-items: start; } }

        .lp-eyebrow {
          font-family: var(--mono); font-size: 0.76rem; letter-spacing: 0.16em;
          text-transform: uppercase; color: var(--accent); margin-bottom: 20px;
        }
        .lp-hero h1 {
          font-size: clamp(1.95rem, 4.4vw, 3.15rem); line-height: 1.12;
          letter-spacing: -0.028em; font-weight: 700; margin: 0 0 22px;
          text-wrap: balance;
        }
        .lp-hero .요약 {
          font-size: clamp(1rem, 1.5vw, 1.16rem); line-height: 1.72; color: var(--text-2);
          max-width: 46ch; margin: 0 0 30px;
        }
        .lp-hero .요약 b { color: var(--text); font-weight: 600; }
        .lp-cta { display: flex; gap: 12px; flex-wrap: wrap; }
        .lp-btn {
          display: inline-flex; align-items: center; gap: 9px;
          padding: 12px 22px; border-radius: var(--radius-sm);
          font-size: 0.92rem; font-weight: 600; transition: all 0.16s;
          border: 1px solid transparent;
        }
        .lp-btn-주 { background: var(--accent); color: #fff; }
        .lp-btn-주:hover { background: var(--accent-hover); }
        .lp-btn-부 { border-color: var(--border-strong); color: var(--text); background: var(--surface); }
        .lp-btn-부:hover { border-color: var(--accent); color: var(--accent); }
        .lp-btn .화살 { font-family: var(--mono); }

        /* 히어로 우측 실측 수치 */
        .lp-지표 {
          border: 1px solid var(--border); background: var(--surface);
          border-radius: var(--radius-sm); overflow: hidden;
          display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--border);
        }
        .lp-지표 > div { background: var(--surface); padding: 15px 17px; }
        .lp-지표 .라벨 {
          font-family: var(--mono); font-size: 0.68rem; letter-spacing: 0.1em;
          text-transform: uppercase; color: var(--text-3, var(--text-2)); margin-bottom: 3px;
        }
        .lp-지표 .값 {
          font-size: 1.85rem; font-weight: 700; line-height: 1.15;
          font-variant-numeric: tabular-nums; letter-spacing: -0.02em;
        }
        .lp-지표 .값 em {
          font-style: normal; font-size: 0.82rem; font-weight: 500;
          color: var(--text-2); margin-left: 3px;
        }
        .lp-지표 .설명 { font-family: var(--mono); font-size: 0.7rem; color: var(--text-2); margin-top: 2px; }
        .lp-지표-주 { font-family: var(--mono); font-size: 0.7rem; color: var(--text-2); margin-top: 9px; text-align: right; }

        /* ── 공통 섹션 ── */
        .lp-sec { padding: clamp(48px, 7vw, 84px) var(--gutter); border-bottom: 1px solid var(--border); }
        .lp-sec-머리 { display: flex; align-items: baseline; gap: 14px; margin-bottom: 12px; }
        .lp-sec-번호 {
          font-family: var(--mono); font-size: 0.76rem; color: var(--accent); font-weight: 600;
        }
        .lp-sec h2 {
          font-size: clamp(1.4rem, 2.5vw, 1.95rem); font-weight: 700;
          letter-spacing: -0.018em; margin: 0;
        }
        .lp-sec .도입 {
          font-size: 1.02rem; line-height: 1.75; color: var(--text-2);
          max-width: 62ch; margin: 0 0 34px;
        }
        .lp-sec .도입 b { color: var(--text); font-weight: 600; }

        /* ── 문제 제기: 좌우 대비 ── */
        .lp-대비 { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden; }
        @media (max-width: 760px) { .lp-대비 { grid-template-columns: 1fr; } }
        .lp-대비 > div { background: var(--surface); padding: 24px 26px; }
        .lp-대비 .제목 { font-weight: 600; font-size: 1.02rem; margin-bottom: 10px; }
        .lp-대비 .해결 .제목 { color: var(--green); }
        .lp-대비 .미해결 .제목 { color: var(--amber); }
        .lp-대비 p { font-size: 0.93rem; line-height: 1.7; color: var(--text-2); margin: 0; }
        .lp-코드 {
          font-family: var(--mono); font-size: 0.78rem; line-height: 1.75;
          background: var(--bg); border: 1px solid var(--border); border-radius: 3px;
          padding: 12px 14px; margin-top: 14px; overflow-x: auto; white-space: pre; color: var(--text-2);
        }

        /* ── 파이프라인 4단 ── */
        .lp-단계들 { display: grid; gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden; }
        .lp-단 {
          background: var(--surface); padding: 22px 26px;
          display: grid; grid-template-columns: 52px minmax(0, 190px) minmax(0, 1fr) minmax(0, 160px); gap: 24px; align-items: start;
        }
        @media (max-width: 860px) { .lp-단 { grid-template-columns: 44px 1fr; gap: 14px; } .lp-단 .출력 { grid-column: 2; } }
        .lp-단 .번호 { font-family: var(--mono); font-size: 0.9rem; font-weight: 600; color: var(--accent); padding-top: 2px; }
        .lp-단 .이름 { font-weight: 700; font-size: 1.06rem; margin-bottom: 3px; }
        .lp-단 .주체 { font-family: var(--mono); font-size: 0.76rem; color: var(--text-2); }
        .lp-단 .설명 { font-size: 0.92rem; line-height: 1.72; color: var(--text-2); }
        .lp-단 .출력 { justify-self: start; }
        .lp-단 .출력 span {
          font-family: var(--mono); font-size: 0.74rem; color: var(--accent);
          border: 1px solid var(--accent-border); background: var(--accent-soft);
          padding: 3px 9px; border-radius: 3px; white-space: nowrap;
        }

        /* ── 우리가 확인한 것 ── */
        .lp-발견 { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
        .lp-발견 article {
          border: 1px solid var(--border); border-left: 3px solid var(--accent);
          background: var(--surface); border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
          padding: 20px 22px;
        }
        .lp-발견 .질문 { font-weight: 600; font-size: 0.98rem; margin-bottom: 8px; }
        .lp-발견 .답 { font-size: 0.9rem; line-height: 1.7; color: var(--text-2); margin: 0; }
        .lp-발견 .답 b { color: var(--text); font-weight: 600; }
        .lp-발견 article.경고 { border-left-color: var(--amber); }

        /* ── 스택 ── */
        .lp-스택 { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden; }
        .lp-스택 > div { background: var(--surface); padding: 14px 18px; }
        .lp-스택 .이름 { font-family: var(--mono); font-size: 0.84rem; font-weight: 500; margin-bottom: 2px; }
        .lp-스택 .역할 { font-size: 0.79rem; color: var(--text-2); }

        /* ── 푸터 ── */
        .lp-발 {
          padding: 34px var(--gutter) 44px; background: var(--chrome); color: var(--chrome-text-2);
          display: flex; flex-wrap: wrap; gap: 14px 32px; align-items: baseline;
        }
        .lp-발 .팀 { font-weight: 700; color: #fff; font-size: 1rem; }
        .lp-발 span { font-family: var(--mono); font-size: 0.76rem; }
        .lp-발 a { color: var(--chrome-accent); font-family: var(--mono); font-size: 0.76rem; }
      `}</style>

      <div className="lp">
        <nav className="lp-bar">
          <span className="팀">정사평</span>
          <span className="프로젝트">허니팟 기반 사이버 공격 분석 시스템</span>
          <span className="우측">
            <a href="#구조">구조</a>
            <a href="#검증">검증</a>
            <Link href="/dashboard">대시보드</Link>
          </span>
        </nav>

        {/* ── 히어로 ── */}
        <header className="lp-hero">
          <div>
            <div className="lp-eyebrow">캡스톤 디자인 · 졸업작품</div>
            <h1>공격은 이미 기록되고 있다.<br />읽을 수 있게 만드는 일이 남았다.</h1>
            <p className="요약">
              허니팟은 공격을 유인해 빠짐없이 기록한다. 문제는 그 기록이
              <code> cowrie.login.failed </code> 같은 영문 원시 이벤트라는 것이다.
              이 시스템은 그것을 <b>공격 유형·위협 점수·한국어 대응 방안</b>까지
              자동으로 옮긴다.
            </p>
            <div className="lp-cta">
              <Link href="/dashboard" className="lp-btn lp-btn-주">
                대시보드 열기 <span className="화살">→</span>
              </Link>
              <a href="#구조" className="lp-btn lp-btn-부">어떻게 동작하나</a>
            </div>
          </div>

          <div className="lp-지표-감쌈">
          <div className="lp-지표">
            {검증.map((m) => (
              <div key={m.라벨}>
                <div className="라벨">{m.라벨}</div>
                <div className="값">
                  {m.값}
                  <em>{m.단위}</em>
                </div>
                <div className="설명">{m.설명}</div>
              </div>
            ))}
          </div>
          <div className="lp-지표-주">2026-09-09 실측 · 실시간 값은 대시보드에서</div>
          </div>
        </header>

        {/* ── 문제 ── */}
        <section className="lp-sec">
          <div className="lp-sec-머리">
            <span className="lp-sec-번호">01</span>
            <h2>수집은 해결됐고, 해석이 비어 있었다</h2>
          </div>
          <p className="도입">
            T-Pot 은 허니팟 25종을 묶어 Elasticsearch 에 로그를 쌓아준다.
            인프라로서는 완성도가 높다. 그런데 운영자가 마주하는 화면은 영문
            Kibana 이고, 그 안의 항목은 이런 모양이다.
          </p>
          <div className="lp-대비">
            <div className="해결">
              <div className="제목">이미 되어 있는 것</div>
              <p>
                허니팟 25종이 SSH·SMB·웹·산업제어 프로토콜까지 받아내고,
                Logstash 가 형식을 맞추고 IP 를 좌표로 바꿔 적재한다.
                오탐이 거의 없는 공격 데이터가 계속 쌓인다.
              </p>
            </div>
            <div className="미해결">
              <div className="제목">사람이 해야 했던 것</div>
              <p>
                이 이벤트가 정찰인지 침입인지, 얼마나 급한지, 지금 뭘 해야 하는지.
                판단하려면 허니팟별 이벤트 스키마와 MITRE ATT&CK 체계를
                이미 알고 있어야 한다.
              </p>
              <pre className="lp-코드">{`{ "eventid": "cowrie.login.failed",
  "username": "root", "password": "123456",
  "src_ip": "203.0.113.10", "dst_port": 22 }`}</pre>
            </div>
          </div>
        </section>

        {/* ── 구조 ── */}
        <section className="lp-sec" id="구조">
          <div className="lp-sec-머리">
            <span className="lp-sec-번호">02</span>
            <h2>네 단을 거쳐 한국어 보고가 된다</h2>
          </div>
          <p className="도입">
            각 단은 자기 인덱스에만 쓴다. 그래서 단계별로 다시 돌릴 수 있고,
            한 단이 멈춰도 앞 단의 결과는 그대로 남는다.
            <b> T-Pot 본체는 어느 단에서도 수정하지 않는다.</b>
          </p>
          <div className="lp-단계들">
            {단계.map((s) => (
              <div className="lp-단" key={s.n}>
                <div className="번호">{s.n}</div>
                <div>
                  <div className="이름">{s.이름}</div>
                  <div className="주체">{s.주체}</div>
                </div>
                <div className="설명">{s.설명}</div>
                <div className="출력">
                  <span>{s.출력}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── 검증 ── */}
        <section className="lp-sec" id="검증">
          <div className="lp-sec-머리">
            <span className="lp-sec-번호">03</span>
            <h2>만들면서 측정한 것</h2>
          </div>
          <p className="도입">
            기능을 늘리는 것보다 <b>무엇이 되고 무엇이 안 되는지</b> 가르는 데
            시간을 더 썼다. 아래는 추정이 아니라 실제로 재본 결과다.
          </p>
          <div className="lp-발견">
            <article>
              <div className="질문">한국어 해설은 쓸 만한가</div>
              <p className="답">
                고위험 60건 전부 성공, 폴백 0건. 다만 모델이 한국어에 한자를
                섞는 일이 있어 <b>출력을 검사해 재시도</b>하도록 했다.
              </p>
            </article>
            <article className="경고">
              <div className="질문">학습 모델을 켤 수 있는가</div>
              <p className="답">
                아직 아니다. 규칙 대비 일치율이 <b>61.4%</b> 에 그친다.
                학습 정답을 규칙에서 뽑았으니 모델의 천장이 규칙 재현이고,
                켜면 오히려 품질이 떨어진다.
              </p>
            </article>
            <article className="경고">
              <div className="질문">LLM 이 위험도를 정할 수 있는가</div>
              <p className="답">
                못 한다. 고위험 문서 10건에서 <b>10건 모두</b> 실제보다 낮게 매겼고,
                판정 예시를 넣어도 그대로였다. 그래서 위험도는 점수에서
                계산하고 모델에게는 문장만 맡긴다.
              </p>
            </article>
            <article>
              <div className="질문">데이터 문제는 어디였나</div>
              <p className="답">
                내보낸 로그에서 포트는 접속 행에, 명령은 다른 행에 흩어져 있었다.
                세션 단위로 합치자 일치율이 <b>35.4% → 61.4%</b> 로 올랐다.
              </p>
            </article>
          </div>
        </section>

        {/* ── 스택 ── */}
        <section className="lp-sec">
          <div className="lp-sec-머리">
            <span className="lp-sec-번호">04</span>
            <h2>쓴 것과 만든 것</h2>
          </div>
          <p className="도입">
            허니팟 운영·로그 정규화·저장은 검증된 도구에 맡기고,
            비어 있던 <b>분류·해석·제시</b> 세 층에만 코드를 썼다.
          </p>
          <div className="lp-스택">
            {스택.map(([이름, 역할]) => (
              <div key={이름}>
                <div className="이름">{이름}</div>
                <div className="역할">{역할}</div>
              </div>
            ))}
          </div>
        </section>

        <footer className="lp-발">
          <span className="팀">정사평</span>
          <span>허니팟 기반 사이버 공격 분석 시스템</span>
          <span>캡스톤 디자인 졸업작품</span>
          <Link href="/dashboard">대시보드 →</Link>
        </footer>
      </div>
    </>
  );
}
