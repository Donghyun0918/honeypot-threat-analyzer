"use client";

// 회원가입 페이지 — Clean Light SaaS (스텝/검증/비번강도 로직 유지, 스타일은 globals.css)

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Shield, User, Lock, Eye, EyeOff, Mail, Building2, ArrowLeft, ArrowRight,
  AlertTriangle, CheckCircle2, Sparkles, ShieldCheck, Zap,
} from "lucide-react";

const RESERVED_USERNAMES = ["admin", "root", "system", "administrator"];

type Step = 1 | 2 | 3;

function calcPwScore(val: string): number {
  let score = 0;
  if (val.length >= 8) score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  return score;
}

function calcStep(name: string, email: string, username: string, pw: string, pwc: string): Step {
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const usernameOk = /^[a-zA-Z0-9_]{4,20}$/.test(username) && !RESERVED_USERNAMES.includes(username.toLowerCase());
  const step1Done = name.trim().length > 0 && emailOk && usernameOk;
  const step2Done = step1Done && calcPwScore(pw) >= 3 && pw === pwc;
  if (step2Done) return 3;
  if (step1Done) return 2;
  return 1;
}

const PW_LEVELS = [
  { label: "매우 약함", color: "#ef4444", width: "20%" },
  { label: "약함", color: "#f97316", width: "40%" },
  { label: "보통", color: "#eab308", width: "60%" },
  { label: "강함", color: "#22c55e", width: "80%" },
  { label: "매우 강함", color: "#06b6d4", width: "100%" },
];

const BENEFITS = [
  { icon: Zap, text: "규칙 기반 자동 분류" },
  { icon: ShieldCheck, text: "MITRE ATT&CK 기반 위협 평가" },
  { icon: Sparkles, text: "한국어 요약·대응 방안 생성" },
];

export default function SignupPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [pw, setPw] = useState("");
  const [pwc, setPwc] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [showPwc, setShowPwc] = useState(false);
  const [terms, setTerms] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const currentStep = calcStep(name, email, username, pw, pwc);
  const pwScore = calcPwScore(pw);
  const pwLevel = PW_LEVELS[Math.min(pwScore, 4)];

  const emailOk = email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const emailErr = email && !emailOk;
  const usernameOk = username && /^[a-zA-Z0-9_]{4,20}$/.test(username) && !RESERVED_USERNAMES.includes(username.toLowerCase());
  const usernameErr = username && !usernameOk;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!name.trim() || !email.trim() || !username.trim() || !pw || !pwc) { setError("모든 필수 항목을 입력해주세요."); return; }
    if (pw !== pwc) { setError("비밀번호가 일치하지 않습니다."); return; }
    if (!terms) { setError("이용약관에 동의해주세요."); return; }

    setLoading(true);
    try {
      // 예전에는 setTimeout 으로 성공을 흉내 내고 로그인 화면으로 보냈다.
      // 계정이 실제로 만들어지지 않아 곧바로 로그인에 실패했다.
      const res = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password: pw, name: name.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data?.message ?? "가입에 실패했습니다.");
        return;
      }
      setSuccess(true);
      setTimeout(() => router.push("/login"), 1600);
    } catch {
      setError("서버에 연결할 수 없습니다.");
    } finally {
      setLoading(false);
    }
  }

  const steps: { n: Step; label: string }[] = [
    { n: 1, label: "기본 정보" }, { n: 2, label: "보안 설정" }, { n: 3, label: "완료" },
  ];

  return (
    <div className="auth">
      {/* BRAND PANEL */}
      <aside className="auth-brand">
        <div className="auth-brand-in">
          <div className="brand">
            <span className="brand-mark"><Shield className="icon" /></span>
            <span className="brand-name">정사<span>평</span></span>
          </div>
          <div className="hp-visual">
            <div className="hp-ring-box">
              <div className="hp-ring" /><div className="hp-ring" /><div className="hp-ring" />
              <div className="hp-core"><Shield className="icon" /></div>
            </div>
          </div>
          <div>
            <div className="brand-headline">허니팟 분석<br /><span>대시보드 계정</span></div>
            <p className="brand-desc">계정을 만들면 수집된 공격 로그의 분류 결과와 한국어 해설을 볼 수 있습니다.</p>
            <div className="hl-list">
              {BENEFITS.map((b) => (
                <div key={b.text} className="hl-item"><span className="hl-ic"><b.icon className="icon" /></span>{b.text}</div>
              ))}
            </div>
          </div>
        </div>
      </aside>

      {/* FORM PANEL */}
      <main className="auth-form">
        <div className="auth-card">
          <Link href="/" className="back-link"><ArrowLeft className="icon" /> 홈으로 돌아가기</Link>
          <h1 className="auth-title">계정 만들기</h1>
          <p className="auth-sub">이미 계정이 있으신가요? <Link href="/login">로그인</Link></p>

          {/* steps */}
          <div className="steps" style={{ marginTop: 22 }}>
            {steps.map((s, i) => (
              <div key={s.n} style={{ display: "contents" }}>
                <div className={`step ${currentStep === s.n ? "active" : ""} ${currentStep > s.n ? "done" : ""}`}>
                  <span className="step-dot">{currentStep > s.n ? <CheckCircle2 className="icon" /> : s.n}</span>
                  <span className="step-label">{s.label}</span>
                </div>
                {i < steps.length - 1 && <span className="step-line" />}
              </div>
            ))}
          </div>

          {success ? (
            <div className="alert alert-success" style={{ padding: "16px", flexDirection: "column", alignItems: "flex-start", gap: 6 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}><CheckCircle2 className="icon" /> 가입이 완료되었습니다!</div>
              <span style={{ color: "var(--text-2)" }}>로그인 페이지로 이동 중입니다...</span>
            </div>
          ) : (
            <form onSubmit={handleSubmit}>
              {error && <div className="alert alert-error" style={{ marginBottom: 14 }}><AlertTriangle className="icon" /><span>{error}</span></div>}

              <div className="field">
                <label className="label">이름 *</label>
                <div className="input-wrap">
                  <User className="icon" />
                  <input className="input has-icon" placeholder="홍길동" value={name} onChange={(e) => setName(e.target.value)} required />
                </div>
              </div>

              <div className="field">
                <label className="label">소속 (선택)</label>
                <div className="input-wrap">
                  <Building2 className="icon" />
                  <input className="input has-icon" placeholder="회사 / 학교" value={org} onChange={(e) => setOrg(e.target.value)} />
                </div>
              </div>

              <div className="field">
                <label className="label">이메일 *</label>
                <div className="input-wrap">
                  <Mail className="icon" />
                  <input type="email" className="input has-icon" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
                </div>
                {emailErr && <div className="field-hint err">올바른 이메일 형식이 아닙니다.</div>}
                {emailOk && <div className="field-hint ok">사용 가능한 이메일입니다.</div>}
              </div>

              <div className="field">
                <label className="label">아이디 *</label>
                <div className="input-wrap">
                  <User className="icon" />
                  <input className="input has-icon" placeholder="영문/숫자 4~20자" value={username} onChange={(e) => setUsername(e.target.value)} required />
                </div>
                {usernameErr && <div className="field-hint err">4~20자 영문/숫자/_ 만 가능하며 예약어는 쓸 수 없습니다.</div>}
                {usernameOk && <div className="field-hint ok">사용 가능한 아이디입니다.</div>}
              </div>

              <div className="field">
                <label className="label">비밀번호 *</label>
                <div className="input-wrap">
                  <Lock className="icon" />
                  <input type={showPw ? "text" : "password"} className="input has-icon" placeholder="8자 이상, 대문자·숫자·기호 권장"
                    value={pw} onChange={(e) => setPw(e.target.value)} required />
                  <button type="button" className="input-suffix-btn" onClick={() => setShowPw(!showPw)}>
                    {showPw ? <EyeOff className="icon" /> : <Eye className="icon" />}
                  </button>
                </div>
                {pw && (
                  <>
                    <div className="pw-meter"><div style={{ width: pwLevel.width, background: pwLevel.color }} /></div>
                    <div className="pw-row"><span className="muted">비밀번호 강도</span><span style={{ color: pwLevel.color, fontWeight: 700 }}>{pwLevel.label}</span></div>
                  </>
                )}
              </div>

              <div className="field">
                <label className="label">비밀번호 확인 *</label>
                <div className="input-wrap">
                  <Lock className="icon" />
                  <input type={showPwc ? "text" : "password"} className="input has-icon" placeholder="비밀번호를 다시 입력"
                    value={pwc} onChange={(e) => setPwc(e.target.value)} required />
                  <button type="button" className="input-suffix-btn" onClick={() => setShowPwc(!showPwc)}>
                    {showPwc ? <EyeOff className="icon" /> : <Eye className="icon" />}
                  </button>
                </div>
                {pwc && pw !== pwc && <div className="field-hint err">비밀번호가 일치하지 않습니다.</div>}
                {pwc && pw === pwc && <div className="field-hint ok">비밀번호가 일치합니다.</div>}
              </div>

              <label style={{ display: "flex", alignItems: "flex-start", gap: 9, fontSize: "0.82rem", color: "var(--text-2)", margin: "4px 0 18px", cursor: "pointer", lineHeight: 1.5 }}>
                <input type="checkbox" checked={terms} onChange={(e) => setTerms(e.target.checked)} style={{ marginTop: 3 }} />
                <span><strong style={{ color: "var(--text)" }}>이용약관</strong> 및 <strong style={{ color: "var(--text)" }}>개인정보처리방침</strong>에 동의합니다.</span>
              </label>

              <button type="submit" className="btn btn-dark btn-block btn-lg" disabled={loading}>
                {loading ? <><span className="spinner" /> 가입 처리 중...</> : <>회원가입 <ArrowRight className="icon" /></>}
              </button>
            </form>
          )}
        </div>
      </main>
    </div>
  );
}
