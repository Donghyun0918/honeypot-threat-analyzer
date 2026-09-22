"use client";

// 로그인 페이지 — Clean Light SaaS (auth 로직은 mock 유지, 스타일은 globals.css)

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Shield, User, Lock, Eye, EyeOff, ArrowLeft, ArrowRight,
  AlertTriangle, CheckCircle2, Info, Activity, BarChart3, ShieldCheck,
} from "lucide-react";

// 시연용 계정. 인증은 전적으로 백엔드가 한다 — 여기 값은 입력을 채워줄 뿐이다.
// (예전에는 이 맵으로 프론트에서 직접 로그인 판정을 했다. 비밀번호가 브라우저에
//  그대로 노출됐고 실제 계정과도 무관했다.)
const 시연계정 = { email: "demo@jsp.test", password: "demo1234" };

const HIGHLIGHTS = [
  { icon: Activity, text: "LLM 실시간 스트리밍 분석" },
  { icon: BarChart3, text: "D3 공격 흐름 시각화" },
  { icon: ShieldCheck, text: "MITRE ATT&CK 기반 대응 권고" },
];

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [shake, setShake] = useState(false);

  function quickLogin(id: string, pw: string) {
    setUsername(id);
    setPassword(pw);
    handleLogin(id, pw);
  }

  async function handleLogin(u = username, p = password) {
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: u.trim(), password: p }),
      });
      const data = await res.json().catch(() => ({}));

      // 성공 판정을 res.ok 로만 한다. **응답에 토큰이 없는 것이 정상이다** —
      // 서버가 httpOnly 쿠키로만 내려주므로 화면은 토큰을 보지 못한다.
      if (!res.ok) {
        setError(data?.message ?? "아이디 또는 비밀번호가 올바르지 않습니다.");
        setShake(true);
        setTimeout(() => setShake(false), 500);
        return;
      }

      setSuccess("로그인되었습니다. 대시보드로 이동합니다...");
      setTimeout(() => router.push("/dashboard"), 900);
    } catch {
      setError("서버에 연결할 수 없습니다. 백엔드가 실행 중인지 확인해주세요.");
      setShake(true);
      setTimeout(() => setShake(false), 500);
    } finally {
      setLoading(false);
    }
  }

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
            <div className="brand-headline">공격자를 <span>유인</span>하고<br />AI로 <span>분석</span>합니다</div>
            <p className="brand-desc">허니팟에 수집된 사이버 공격 데이터를 대규모 언어 모델이 실시간으로 분석해 위협 인텔리전스를 제공합니다.</p>
            <div className="hl-list">
              {HIGHLIGHTS.map((h) => (
                <div key={h.text} className="hl-item"><span className="hl-ic"><h.icon className="icon" /></span>{h.text}</div>
              ))}
            </div>
          </div>
        </div>
      </aside>

      {/* FORM PANEL */}
      <main className="auth-form">
        <div className={`auth-card ${shake ? "shake" : ""}`}>
          <Link href="/" className="back-link"><ArrowLeft className="icon" /> 홈으로 돌아가기</Link>
          <h1 className="auth-title">다시 오셨군요</h1>
          <p className="auth-sub">계정이 없으신가요? <Link href="/signup">회원가입</Link></p>

          <div className="alert alert-info" style={{ margin: "20px 0" }}>
            <Info className="icon" />
            <span>아래 <strong>시연 계정</strong> 버튼을 누르면 입력이 채워집니다. 인증은 백엔드에서 처리됩니다.</span>
          </div>

          {error && <div className="alert alert-error" style={{ marginBottom: 14 }}><AlertTriangle className="icon" /><span>{error}</span></div>}
          {success && <div className="alert alert-success" style={{ marginBottom: 14 }}><CheckCircle2 className="icon" /><span>{success}</span></div>}

          <form onSubmit={(e) => { e.preventDefault(); handleLogin(); }}>
            <div className="field">
              <label className="label">이메일</label>
              <div className="input-wrap">
                <User className="icon" />
                <input type="text" className="input has-icon" placeholder="이메일을 입력하세요"
                  value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
              </div>
            </div>
            <div className="field">
              <label className="label">비밀번호</label>
              <div className="input-wrap">
                <Lock className="icon" />
                <input type={showPw ? "text" : "password"} className="input has-icon" placeholder="비밀번호를 입력하세요"
                  value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
                <button type="button" className="input-suffix-btn" onClick={() => setShowPw(!showPw)} aria-label="비밀번호 표시">
                  {showPw ? <EyeOff className="icon" /> : <Eye className="icon" />}
                </button>
              </div>
            </div>
            <div className="row-between">
              <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: "0.82rem", color: "var(--text-2)", cursor: "pointer" }}>
                <input type="checkbox" /> 로그인 상태 유지
              </label>
              <a href="#" style={{ fontSize: "0.82rem", color: "var(--accent)", fontWeight: 600 }}>비밀번호 찾기</a>
            </div>
            <button type="submit" className="btn btn-dark btn-block btn-lg" disabled={loading}>
              {loading ? <><span className="spinner" /> 확인 중...</> : <>로그인 <ArrowRight className="icon" /></>}
            </button>
          </form>

          <div className="divider">또는 빠른 로그인</div>
          <div className="demo-grid" style={{ gridTemplateColumns: "1fr" }}>
            <button className="demo-btn" onClick={() => quickLogin(시연계정.email, 시연계정.password)}>
              <span className="t"><ShieldCheck className="icon" style={{ color: "var(--accent)" }} /> 시연 계정으로 로그인</span>
              <span className="r">{시연계정.email}</span>
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}
