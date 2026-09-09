import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "정사평 — 허니팟 기반 사이버 공격 분석 시스템",
  description:
    "허니팟이 수집한 영문 보안 로그를 규칙 기반 분류와 한국어 LLM 해설을 거쳐 " +
    "바로 읽고 대응할 수 있는 위협 보고로 바꿉니다.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ko">
      <head>
        {/* IBM Plex — 엔지니어링 문서용으로 설계된 서체. KR 서브패밀리가 있어
            한글·영문·숫자가 한 가족 안에서 맞물린다. */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans+KR:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
