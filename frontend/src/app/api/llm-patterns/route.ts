// GET /api/llm-patterns — 한국어 해설을 **공격 패턴 단위**로 접어서 준다.
//
// llm-analyzer 가 패턴당 한 번만 해설하도록 바뀌면서(실측: 고위험 45,075건이
// 74개 패턴, 상위 2개가 89.8%) 같은 문장을 가진 문서가 수백~수만 건씩 생긴다.
// 건별 목록(/api/attacks?view=llm)을 그대로 쓰면 화면에 똑같은 문단이 수백 줄
// 나온다 — 파이프라인은 패턴 단위로 갔는데 화면만 건별로 남은 것이다.
//
// 접어서 보여주면 반복이 사라질 뿐 아니라, 이 프로젝트가 측정으로 찾아낸 사실
// ("4만 건이 실은 수십 개 패턴")이 화면에 그대로 드러난다.

import { NextRequest, NextResponse } from "next/server";
import { 인증헤더값, 인증실패통과 } from "@/lib/세션쿠키";

const API = process.env.SPRING_API_URL ?? "http://localhost:8090";

type 패턴 = {
  group_key: string;
  count: number;
  ip_count: number;
  latest?: string;
  severity?: string;
  mitre_score?: number;
  summary_ko?: string;
  solution_ko?: string;
  ttp_inferred?: string[];
  honeypot?: string;
  ml_label?: string;
};

export async function GET(req: NextRequest) {
  const sp = new URL(req.url).searchParams;
  const since = sp.get("since");
  const size = sp.get("size") ?? "12";
  const auth = 인증헤더값(req);

  const qs = new URLSearchParams({ size });
  if (since) qs.set("since", since);

  try {
    const res = await fetch(`${API}/api/llm-patterns?${qs}`, {
      cache: "no-store",
      headers: auth ? { Authorization: auth } : undefined,
      signal: AbortSignal.timeout(10_000),
    });
    // 인증 실패는 아래 빈-응답 처리로 덮지 않고 그대로 올린다(세션쿠키.ts 참조).
    const 인증거부 = 인증실패통과(res.status);
    if (인증거부) return 인증거부;

    if (!res.ok) return NextResponse.json({ 패턴목록: [], 오류: `백엔드 ${res.status}` });

    const d = (await res.json()) as { items?: 패턴[]; pattern_count?: number; event_total?: number };
    const items = d.items ?? [];

    // group_key 는 "허니팟|라벨|포트" 다. 화면에서 다시 쪼개 쓰기 좋게 풀어준다.
    //
    // 패턴 재사용을 넣기 전에 건별로 해설된 문서는 키가 없어 백엔드가
    // "(건별 해설)" 버킷으로 모은다. 그걸 쪼개면 "포트 -" 같은 가짜 패턴처럼
    // 보이므로 따로 표시한다 — 합계에서 빼지는 않는다(빼면 숫자가 안 맞는다).
    const 패턴목록 = items.map((p) => {
      const 키 = String(p.group_key ?? "");
      const 레거시 = !키.includes("|");
      const [허니팟, 라벨, 포트] = 키.split("|");
      return {
        키,
        레거시,
        허니팟: 레거시 ? "여러 지점" : (p.honeypot ?? 허니팟 ?? "-"),
        라벨: 레거시 ? "패턴 이전 해설" : (p.ml_label ?? 라벨 ?? "-"),
        // 임시 포트는 사건마다 달라서 하나로 접은 것이다. 번호처럼 보이면 안 된다.
        포트: 레거시 ? "—" : (포트 === "ephemeral" ? "임시 포트" : (포트 ?? "-")),
        건수: p.count ?? 0,
        공격IP수: p.ip_count ?? 0,
        최근: p.latest ?? null,
        위험등급: p.severity ?? null,
        위협점수: p.mitre_score ?? null,
        요약: p.summary_ko ?? "",
        대응: p.solution_ko ?? "",
        기법: Array.isArray(p.ttp_inferred) ? p.ttp_inferred : [],
      };
    });

    const 사건합계 = d.event_total ?? 패턴목록.reduce((a, p) => a + p.건수, 0);
    return NextResponse.json({
      패턴목록,
      패턴수: d.pattern_count ?? 패턴목록.length,
      사건합계,
      // 한 번의 해설이 평균 몇 건을 덮는가 — 절감을 한 숫자로 보여준다.
      건당덮는수: 패턴목록.length > 0 ? Math.round((사건합계 / 패턴목록.length) * 10) / 10 : null,
    });
  } catch {
    return NextResponse.json({ 패턴목록: [], 오류: "백엔드에 연결할 수 없습니다." });
  }
}
