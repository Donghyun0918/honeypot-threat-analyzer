/**
 * LLM 제공자 추상화
 *
 * Ollama(로컬) 외에 OpenAI(+호환), Anthropic Claude, Google Gemini 를
 * 같은 인터페이스로 사용. 환경변수 LLM_PROVIDER 로 선택한다.
 *
 *   LLM_PROVIDER = ollama(기본) | openai | anthropic | gemini | openai-compatible
 *   LLM_MODEL    = 모델명 (미지정 시 제공자별 기본값)
 *   OLLAMA_HOST          (ollama)
 *   OPENAI_API_KEY  / OPENAI_BASE_URL          (openai / openai-compatible)
 *   ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL     (anthropic)
 *   GEMINI_API_KEY  / GEMINI_BASE_URL          (gemini)
 *
 * API 키가 없으면 해당 제공자의 상태확인()이 false 를 반환하므로,
 * 키를 채우기 전에는 기본값(ollama)으로 운용하면 된다.
 *
 * 공통 인터페이스:
 *   호출(프롬프트)     → 단건 응답 원문(보통 JSON 문자열)
 *   스트리밍(프롬프트) → [토큰, done] 비동기 제너레이터
 *   상태확인()         → 연결/인증 가능 여부
 */

const 요청타임아웃 = 180_000; // ms
const JSON지시 =
  "You must respond with ONLY a single valid JSON object. No markdown, no code fences, no commentary.";

// 빈 문자열도 기본값으로 처리(컴포즈가 미설정 env를 ""로 넘기는 경우 대비)
function env(키: string, 기본 = ""): string {
  const v = process.env[키];
  return v && v.trim() !== "" ? v : 기본;
}

export interface LLM제공자 {
  readonly 이름: string;
  readonly 모델: string;
  호출(프롬프트: string): Promise<string>;
  스트리밍(프롬프트: string): AsyncGenerator<[string, boolean]>;
  상태확인(): Promise<boolean>;
}

// ─── 공통: SSE(data:) 라인 파서 ────────────────────────────────────────────
async function* SSE라인들(
  body: ReadableStream<Uint8Array>
): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    for (const line of lines) {
      const t = line.trim();
      if (t.startsWith("data:")) yield t.slice(5).trim();
    }
  }
  const last = buf.trim();
  if (last.startsWith("data:")) yield last.slice(5).trim();
}

// ─── Ollama ────────────────────────────────────────────────────────────────
export class Ollama제공자 implements LLM제공자 {
  readonly 이름 = "ollama";
  readonly 모델: string;
  private readonly 주소: string;

  constructor(모델?: string, 주소?: string) {
    this.주소 = 주소 ?? env("OLLAMA_HOST", "http://localhost:11434");
    this.모델 = 모델 ?? env("LLM_MODEL", "llama3.1:8b");
  }

  private 본문(프롬프트: string, stream: boolean) {
    return {
      model: this.모델,
      prompt: 프롬프트,
      stream,
      format: "json",
      options: { temperature: 0.1, top_p: 0.9, num_predict: 1024 },
    };
  }

  async 호출(프롬프트: string): Promise<string> {
    const res = await fetch(`${this.주소}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(this.본문(프롬프트, false)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok) throw new Error(`Ollama 응답 오류: ${res.status}`);
    const data = (await res.json()) as { response?: string };
    return data.response ?? "";
  }

  async *스트리밍(프롬프트: string): AsyncGenerator<[string, boolean]> {
    const res = await fetch(`${this.주소}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(this.본문(프롬프트, true)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok || !res.body) throw new Error(`Ollama 스트리밍 오류: ${res.status}`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const d = JSON.parse(line) as { response?: string; done?: boolean };
          yield [d.response ?? "", d.done ?? false];
          if (d.done) return;
        } catch {
          /* JSON 파싱 실패 시 skip */
        }
      }
    }
  }

  async 상태확인(): Promise<boolean> {
    try {
      const res = await fetch(`${this.주소}/api/tags`, {
        signal: AbortSignal.timeout(5_000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

// ─── OpenAI (및 OpenAI 호환: LM Studio·vLLM·Together·Groq 등) ───────────────
export class OpenAI제공자 implements LLM제공자 {
  readonly 이름: string;
  readonly 모델: string;
  private readonly base: string;
  private readonly key: string;
  private readonly json강제: boolean;

  constructor(opts?: {
    이름?: string;
    모델?: string;
    base?: string;
    key?: string;
    json강제?: boolean;
  }) {
    this.이름 = opts?.이름 ?? "openai";
    this.base = (opts?.base ?? env("OPENAI_BASE_URL", "https://api.openai.com")).replace(
      /\/+$/,
      ""
    );
    this.key = opts?.key ?? env("OPENAI_API_KEY");
    this.모델 = opts?.모델 ?? env("LLM_MODEL", "gpt-4o-mini");
    // 일부 OpenAI 호환 서버는 response_format 미지원 → OPENAI_JSON_MODE=false 로 끄기
    this.json강제 = opts?.json강제 ?? env("OPENAI_JSON_MODE", "true") !== "false";
  }

  private 본문(프롬프트: string, stream: boolean) {
    const b: Record<string, unknown> = {
      model: this.모델,
      messages: [
        { role: "system", content: JSON지시 },
        { role: "user", content: 프롬프트 },
      ],
      temperature: 0.1,
      stream,
    };
    if (this.json강제) b.response_format = { type: "json_object" };
    return b;
  }

  private get 헤더() {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.key}`,
    };
  }

  async 호출(프롬프트: string): Promise<string> {
    const res = await fetch(`${this.base}/v1/chat/completions`, {
      method: "POST",
      headers: this.헤더,
      body: JSON.stringify(this.본문(프롬프트, false)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok)
      throw new Error(`${this.이름} 응답 오류: ${res.status} ${await res.text().catch(() => "")}`);
    const d = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    return d.choices?.[0]?.message?.content ?? "";
  }

  async *스트리밍(프롬프트: string): AsyncGenerator<[string, boolean]> {
    const res = await fetch(`${this.base}/v1/chat/completions`, {
      method: "POST",
      headers: this.헤더,
      body: JSON.stringify(this.본문(프롬프트, true)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok || !res.body)
      throw new Error(`${this.이름} 스트리밍 오류: ${res.status}`);
    for await (const data of SSE라인들(res.body)) {
      if (data === "[DONE]") {
        yield ["", true];
        return;
      }
      try {
        const o = JSON.parse(data) as {
          choices?: { delta?: { content?: string }; finish_reason?: string | null }[];
        };
        const t = o.choices?.[0]?.delta?.content ?? "";
        const done = o.choices?.[0]?.finish_reason != null;
        if (t) yield [t, false];
        if (done) {
          yield ["", true];
          return;
        }
      } catch {
        /* skip */
      }
    }
    yield ["", true];
  }

  async 상태확인(): Promise<boolean> {
    if (!this.key) return false;
    try {
      const res = await fetch(`${this.base}/v1/models`, {
        headers: this.헤더,
        signal: AbortSignal.timeout(5_000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

// ─── Anthropic Claude ────────────────────────────────────────────────────────
export class Anthropic제공자 implements LLM제공자 {
  readonly 이름 = "anthropic";
  readonly 모델: string;
  private readonly base: string;
  private readonly key: string;

  constructor(opts?: { 모델?: string; base?: string; key?: string }) {
    this.base = (opts?.base ?? env("ANTHROPIC_BASE_URL", "https://api.anthropic.com")).replace(
      /\/+$/,
      ""
    );
    this.key = opts?.key ?? env("ANTHROPIC_API_KEY");
    this.모델 = opts?.모델 ?? env("LLM_MODEL", "claude-3-5-haiku-latest");
  }

  private get 헤더() {
    return {
      "Content-Type": "application/json",
      "x-api-key": this.key,
      "anthropic-version": "2023-06-01",
    };
  }

  private 본문(프롬프트: string, stream: boolean) {
    return {
      model: this.모델,
      max_tokens: 1024,
      temperature: 0.1,
      system: JSON지시,
      messages: [{ role: "user", content: 프롬프트 }],
      stream,
    };
  }

  async 호출(프롬프트: string): Promise<string> {
    const res = await fetch(`${this.base}/v1/messages`, {
      method: "POST",
      headers: this.헤더,
      body: JSON.stringify(this.본문(프롬프트, false)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok)
      throw new Error(`Anthropic 응답 오류: ${res.status} ${await res.text().catch(() => "")}`);
    const d = (await res.json()) as { content?: { text?: string }[] };
    return d.content?.map((c) => c.text ?? "").join("") ?? "";
  }

  async *스트리밍(프롬프트: string): AsyncGenerator<[string, boolean]> {
    const res = await fetch(`${this.base}/v1/messages`, {
      method: "POST",
      headers: this.헤더,
      body: JSON.stringify(this.본문(프롬프트, true)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok || !res.body)
      throw new Error(`Anthropic 스트리밍 오류: ${res.status}`);
    for await (const data of SSE라인들(res.body)) {
      try {
        const o = JSON.parse(data) as {
          type?: string;
          delta?: { text?: string };
        };
        if (o.type === "content_block_delta") {
          const t = o.delta?.text ?? "";
          if (t) yield [t, false];
        } else if (o.type === "message_stop") {
          yield ["", true];
          return;
        }
      } catch {
        /* event: 라인 등은 skip */
      }
    }
    yield ["", true];
  }

  async 상태확인(): Promise<boolean> {
    if (!this.key) return false;
    try {
      const res = await fetch(`${this.base}/v1/models`, {
        headers: this.헤더,
        signal: AbortSignal.timeout(5_000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

// ─── Google Gemini ───────────────────────────────────────────────────────────
export class Gemini제공자 implements LLM제공자 {
  readonly 이름 = "gemini";
  readonly 모델: string;
  private readonly base: string;
  private readonly key: string;

  constructor(opts?: { 모델?: string; base?: string; key?: string }) {
    this.base = (
      opts?.base ?? env("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com")
    ).replace(/\/+$/, "");
    this.key = opts?.key ?? env("GEMINI_API_KEY");
    this.모델 = opts?.모델 ?? env("LLM_MODEL", "gemini-2.0-flash");
  }

  private 본문(프롬프트: string) {
    return {
      contents: [{ parts: [{ text: 프롬프트 }] }],
      generationConfig: {
        temperature: 0.1,
        responseMimeType: "application/json",
      },
    };
  }

  async 호출(프롬프트: string): Promise<string> {
    const url = `${this.base}/v1beta/models/${this.모델}:generateContent?key=${this.key}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(this.본문(프롬프트)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok)
      throw new Error(`Gemini 응답 오류: ${res.status} ${await res.text().catch(() => "")}`);
    const d = (await res.json()) as {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
    };
    return d.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("") ?? "";
  }

  async *스트리밍(프롬프트: string): AsyncGenerator<[string, boolean]> {
    const url = `${this.base}/v1beta/models/${this.모델}:streamGenerateContent?alt=sse&key=${this.key}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(this.본문(프롬프트)),
      signal: AbortSignal.timeout(요청타임아웃),
    });
    if (!res.ok || !res.body)
      throw new Error(`Gemini 스트리밍 오류: ${res.status}`);
    for await (const data of SSE라인들(res.body)) {
      try {
        const o = JSON.parse(data) as {
          candidates?: { content?: { parts?: { text?: string }[] } }[];
        };
        const t = o.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("") ?? "";
        if (t) yield [t, false];
      } catch {
        /* skip */
      }
    }
    yield ["", true];
  }

  async 상태확인(): Promise<boolean> {
    if (!this.key) return false;
    try {
      const res = await fetch(`${this.base}/v1beta/models?key=${this.key}`, {
        signal: AbortSignal.timeout(5_000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

// ─── 팩토리: LLM_PROVIDER 로 선택 ──────────────────────────────────────────
export function 제공자생성(): LLM제공자 {
  const p = env("LLM_PROVIDER", "ollama").toLowerCase();
  switch (p) {
    case "openai":
      return new OpenAI제공자();
    case "openai-compatible":
    case "compatible":
      return new OpenAI제공자({ 이름: "openai-compatible" });
    case "anthropic":
    case "claude":
      return new Anthropic제공자();
    case "gemini":
    case "google":
      return new Gemini제공자();
    case "ollama":
    default:
      return new Ollama제공자();
  }
}
