// GET /api/model — 현재 학습된 분류 모델 메타정보.
// 우선순위: env MODEL_METRICS_PATH 파일 → 없으면 빌드에 번들된 model-metrics.json.
// (ml-classifier training/train.py 가 출력하는 metrics.json 스키마를 그대로 읽음)

import { NextResponse } from "next/server";
import fs from "node:fs/promises";
import bundled from "@/data/model-metrics.json";

type Metrics = {
  algorithm?: string;
  split_method?: string;
  multi?: { accuracy?: number; macro_f1?: number; labels?: string[] };
  cv?: { cv_acc_mean?: number; cv_acc_std?: number; cv_f1_mean?: number };
  n_train?: number;
  n_test?: number;
  n_features?: number;
};

async function loadMetrics(): Promise<{ m: Metrics; source: string }> {
  const p = process.env.MODEL_METRICS_PATH;
  if (p) {
    try {
      const raw = await fs.readFile(p, "utf-8");
      return { m: JSON.parse(raw), source: "file" };
    } catch {
      // 파일 경로가 주어졌지만 못 읽으면 번들로 폴백
    }
  }
  return { m: bundled as Metrics, source: "bundled" };
}

const ALGO_NAMES: Record<string, string> = { lgbm: "LightGBM", xgb: "XGBoost", rf: "Random Forest" };

export async function GET() {
  try {
    const { m, source } = await loadMetrics();
    const multi = m.multi ?? {};
    const n_train = m.n_train ?? 0;
    const n_test = m.n_test ?? 0;
    return NextResponse.json({
      available: true,
      source,
      algorithm: ALGO_NAMES[m.algorithm ?? ""] ?? m.algorithm ?? "unknown",
      accuracy: multi.accuracy ?? null,
      macro_f1: multi.macro_f1 ?? null,
      cv_acc_mean: m.cv?.cv_acc_mean ?? null,
      cv_acc_std: m.cv?.cv_acc_std ?? null,
      labels: multi.labels ?? [],
      n_train,
      n_test,
      n_total: n_train + n_test,
      n_features: m.n_features ?? null,
      split_method: m.split_method ?? null,
    });
  } catch (e) {
    return NextResponse.json({ available: false, 오류: String(e) });
  }
}
