"""Train a LightGBM multi-class classifier for ml-classifier.

Evidence-based defaults
-----------------------
Split ratio   : 80/20 stratified  (Stanford CS230, sklearn docs; >10 k samples)
CV evaluation : Stratified 5-fold (Nature NPJ 2024 — more reliable than a
                single split for imbalanced security data)
Imbalance     : SMOTE + class_weight="balanced"  (MDPI IDS 2024; combining
                over-sampling with cost-sensitive learning beats either alone)
Min class size: ≥300 samples recommended (NIH/PMC convergence study)
Normal traffic: ~25% of attack samples (CIC-IDS2017 benign fraction reference)

Two data-input modes:

  1) Auto split — pass one CSV, gets stratified 80/20 + 5-fold CV evaluation:
         python train.py --csv dataset.csv

  2) Manual split — pre-split files (no CV):
         python train.py --train-csv tr.csv --test-csv te.csv

Writes ``multi_model.pkl`` plus ``metrics.json`` / ``confusion_multi.txt``
to ``--out-dir``.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import StratifiedKFold, train_test_split

FEATURE_COLS = [
    "hour", "is_night", "day_of_week",
    "dst_port", "protocol", "source_honeypot", "event_type",
    "login_success", "duration", "login_attempts",
    "cmd_length", "special_char_cnt", "pipe_count",
    "has_wget", "has_curl", "has_reverse_shell",
]

# Evidence-based thresholds (NIH/PMC dataset size study)
_WARN_SAMPLES_PER_CLASS  = 300   # below this: warn
_MIN_SAMPLES_PER_CLASS   = 50    # below this: error (unreliable stratification)
_CV_FOLDS                = 5     # Stratified K-Fold k (sklearn / Nature NPJ best practice)


def _load(csv_path: Path) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_COLS + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV missing required columns: {missing}")
    return df[FEATURE_COLS].to_numpy(), df["label"].astype(str).to_numpy()


def _check_class_sizes(y: np.ndarray, context: str = "") -> None:
    counts = Counter(y)
    ctx = f" ({context})" if context else ""
    for label, n in counts.items():
        if n < _MIN_SAMPLES_PER_CLASS:
            raise SystemExit(
                f"Class '{label}' has only {n} samples{ctx}. "
                f"Minimum is {_MIN_SAMPLES_PER_CLASS}. "
                "Collect more data or remove this class."
            )
        if n < _WARN_SAMPLES_PER_CLASS:
            print(
                f"WARNING: class '{label}' has {n} samples{ctx} "
                f"(recommended ≥{_WARN_SAMPLES_PER_CLASS} for reliable metrics). "
                "Consider more data or using --smote."
            )
    # Print distribution summary
    total = len(y)
    print(f"Label distribution{ctx}:")
    for label, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {label:15s}  {n:>7,}  ({n/total*100:5.1f}%)")


def _apply_smote(X: np.ndarray, y: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Apply SMOTE to balance minority classes.

    Per MDPI IDS 2024 paper: combining SMOTE with class_weight="balanced"
    outperforms either technique alone on intrusion detection datasets.
    SMOTE target: all classes up-sampled to the majority class size.
    """
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        raise SystemExit(
            "imbalanced-learn not installed. "
            "Run: pip install imbalanced-learn  (or omit --smote)"
        )
    counts = Counter(y)
    # SMOTE requires at least k_neighbors+1 samples per class.
    # Use k=min(5, min_count-1) to handle small classes gracefully.
    k = min(5, min(counts.values()) - 1)
    if k < 1:
        print("WARNING: SMOTE skipped — too few samples in a class for k-neighbours")
        return X, y
    sm = SMOTE(random_state=seed, k_neighbors=k)
    X_res, y_res = sm.fit_resample(X, y)
    before = dict(Counter(y))
    after  = dict(Counter(y_res))
    added  = sum(after[c] - before.get(c, 0) for c in after)
    print(f"SMOTE: {len(y):,} → {len(y_res):,} samples (+{added:,} synthetic)")
    return X_res, y_res


def _ascii_confusion(y_true, y_pred, labels) -> str:
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    str_labels = [str(l) for l in labels]
    out = ["true \\ pred  " + " ".join(f"{l:>13}" for l in str_labels)]
    for i, l in enumerate(str_labels):
        row = " ".join(f"{cm[i][j]:>13d}" for j in range(len(labels)))
        out.append(f"{l:>13} {row}")
    return "\n".join(out)


def _build_model(params: dict):
    try:
        from lightgbm import LGBMClassifier
    except ImportError:
        raise SystemExit("LightGBM not installed (pip install lightgbm)")
    return LGBMClassifier(
        n_estimators=params["n_estimators"],
        max_depth=params["max_depth"] or -1,
        random_state=params["seed"],
        n_jobs=-1,
        class_weight="balanced",  # cost-sensitive learning (MDPI IDS 2024)
        verbose=-1,
    )


def _cv_evaluate(X: np.ndarray, y: np.ndarray, params: dict) -> dict:
    """Stratified K-Fold cross-validation for robust metric estimation.

    Nature NPJ Digital Medicine 2024: CV metrics are more reliable than a
    single split, especially for imbalanced security datasets.
    """
    skf = StratifiedKFold(n_splits=_CV_FOLDS, shuffle=True,
                          random_state=params["seed"])
    fold_acc, fold_f1 = [], []
    print(f"\nStratified {_CV_FOLDS}-Fold CV evaluation (evidence-based: Nature NPJ 2024)…")
    for fold_i, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        clf = _build_model(params)
        clf.fit(X[train_idx], y[train_idx])
        y_pred = clf.predict(X[val_idx])
        acc = accuracy_score(y[val_idx], y_pred)
        f1  = f1_score(y[val_idx], y_pred, average="macro", zero_division=0)
        fold_acc.append(acc)
        fold_f1.append(f1)
        print(f"  fold {fold_i}/{_CV_FOLDS}  acc={acc:.4f}  macro-F1={f1:.4f}")

    mean_acc = float(np.mean(fold_acc))
    std_acc  = float(np.std(fold_acc))
    mean_f1  = float(np.mean(fold_f1))
    std_f1   = float(np.std(fold_f1))
    print(f"  CV summary:  acc={mean_acc:.4f}±{std_acc:.4f}  "
          f"macro-F1={mean_f1:.4f}±{std_f1:.4f}")
    return {
        "cv_folds": _CV_FOLDS,
        "cv_acc_mean":  round(mean_acc, 4),
        "cv_acc_std":   round(std_acc, 4),
        "cv_f1_mean":   round(mean_f1, 4),
        "cv_f1_std":    round(std_f1, 4),
    }


def _train_final(X_train, y_train, X_test, y_test,
                 out_dir: Path, params: dict, cv_metrics: dict | None) -> dict:
    """Train on full train set, evaluate on held-out test set, save artefacts."""
    print("\nTraining final model on full train split…")
    t0 = time.time()
    clf = _build_model(params)
    clf.fit(X_train, y_train)
    train_sec = round(time.time() - t0, 2)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average="macro", zero_division=0)
    print(f"  hold-out test:  accuracy={acc:.4f}  macro-F1={f1:.4f}  ({train_sec}s)")

    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, out_dir / "multi_model.pkl")

    labels = sorted(set(y_test) | set(y_train))
    metrics = {
        "algorithm": "lgbm",
        "split_method": "stratified_80_20",
        "multi": {
            "accuracy":  round(acc, 4),
            "macro_f1":  round(f1, 4),
            "train_sec": train_sec,
            "labels":    labels,
            "report":    classification_report(
                y_test, y_pred, output_dict=True, zero_division=0),
        },
        "cv": cv_metrics,        # None when manual split used
        "n_train":    int(len(y_train)),
        "n_test":     int(len(y_test)),
        "n_features": len(FEATURE_COLS),
        "params":     params,
        "methodology": {
            "split_ratio":       "80/20 stratified",
            "cv_strategy":       f"stratified_{_CV_FOLDS}_fold",
            "imbalance_method":  "class_weight=balanced + optional SMOTE",
            "references": [
                "Stanford CS230 deep learning split guidelines",
                "Nature NPJ Digital Medicine 2024 (min dataset sizes)",
                "MDPI Sensors 2024 (SMOTE+class_weight for IDS)",
                "CIC-IDS2017 (benign:attack ratio reference)",
            ],
        },
    }
    (out_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False))
    (out_dir / "confusion_multi.txt").write_text(
        _ascii_confusion(y_test, y_pred, labels))

    print("\n=== Classification report (hold-out test set) ===")
    print(classification_report(y_test, y_pred, zero_division=0))
    return metrics


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv",        help="single CSV; auto stratified 80/20 split + CV")
    ap.add_argument("--train-csv",  help="pre-split training CSV (skips CV)")
    ap.add_argument("--test-csv",   help="pre-split test CSV")
    ap.add_argument("--encoders",   help="encoders.json (copied to out-dir)")
    ap.add_argument("--out-dir",    default="models")
    # Evidence-based defaults
    ap.add_argument("--test-size",  type=float, default=0.2,
                    help="hold-out fraction (default 0.2 = 80/20, CS230/sklearn)")
    ap.add_argument("--no-cv",      action="store_true",
                    help="skip k-fold CV evaluation (faster but less reliable)")
    ap.add_argument("--smote",      action="store_true",
                    help="apply SMOTE to training set before fitting "
                         "(MDPI IDS 2024: best combined with class_weight=balanced). "
                         "Requires imbalanced-learn.")
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--max-depth",    type=int, default=None)
    ap.add_argument("--seed",         type=int, default=42)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    params = {
        "n_estimators": args.n_estimators,
        "max_depth":    args.max_depth,
        "seed":         args.seed,
    }

    if args.csv:
        if args.train_csv or args.test_csv:
            raise SystemExit("Use either --csv or --train-csv/--test-csv, not both")
        X, y = _load(Path(args.csv))
        print(f"Loaded {len(y):,} samples, {len(FEATURE_COLS)} features")
        _check_class_sizes(y, "full dataset")

        # Stratified split: preserves class ratio in both halves.
        # Fallback to non-stratified only if a class is too rare to split.
        min_count = min(Counter(y).values())
        stratify = y if min_count >= 2 else None
        if stratify is None:
            print(f"NOTE: rarest class has {min_count} member(s) — "
                  "splitting without stratification")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_size, stratify=stratify,
            random_state=args.seed)
        print(f"\nStratified 80/20 split  "
              f"train={len(y_train):,}  test={len(y_test):,}")

        # Optional SMOTE on training set only (never on test set — data leakage)
        if args.smote:
            X_train, y_train = _apply_smote(X_train, y_train, args.seed)

        # Stratified K-Fold CV on the training portion for reliable estimates
        cv_metrics = None
        if not args.no_cv:
            cv_metrics = _cv_evaluate(X_train, y_train, params)

    elif args.train_csv and args.test_csv:
        X_train, y_train = _load(Path(args.train_csv))
        X_test, y_test   = _load(Path(args.test_csv))
        print(f"Manual split  train={len(y_train):,}  test={len(y_test):,}")
        _check_class_sizes(y_train, "train set")
        if args.smote:
            X_train, y_train = _apply_smote(X_train, y_train, args.seed)
        cv_metrics = None  # CV not run on pre-split data
    else:
        raise SystemExit("Provide --csv or both --train-csv and --test-csv")

    _train_final(X_train, y_train, X_test, y_test, out_dir, params, cv_metrics)
    print(f"\nSaved {out_dir / 'multi_model.pkl'}")

    if args.encoders:
        shutil.copyfile(args.encoders, out_dir / "encoders.json")
        print(f"Copied encoders → {out_dir / 'encoders.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
