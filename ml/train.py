"""Train and evaluate the Random Forest URL classifier.

    python -m ml.train                         # synthetic dataset (default, no downloads)
    python -m ml.train --phish-csv p.csv --legit-csv l.csv   # real feeds
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from .dataset import generate_synthetic, load_csv, write_csv
from .features import FEATURE_NAMES, feature_vector

MODEL_DIR = Path(__file__).parent / "model"


def main() -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish-csv")
    ap.add_argument("--legit-csv")
    ap.add_argument("--per-class", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    if args.phish_csv and args.legit_csv:
        rows = load_csv(args.phish_csv, 1) + load_csv(args.legit_csv, 0)
        source = f"real feeds: {args.phish_csv} + {args.legit_csv}"
    else:
        rows = generate_synthetic(args.per_class, args.seed)
        source = "synthetic (locally generated, original templates)"
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        write_csv(rows, MODEL_DIR / "training_dataset.csv")

    urls = [r[0] for r in rows]
    y = np.array([r[1] for r in rows])
    X = np.array([feature_vector(u) for u in urls])
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=args.seed)

    clf = RandomForestClassifier(n_estimators=250, max_depth=18, min_samples_leaf=2, class_weight="balanced",
                                 n_jobs=-1, random_state=args.seed)
    t0 = time.time()
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    proba = clf.predict_proba(Xte)[:, 1]
    cv = cross_val_score(RandomForestClassifier(n_estimators=100, max_depth=18, class_weight="balanced",
                                                n_jobs=-1, random_state=args.seed),
                         X, y, cv=StratifiedKFold(5, shuffle=True, random_state=args.seed), scoring="f1")
    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    metrics = {
        "data_source": source, "samples": int(len(y)), "train_samples": int(len(ytr)), "test_samples": int(len(yte)),
        "accuracy": round(accuracy_score(yte, pred), 4), "precision": round(precision_score(yte, pred), 4),
        "recall": round(recall_score(yte, pred), 4), "f1": round(f1_score(yte, pred), 4),
        "roc_auc": round(roc_auc_score(yte, proba), 4),
        "false_positive_rate": round(fp / max(1, fp + tn), 4), "false_negative_rate": round(fn / max(1, fn + tp), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "cv_f1_mean": round(float(cv.mean()), 4), "cv_f1_std": round(float(cv.std()), 4),
        "feature_importance": dict(sorted(zip(FEATURE_NAMES, map(lambda v: round(float(v), 4), clf.feature_importances_)),
                                          key=lambda kv: -kv[1])),
        "trained_seconds": round(time.time() - t0, 2),
        "caveat": ("Trained on synthetic data: treat these numbers as optimistic. Retrain on real feeds before relying on them."
                   if "synthetic" in source else "Evaluated on a random 25% hold-out of the supplied feeds."),
    }
    bundle = {"model": clf, "feature_names": FEATURE_NAMES, "baseline": X[y == 0].mean(axis=0).tolist(),
              "version": time.strftime("%Y%m%d-%H%M%S")}
    joblib.dump(bundle, MODEL_DIR / "phishguard_rf.joblib", compress=3)
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps({k: v for k, v in metrics.items() if k != "feature_importance"}, indent=2))
    return metrics


if __name__ == "__main__":
    main()
