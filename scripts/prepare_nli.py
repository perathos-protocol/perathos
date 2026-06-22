#!/usr/bin/env python
"""Convert a HuggingFace NLI dataset into the {premise,hypothesis,label} JSONL
that train_entailment.py / evaluate.py consume.

Default source is SNLI (labels map 1:1 to entailment/neutral/contradiction).
SNLI is CC BY-SA 4.0 — commercially usable but share-alike; for a fully
permissive shippable model use the MIT sets (FActScore, RAGTruth) per
docs/research/TRAINING_DATA.md and write your own loader for their formats.

Usage:
    pip install perathos[train]
    python scripts/prepare_nli.py --out-dir data --train 2000 --eval 600
    # -> data/train.jsonl, data/eval.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

LABELS = ["entailment", "neutral", "contradiction"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="stanfordnlp/snli", help="HF dataset id")
    ap.add_argument("--out-dir", type=Path, default=Path("data"))
    ap.add_argument("--train", type=int, default=2000, help="train examples to keep")
    ap.add_argument("--eval", dest="n_eval", type=int, default=600, help="eval examples to keep")
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()

    from datasets import load_dataset

    ds = load_dataset(args.dataset)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    def dump(split_name: str, n: int, out: Path) -> int:
        split = ds[split_name].shuffle(seed=args.seed)
        written = 0
        with out.open("w", encoding="utf-8") as fh:
            for row in split:
                lbl = row.get("label", -1)
                if lbl is None or lbl < 0 or lbl > 2:  # SNLI uses -1 for unlabeled
                    continue
                rec = {
                    "premise": row["premise"],
                    "hypothesis": row["hypothesis"],
                    "label": LABELS[lbl],
                }
                fh.write(json.dumps(rec) + "\n")
                written += 1
                if written >= n:
                    break
        return written

    n_tr = dump("train", args.train, args.out_dir / "train.jsonl")
    eval_split = "validation" if "validation" in ds else "test"
    n_ev = dump(eval_split, args.n_eval, args.out_dir / "eval.jsonl")
    print(f"wrote {n_tr} train -> {args.out_dir / 'train.jsonl'}")
    print(f"wrote {n_ev} eval  -> {args.out_dir / 'eval.jsonl'} (from '{eval_split}')")


if __name__ == "__main__":
    main()
