#!/usr/bin/env python
"""Fine-tune an NLI entailment model for the Claim-Entailment verifier (124).

Trains a transformers sequence-classification model on (premise, hypothesis,
label) triples where label is one of {entailment, neutral, contradiction}. The
resulting checkpoint plugs straight into the verifier:

    from perathos.verifiers import ClaimEntailmentVerifier
    from perathos.verifiers_nli import nli_entailment_fn
    v = ClaimEntailmentVerifier(entailment_fn=nli_entailment_fn("path/to/checkpoint"))

Data format — JSONL, one object per line:
    {"premise": "<evidence>", "hypothesis": "<claim>", "label": "entailment"}

Requires the training extras:  pip install perathos[train]

LICENSE REMINDER (see docs/research/TRAINING_DATA.md): prefer permissive,
commercially-usable sets — FActScore (MIT), RAGTruth (MIT), DocNLI (BSD-3),
SAFE/LongFact (Apache/CC-BY). AVOID AggreFact (no LICENSE file) and the
CC-BY-NC sets (ANLI, SciFact, AVeriTeC, FELM) in any shippable model. The
FEVER family / VitaminC / SelfCheckGPT are CC-BY-SA (share-alike).

Usage:
    python scripts/train_entailment.py train.jsonl --eval eval.jsonl \
        --base microsoft/deberta-v3-base --out ./entailment-ckpt --epochs 3
    # Smoke test the harness without real training:
    python scripts/train_entailment.py train.jsonl --max-steps 2
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

LABELS = ["entailment", "neutral", "contradiction"]
LABEL2ID = {name: i for i, name in enumerate(LABELS)}


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for i, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        rec = json.loads(raw)
        if rec["label"] not in LABEL2ID:
            raise SystemExit(f"line {i}: label must be one of {LABELS}, got {rec['label']!r}")
        rows.append(rec)
    if not rows:
        raise SystemExit(f"no examples in {path}")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("train", type=Path, help="JSONL of {premise,hypothesis,label}")
    ap.add_argument("--eval", dest="eval_path", type=Path, default=None)
    ap.add_argument("--base", default="microsoft/deberta-v3-base")
    ap.add_argument("--out", type=Path, default=Path("./entailment-ckpt"))
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--max-steps", type=int, default=-1, help="cap steps (use 2 for a smoke test)")
    args = ap.parse_args()

    # Heavy imports are local so --help works without torch installed.
    import numpy as np
    import torch
    from torch.utils.data import Dataset
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    tok = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForSequenceClassification.from_pretrained(args.base, num_labels=len(LABELS))

    # If the base already has an entailment/neutral/contradiction head, REUSE its
    # label order so the pretrained head stays aligned (forcing our order would
    # scramble it and waste a short fine-tune). Otherwise install our mapping.
    cfg_l2i = {str(k).lower(): int(v) for k, v in (model.config.label2id or {}).items()}
    if set(LABELS).issubset(cfg_l2i):
        label2id = {name: cfg_l2i[name] for name in LABELS}
    else:
        label2id = dict(LABEL2ID)
        model.config.label2id = label2id
        model.config.id2label = {i: n for n, i in label2id.items()}

    class NLIDataset(Dataset):
        def __init__(self, rows):
            self.rows = rows

        def __len__(self):
            return len(self.rows)

        def __getitem__(self, idx):
            r = self.rows[idx]
            enc = tok(
                r["premise"], r["hypothesis"],
                truncation=True, max_length=args.max_length, padding="max_length",
                return_tensors="pt",
            )
            item = {k: v.squeeze(0) for k, v in enc.items()}
            item["labels"] = torch.tensor(label2id[r["label"]])
            return item

    train_ds = NLIDataset(load_jsonl(args.train))
    eval_ds = NLIDataset(load_jsonl(args.eval_path)) if args.eval_path else None

    def metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {"accuracy": float((preds == labels).mean())}

    targs = TrainingArguments(
        output_dir=str(args.out),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        max_steps=args.max_steps,
        eval_strategy="epoch" if eval_ds else "no",
        save_strategy="epoch",
        logging_steps=10,
        report_to=[],
    )
    trainer = Trainer(
        model=model, args=targs,
        train_dataset=train_ds, eval_dataset=eval_ds,
        compute_metrics=metrics if eval_ds else None,
    )
    trainer.train()
    trainer.save_model(str(args.out))
    tok.save_pretrained(str(args.out))
    print(f"saved checkpoint -> {args.out}")
    print("plug in with: nli_entailment_fn(model_name=str(out))")


if __name__ == "__main__":
    main()
