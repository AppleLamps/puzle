from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import time
from pathlib import Path

import requests
from requests import RequestException


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "door_probe"
PREREG = OUT / "live_probe_preregistered.json"
RESULT = OUT / "live_probe_results.json"


MASTER = ["yellowblueprimes", "matrixsumlist", "lastwordsbeforearchichoice", "yinyang"]
TOKENS = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword"]
HINTS = [
    "yellowblueprimes",
    "yellowblue",
    "blueyellow",
    "primes",
    "primenumbers",
    "primepart",
    "zeroedout",
    "zeroout",
    "characterszeroedout",
    "anotherdoor",
    "thereisanotherdoor",
    "door",
    "yinyang",
    "yingyang",
    "salphaseion",
    "salvation",
    "hashthetext",
    "ourfirsthintisyourlastcommand",
    "anstoo",
    "sha256",
    "thematrixhasyou",
]


def candidate_paths() -> list[str]:
    values: set[str] = set(MASTER + TOKENS + HINTS)
    separators = ["", "-", "_"]

    # Contiguous sequences preserve the authenticated order in the master hint.
    for start in range(len(MASTER)):
        for stop in range(start + 2, len(MASTER) + 1):
            chunk = MASTER[start:stop]
            for separator in separators:
                values.add(separator.join(chunk))

    # Pairings use only exact creator/page vocabulary; no added semantic words.
    licensed_atoms = list(dict.fromkeys(MASTER + TOKENS + HINTS))
    for left, right in itertools.combinations(licensed_atoms, 2):
        if left in MASTER or right in MASTER or left in {"anotherdoor", "thereisanotherdoor", "door"} or right in {"anotherdoor", "thereisanotherdoor", "door"}:
            values.add(left + right)

    # Exact authenticated phrases, normalized only for URL-path spelling.
    values.update(
        {
            "yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang",
            "yellow-blue-primes",
            "yellow_blue_primes",
            "lastwordsbeforearchichoiceyinyang",
            "matrixsumlistlastwordsbeforearchichoice",
            "matrixsumlistenterlastwordsbeforearchichoicethispassword",
            "thispasswordyinyang",
            "passwordinfrontofyoureyes",
            "infrontofyoureyes",
            "verylaststep",
            "truegiveaway",
        }
    )
    return ["/" + value for value in sorted(values)][:300]


def prepare() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    paths = candidate_paths()
    data = {
        "scope": "One bounded live GET probe against gsmg.io",
        "license": "Paths use only creator-authenticated/page-decoded vocabulary and normalized separators",
        "candidate_count": len(paths),
        "acceptance": "candidate response byte length AND SHA-256 differ from every app-shell baseline response",
        "controls": {
            "app_shell_baselines": [
                "/__gsmg_probe_control_a_20260804",
                "/__gsmg_probe_control_b_20260804",
                "/__gsmg_probe_control_c_20260804",
            ],
            "known_old_pages": [
                "/theseedisplanted",
                "/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself",
            ],
        },
        "candidates": paths,
    }
    encoded = (json.dumps(data, indent=2) + "\n").encode()
    PREREG.write_bytes(encoded)
    (OUT / "live_probe_preregistered.sha256").write_text(hashlib.sha256(encoded).hexdigest() + "\n")
    print(json.dumps({"candidate_count": len(paths), "sha256": hashlib.sha256(encoded).hexdigest()}))


def get(session: requests.Session, path: str) -> dict[str, object]:
    last_error = ""
    for attempt in range(1, 6):
        try:
            response = session.get("https://gsmg.io" + path, timeout=12, allow_redirects=True)
            break
        except RequestException as exc:
            last_error = repr(exc)
            time.sleep(min(2 ** attempt, 20))
    else:
        return {
            "path": path,
            "transport_error": last_error,
            "attempts": 5,
        }
    body = response.content
    return {
        "path": path,
        "status": response.status_code,
        "final_url": response.url,
        "length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "content_type": response.headers.get("content-type"),
        "title": extract_title(response.text),
        "attempts": attempt,
    }


def extract_title(text: str) -> str | None:
    lower = text.lower()
    start = lower.find("<title>")
    stop = lower.find("</title>", start + 7)
    return text[start + 7 : stop].strip() if start >= 0 and stop >= 0 else None


def run() -> None:
    prereg = json.loads(PREREG.read_text(encoding="utf-8"))
    session = requests.Session()
    session.headers.update({
        "User-Agent": "GSMG-public-door-audit/1.0 (bounded research probe)",
        "Connection": "close",
    })
    checkpoint_path = OUT / "live_probe_checkpoint.json"
    if checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        baselines = checkpoint["baselines"]
        positives = checkpoint["known_old_page_controls"]
        candidates = checkpoint["candidates"]
    else:
        baselines = []
        positives = []
        candidates = []
        for path in prereg["controls"]["app_shell_baselines"]:
            baselines.append(get(session, path))
            time.sleep(0.5)
        for path in prereg["controls"]["known_old_pages"]:
            positives.append(get(session, path))
            time.sleep(0.5)
    baseline_pairs = {(row["length"], row["sha256"]) for row in baselines}
    completed_paths = {row["path"] for row in candidates}
    batch_count = 0
    for index, path in enumerate(prereg["candidates"], 1):
        if path in completed_paths:
            continue
        if batch_count == 8:
            print(f"cooldown after {len(candidates)}/{len(prereg['candidates'])}", flush=True)
            time.sleep(45)
            batch_count = 0
        row = get(session, path)
        if "transport_error" in row:
            # A rate-limit reset is not evidence. Cool down once and retry the
            # same sealed path rather than recording it as a candidate result.
            print(f"transport cooldown at {path}", flush=True)
            time.sleep(60)
            row = get(session, path)
        if "transport_error" not in row:
            row["differs_in_length_and_hash_from_all_baselines"] = all(
                row["length"] != baseline["length"] and row["sha256"] != baseline["sha256"]
                for baseline in baselines
            )
        else:
            row["differs_in_length_and_hash_from_all_baselines"] = False
        candidates.append(row)
        (OUT / "live_probe_checkpoint.json").write_text(
            json.dumps({"baselines": baselines, "known_old_page_controls": positives, "candidates": candidates}, indent=2) + "\n",
            encoding="utf-8",
        )
        batch_count += 1
        if len(candidates) % 8 == 0:
            print(f"{len(candidates)}/{len(prereg['candidates'])}", flush=True)
        time.sleep(0.5)
    accepted = [row for row in candidates if row["differs_in_length_and_hash_from_all_baselines"]]
    output = {
        "preregistered_sha256": hashlib.sha256(PREREG.read_bytes()).hexdigest(),
        "baseline_pairs": [{"length": length, "sha256": digest} for length, digest in sorted(baseline_pairs)],
        "baselines": baselines,
        "known_old_page_controls": positives,
        "candidates_tested": len(candidates),
        "accepted_count": len(accepted),
        "accepted": accepted,
        "candidates": candidates,
    }
    RESULT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tested": len(candidates), "accepted": len(accepted), "result": str(RESULT)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["prepare", "run"])
    args = parser.parse_args()
    prepare() if args.mode == "prepare" else run()
