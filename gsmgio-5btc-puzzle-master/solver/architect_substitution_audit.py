"""Align the authenticated puzzle Architect text with the movie transcript."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import urllib.request

from bs4 import BeautifulSoup

from .extract import README, ROOT


RESULT_PATH = ROOT / "architect_substitution_audit.json"
SOURCE_URL = "https://www.springfieldspringfield.co.uk/movie_script.php?movie=matrix-reloaded-the"


def _words(value: str) -> list[str]:
    return re.findall(r"[A-Za-z]+", value.upper())


def _puzzle_text() -> str:
    readme = README.read_text(encoding="utf-8-sig")
    phase_start = readme.index("- phase 3.2.1")
    match = re.search(
        r"The result of decryption:\s*\n\s*```\s*(.*?)\s*```\s*\n\s*- phase 3\.2\.2",
        readme[phase_start:],
        re.DOTALL,
    )
    if match is None:
        raise ValueError("authenticated Architect plaintext block not found")
    return match.group(1)


def _source_text() -> tuple[str, str]:
    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "Mozilla/5.0"})
    html = urllib.request.urlopen(request, timeout=30).read()
    document = BeautifulSoup(html, "html.parser")
    container = document.select_one(".scrolling-script-container")
    if container is None:
        raise ValueError("movie transcript container not found")
    full = container.get_text(" ", strip=True)
    start = full.index("Your life is the sum")
    end = full.index("We won't.", start) + len("We won't.")
    return full[start:end], hashlib.sha256(html).hexdigest()


def run() -> dict[str, object]:
    puzzle_text = _puzzle_text()
    source_text, source_html_sha256 = _source_text()
    puzzle = _words(puzzle_text)
    source = _words(source_text)
    matcher = difflib.SequenceMatcher(a=source, b=puzzle, autojunk=False)
    edits: list[dict[str, object]] = []
    inserted_words: list[str] = []
    removed_words: list[str] = []
    for tag, source_start, source_end, puzzle_start, puzzle_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        source_span = source[source_start:source_end]
        puzzle_span = puzzle[puzzle_start:puzzle_end]
        edits.append({
            "operation": tag,
            "source_range": [source_start, source_end],
            "puzzle_range": [puzzle_start, puzzle_end],
            "source_words": source_span,
            "puzzle_words": puzzle_span,
        })
        removed_words.extend(source_span)
        inserted_words.extend(puzzle_span)

    result = {
        "schema": "architect-source-substitution-audit-v1",
        "source": {
            "url": SOURCE_URL,
            "retrieved_html_sha256": source_html_sha256,
            "transcript_excerpt_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            "word_count": len(source),
        },
        "puzzle": {
            "readme_sha256": hashlib.sha256(README.read_bytes()).hexdigest(),
            "plaintext_sha256": hashlib.sha256(puzzle_text.encode("utf-8")).hexdigest(),
            "word_count": len(puzzle),
        },
        "matching_word_count": sum(block.size for block in matcher.get_matching_blocks()),
        "edit_count": len(edits),
        "inserted_or_replacement_words": inserted_words,
        "removed_or_replaced_source_words": removed_words,
        "edits": edits,
        "scope_note": "SequenceMatcher identifies alignment candidates; semantic interpretation of substitutions remains a separate proof obligation.",
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({
        "source_words": output["source"]["word_count"],
        "puzzle_words": output["puzzle"]["word_count"],
        "matching_words": output["matching_word_count"],
        "edit_count": output["edit_count"],
        "inserted_or_replacement_words": output["inserted_or_replacement_words"],
    }, indent=2))
