#!/usr/bin/env python3
"""Show why the phase1verification capture says "Oops! Page Not Found".

The capture of gsmg.io/phase1verification is the Vue single-page app, not a
puzzle page. This pulls the router table and the relevant components out of
app.js to show that /phase1verification has no client-side route, so it lands on
the catch-all that renders that message for any unknown URL.
"""

import json
import re

BUNDLE = "GSMG _ GSMG_files/app.js.download"
PAGE = "GSMG _ GSMG.html"

MODULE = re.compile(r'/\*\*\*/\s*"((?:[^"\\]|\\.)+)":\s*/\*\*\*/')


def modules(source):
    """Split a webpack bundle into {module id: source}."""
    marks = [(m.start(), m.group(1)) for m in MODULE.finditer(source)]
    starts = [pos for pos, _ in marks]
    out = {}
    for index, (pos, name) in enumerate(marks):
        end = starts[index + 1] if index + 1 < len(starts) else len(source)
        out.setdefault(name, source[pos:end])
    return out


def rendered_text(html):
    body = html.split("<!-- END WAYBACK TOOLBAR INSERT -->")[-1]
    body = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", body, flags=re.I)
    text = re.sub(r"<[^>]+>", " | ", body)
    return re.sub(r"(\s*\|\s*)+", " | ", text).strip()


def main():
    html = open(PAGE, encoding="utf-8", errors="replace").read()
    source = open(BUNDLE, encoding="utf-8", errors="replace").read()

    archived = re.search(r"saved from url=\(\d+\)(\S+)", html)
    captures = re.search(r">(\d+ captures?)</a><div class=\"r\"[^>]*>([^<]+)<", html)
    print(f"archived url: {archived.group(1) if archived else '?'}")
    if captures:
        print(f"captures:     {captures.group(1)} spanning {captures.group(2)}")
    print(f"renders:      {rendered_text(html)[:120]}")

    table = source[source.find('path: "/puzzle"') - 6000 :][:9000]
    routes = re.findall(r'path:\s*"([^"]+)"[\s\S]{0,120}?name:\s*"([^"]+)"', table)
    seen, ordered = set(), []
    for path, name in routes:
        if path not in seen:
            seen.add(path)
            ordered.append((path, name))
    print("\nclient-side routes:")
    for path, name in ordered:
        print(f"  {path:<28} {name}")

    catch_all = re.search(r'path:\s*"\*",\s*component:\s*__webpack_require__\("(\w+)"\)', source)
    print(f"\ncatch-all route: path \"*\" -> module {catch_all.group(1)}")

    for path in ("/phase1verification", "/theseedisplanted"):
        print(f"  {path:<20} in route table: {path in seen}")

    mods = modules(source)
    # the catch-all component and the surviving puzzle component
    for label, module_id in (("404 component", catch_all.group(1)), ("puzzle component", "t5W0")):
        body = mods[module_id]
        template = re.search(r'__vue_template__ = __webpack_require__\("(\w+)"\)', body)
        print(f"\n{label} ({module_id}) template -> {template.group(1)}")
        text = mods[template.group(1)]
        for literal in re.findall(r'_vm\._v\("([^"]+)"\)|\$t\(\'([^\']+)\'\)|"src":"([^"]+)"', text):
            value = next(part for part in literal if part)
            print(f"    renders: {value}")

    config = json.loads(re.search(r"window\.config = (\{.*?\});", html, re.S).group(1))
    strings = config["translations"]
    print("\ntranslations for the strings on screen:")
    for key in ("page_not_found", "go_home"):
        print(f"  {key} = {strings[key]!r}")

    for needle in ("phase1verification", "theseedisplanted", "cryptologic", "MEGANIGMA"):
        print(f"\n{needle!r} occurrences in app.js: {source.count(needle)}")


if __name__ == "__main__":
    main()
