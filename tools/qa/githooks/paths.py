"""Path classes of the iOS repo, used by the git hooks (plan E, annex A7 for the product roots).

test     test sources and harness tests: a RED commit may hold only these
pin      parity/SPEC_PIN, the spec commit this repo is held to: judged by parity.py check-commit
product  everything the app is built from, plus the vendored parity files: judged by parity.py check-commit
harness  tools, Claude settings, instruction files, CI, the top-level SPEC_PIN: needs [harness-change: ...]
doc      documentation
other    anything else: treated like product (default deny)
"""
import re

CLASSES = [
    ("test", [r"^Packages/[^/]+/Tests/", r"^Tests/", r"^App/Tests/", r"^tools/qa/tests/"]),
    ("pin", [r"^parity/SPEC_PIN$"]),
    ("product", [r"^Packages/[^/]+/Sources/", r"^Packages/[^/]+/Package\.(swift|resolved)$",
                 r"^Package\.(swift|resolved)$", r"^App/", r"^Extensions/", r"^project\.yml$", r"\.xcconfig$",
                 r"\.entitlements$", r"(^|/)Info\.plist$", r"^\.xcode-version$", r"^parity/", r"\.xcstrings$"]),
    ("harness", [r"^SPEC_PIN$", r"^tools/",r"^\.claude/", r"^AGENTS\.md$", r"^CLAUDE\.md$", r"^REVIEW\.md$", r"^\.github/",
                 r"^\.gitignore$", r"^\.gitattributes$", r"^\.swift-format$", r"^\.swiftlint\.yml$"]),
    ("doc", [r"^docs/", r"\.md$", r"^LICENSE(\.|$)"]),
]
_COMPILED = [(name, [re.compile(p) for p in pats]) for name, pats in CLASSES]


def kind(path):
    for name, rxs in _COMPILED:
        if any(rx.search(path) for rx in rxs):
            return name
    return "other"
