#!/usr/bin/env bash
# Reproducible self-test for bkcrack_xml_guess.py.
#
# Builds a synthetic OOXML-style ZipCrypto+Deflate encrypted archive with a
# KNOWN password, then verifies:
#   A. --reference with the exact real plaintext recovers the correct keys
#      against the Deflate-compressed [Content_Types].xml entry.
#   B. --auto-content-types recovers the same keys when the archive's real
#      content matches what that heuristic generates (mechanism-level check
#      of the auto-guess -> recompress -> attack pipeline).
#   C. --force-declaration-guess (the OLD script's core technique) does NOT
#      recover the keys within a bounded timeout, demonstrating the fix was
#      necessary.
# All recovered keys are cross-checked against ground truth derived directly
# from the known password via `bkcrack --password`.
#
# Requires: bkcrack on PATH, python3, the `zip` command (Info-Zip).
set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bkcrack_xml_guess.py"
PASSWORD="testpass123"
PER_ATTEMPT_TIMEOUT=180  # Correct Deflate guess can take 1-3 min on 2 threads depending on where
                        # in the keyspace the solution falls. Wrong guesses take even longer.
                        # Set well above the expected correct-guess time to avoid false failures.

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "== building synthetic OOXML-style archive in $WORKDIR =="
mkdir -p word docProps
echo '<w:document xmlns:w="x"><w:body/></w:document>' > word/document.xml
echo '<cp:coreProperties xmlns:cp="x"/>' > docProps/core.xml
echo '<Properties xmlns="x"/>' > docProps/app.xml

# Generate [Content_Types].xml with the SAME function the script itself uses,
# for a fixed set of entry names, so the archive's real content and the
# script's --auto-content-types guess are exactly the same bytes. This is
# a mechanism-level test of the auto-guess -> recompress -> attack pipeline,
# not a claim that real-world Office output always matches this template.
python3 - "$SCRIPT" << 'PYEOF'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("bxg", sys.argv[1])
bxg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bxg)

fake_entries = [
    bxg.EntryInfo(0, "ZipCrypto", "Deflate", "00000000", 0, 0, "[Content_Types].xml"),
    bxg.EntryInfo(1, "ZipCrypto", "Deflate", "00000000", 0, 0, "word/document.xml"),
    bxg.EntryInfo(2, "ZipCrypto", "Store",   "00000000", 0, 0, "docProps/core.xml"),
    bxg.EntryInfo(3, "ZipCrypto", "Store",   "00000000", 0, 0, "docProps/app.xml"),
]
data = bxg.build_ooxml_content_types_guess(fake_entries)
with open("[Content_Types].xml", "wb") as f:
    f.write(data)
print(f"wrote {len(data)}-byte [Content_Types].xml matching the auto-generator's own template")
PYEOF

zip -q -e -P "$PASSWORD" test.zip '[Content_Types].xml' word/document.xml docProps/core.xml docProps/app.xml
echo "archive contents:"
bkcrack -L test.zip

echo
echo "== ground truth: keys derived directly from the known password =="
TRUE_KEYS=$(bkcrack -C test.zip --password "$PASSWORD" 2>&1 | grep -oE '[0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8}')
echo "true keys: $TRUE_KEYS"
[ -n "$TRUE_KEYS" ] || { echo "FAIL: could not derive ground-truth keys"; exit 1; }

check_keys() {
  # extract "xx xx xx" style triplet from bkcrack_xml_guess.py's own summary line
  echo "$1" | grep -oE "\('[0-9a-f]{8}', '[0-9a-f]{8}', '[0-9a-f]{8}'\)" \
    | grep -oE '[0-9a-f]{8}' | tr '\n' ' ' | sed 's/ $//'
}

echo
echo "== test A: --reference with the exact real plaintext =="
cp '[Content_Types].xml' reference_exact.xml
set +e
OUT=$(timeout $((PER_ATTEMPT_TIMEOUT * 9 + 30)) python3 "$SCRIPT" test.zip 0 \
      --reference reference_exact.xml --timeout "$PER_ATTEMPT_TIMEOUT" --bkcrack bkcrack 2>&1)
RC=$?
set -e
echo "$OUT" | tail -15
FOUND=$(check_keys "$OUT")
[ $RC -eq 0 ] && [ "$FOUND" = "$TRUE_KEYS" ] \
  && echo "PASS: --reference recovered correct keys ($FOUND)" \
  || { echo "FAIL: --reference did not recover correct keys (rc=$RC, found='$FOUND', expected='$TRUE_KEYS')"; exit 1; }

echo
echo "== test B: --auto-content-types (mechanism check) =="
set +e
OUT=$(timeout $((PER_ATTEMPT_TIMEOUT * 9 + 30)) python3 "$SCRIPT" test.zip '[Content_Types].xml' \
      --auto-content-types --timeout "$PER_ATTEMPT_TIMEOUT" --bkcrack bkcrack 2>&1)
RC=$?
set -e
echo "$OUT" | tail -15
FOUND=$(check_keys "$OUT")
[ $RC -eq 0 ] && [ "$FOUND" = "$TRUE_KEYS" ] \
  && echo "PASS: --auto-content-types recovered correct keys ($FOUND)" \
  || { echo "FAIL: --auto-content-types did not recover correct keys (rc=$RC, found='$FOUND', expected='$TRUE_KEYS')"; exit 1; }

echo
echo "== test C: old technique (--force-declaration-guess) should NOT find keys within budget =="
set +e
timeout $((PER_ATTEMPT_TIMEOUT * 9 + 30)) python3 "$SCRIPT" test.zip '[Content_Types].xml' \
  --force-declaration-guess --timeout "$PER_ATTEMPT_TIMEOUT" --bkcrack bkcrack > old_out.log 2>&1
RC=$?
set -e
if grep -q "Match" old_out.log; then
  echo "UNEXPECTED: old technique found a match — investigate (this would contradict the byte-level analysis)."
  exit 1
else
  echo "PASS (expected): old isolated-guess technique found no match within the test budget,"
  echo "        consistent with the byte-level mismatch shown in the findings doc."
fi

echo
echo "All checks passed."
