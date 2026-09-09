#!/usr/bin/env python3
"""
bkcrack_xml_guess.py — known-plaintext helper for recovering ZipCrypto internal
keys from a zip entry you suspect starts with an XML declaration.

--------------------------------------------------------------------------
REVISION NOTE (see bkcrack_xml_guess_findings.md for the full writeup)
--------------------------------------------------------------------------
The previous version of this script recompressed a short candidate string
(e.g. '<?xml version="1.0"?>') IN ISOLATION with zlib at levels 1-9 and used
the leading bytes of that as an -x known-plaintext guess, regardless of the
target entry's actual zip compression method.

That is broken in two independent ways, both confirmed empirically against a
real ZipCrypto+Deflate archive built with Info-Zip (see the findings doc):

  1. For a Deflate-compressed entry, deflate's Huffman coding depends on the
     statistics of the *entire* compressed block, not just its first few
     bytes. Compressing a 20-60 byte guess by itself produces a totally
     different bitstream than the same bytes would get as the prefix of a
     real, multi-hundred-byte XML file. In testing, the isolated-guess
     technique produced compressed bytes with ZERO relationship to the real
     ciphertext — not even a partial match — while recompressing a guess at
     the FULL content and matching zlib level reproduced the true ciphertext
     byte-for-byte and let bkcrack recover the correct keys in seconds.
  2. For a Store (uncompressed) entry, deflating the guess at all is wrong —
     the plaintext bytes ARE the guess, with no compression step.

Also fixed: the old script passed a numeric entry index straight to
bkcrack's `-c` (entry NAME) flag. bkcrack has no way to know "0" means
"the first entry" there — it looks for a file literally named "0" inside
the zip and errors with "found no entry named 0". Numeric selectors must
go through `--cipher-index` instead.

Also fixed: bkcrack requires >= 8 contiguous known plaintext bytes and does
NOT fail fast on an incorrect guess — Z-reduction "succeeds" regardless of
whether the guessed bytes are actually correct, so a wrong guess burns
through the *entire* keyspace search before concluding failure. Guess
quality matters a lot; this script validates inputs up front rather than
silently handing bkcrack bytes doomed to waste minutes of search time.

--------------------------------------------------------------------------
STRATEGY
--------------------------------------------------------------------------
The script inspects the target entry's real compression method via
`bkcrack -L` (zip central-directory metadata is never encrypted, only file
*data* is, so this is always available) and picks a technique accordingly:

  Store   -> the short XML-declaration candidates are used directly as
             plaintext (no compression). This is the reliable case from
             bkcrack's own tutorial (example/tutorial.md, spiral.svg).

  Deflate -> requires a full reference/candidate file via --reference
             that approximates the ENTIRE original plaintext, not just its
             first line. The script recompresses that whole file with raw
             deflate at levels 1-9 and feeds each result to bkcrack via
             -p/--plain-file (the same mechanism the official tutorial uses
             for its own worked example). Without --reference, the script
             refuses to just guess blindly and explains why, rather than
             reproducing the broken behavior above.

  --auto-content-types is a convenience for the common real-world case of
  attacking an OOXML (.docx/.xlsx/.pptx) package: since entry NAMES are
  visible in the zip directory without decryption, the script can build a
  best-effort [Content_Types].xml reference from the extensions and known
  part names already visible in the archive listing. This is a heuristic,
  not a guarantee — unusual parts (custom XML, embedded objects, etc.)
  need their own Override entries added by hand.

  --all: sweep every ZipCrypto entry in the archive, trying every known XML
  header variant against each (direct bytes for Store; structured OOXML part
  templates for known Deflate entry types; isolated-declaration compressed as
  a last resort if --force-declaration-guess is also given). On the first
  successful key recovery, immediately decrypts the WHOLE archive (bkcrack
  -D) and hashes every extracted file — producing a chain-of-custody manifest
  as the "prove it can be done" artifact, not just a key triple. Because
  ZipCrypto derives one internal key state per archive from the password, one
  successful entry is enough to decrypt every entry.

Usage:
    ./bkcrack_xml_guess.py                                    # prompts for archive + entry
    ./bkcrack_xml_guess.py sn.zip                              # prompts for entry only
    ./bkcrack_xml_guess.py sn.zip 0                             # no prompts, stored entry
    ./bkcrack_xml_guess.py sn.zip 0 --reference guess.xml       # deflate entry, explicit guess
    ./bkcrack_xml_guess.py sn.zip '[Content_Types].xml' --auto-content-types
    ./bkcrack_xml_guess.py sn.zip --all                         # sweep every entry, every header variant
    ./bkcrack_xml_guess.py sn.zip --all --extract-dir ./proof   # also specify where to land files
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib

# ---------------------------------------------------------------------------
# Known XML declaration variants to try.
# Broad-but-bounded: encoding, standalone, quote style, line ending, version.
# Each wrong guess against a Deflate entry costs real time (bkcrack does not
# fail fast — see REVISION NOTE), so for Deflate these are used as FULL FILE
# content only for very short entries; for Store entries they are all tried
# directly as plaintext.
# ---------------------------------------------------------------------------
CANDIDATES = [
    # bare declaration, no encoding/standalone
    '<?xml version="1.0"?>',
    "<?xml version='1.0'?>",
    '<?xml version="1.0"?>\n',
    '<?xml version="1.0"?>\r\n',
    '<?xml version="1.1"?>',
    '<?xml version="1.1"?>\r\n',
    # UTF-8
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<?xml version="1.0" encoding="utf-8"?>',
    "<?xml version='1.0' encoding='UTF-8'?>",
    '<?xml version="1.0" encoding="UTF-8"?>\n',
    '<?xml version="1.0" encoding="UTF-8"?>\r\n',
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n',
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n',
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\r\n',
    "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>",
    "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\r\n",
    '<?xml version="1.1" encoding="UTF-8" standalone="yes"?>',
    '<?xml version="1.1" encoding="UTF-8" standalone="yes"?>\r\n',
    # other common encodings
    '<?xml version="1.0" encoding="ISO-8859-1"?>',
    '<?xml version="1.0" encoding="ISO-8859-1"?>\r\n',
    '<?xml version="1.0" encoding="iso-8859-1"?>',
    '<?xml version="1.0" encoding="US-ASCII"?>',
    '<?xml version="1.0" encoding="Windows-1252"?>',
    '<?xml version="1.0" encoding="UTF-16"?>',
    # LibreOffice sometimes writes no standalone attribute
    '<?xml version="1.0" encoding="UTF-8" ?>',
    '<?xml version="1.0" encoding="UTF-8" ?>\r\n',
    # XHTML-style
    '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE',
]


def candidate_byte_variants():
    """Yield (label, bytes) for every candidate, including a UTF-8-BOM-prefixed
    variant of each — BOM'd XML declarations are common enough in the wild
    (Windows-authored files especially) to be worth trying by default."""
    for c in CANDIDATES:
        raw = c.encode("utf-8")
        yield c, raw
        yield f"BOM+{c}", b"\xef\xbb\xbf" + raw


MIN_PLAINTEXT_BYTES = 8  # bkcrack's hard minimum (empirically confirmed); recommend >=12

LIST_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]{8})\s+(\d+)\s+(\d+)\s+(.*\S)\s*$"
)
KEYS_RE = re.compile(r"\b([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\b")


class EntryInfo:
    def __init__(self, index, encryption, compression, crc32, uncompressed, packed, name):
        self.index = int(index)
        self.encryption = encryption
        self.compression = compression
        self.crc32 = crc32
        self.uncompressed = int(uncompressed)
        self.packed = int(packed)
        self.name = name


def require_bkcrack(bkcrack_bin):
    if shutil.which(bkcrack_bin) is None and not os.path.isfile(bkcrack_bin):
        sys.exit(
            f"error: '{bkcrack_bin}' not found on PATH.\n"
            f"Build it (see ~/tools/bkcrack if you have the source cloned, or\n"
            f"https://github.com/kimci86/bkcrack) or pass --bkcrack /path/to/bkcrack."
        )


def list_entries(bkcrack_bin, archive):
    result = subprocess.run([bkcrack_bin, "-L", archive], capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"error listing '{archive}':\n{result.stdout}{result.stderr}")
    entries = []
    for line in result.stdout.splitlines():
        m = LIST_ROW_RE.match(line)
        if m:
            entries.append(EntryInfo(*m.groups()))
    if not entries:
        sys.exit(f"error: could not parse any entries from 'bkcrack -L {archive}'. Raw output:\n{result.stdout}")
    return entries


def resolve_entry(entries, selector):
    if selector.isdigit():
        idx = int(selector)
        for e in entries:
            if e.index == idx:
                return e
        sys.exit(f"error: no entry at index {idx} (archive has {len(entries)} entries, indices 0..{len(entries)-1})")
    for e in entries:
        if e.name == selector:
            return e
    sys.exit(f"error: no entry named {selector!r} in archive")


def deflate_raw(data: bytes, level: int) -> bytes:
    co = zlib.compressobj(level, zlib.DEFLATED, -15)  # -15 = raw deflate, no zlib/gzip header
    return co.compress(data) + co.flush()


def cipher_selector_args(entry):
    return ["--cipher-index", str(entry.index)]


def _as_text(x):
    if x is None:
        return ""
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else x


def run_bkcrack_plain_file(bkcrack_bin, archive, entry, plaintext_bytes, offset, extra_args, jobs, timeout):
    """Feed plaintext_bytes to bkcrack -p and return (found, keys_tuple, raw_output)."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        tf.write(plaintext_bytes)
        plain_path = tf.name
    try:
        cmd = [bkcrack_bin, "-C", archive] + cipher_selector_args(entry) + ["-p", plain_path]
        if offset:
            cmd += ["-o", str(offset)]
        if jobs:
            cmd += ["-j", str(jobs)]
        cmd += extra_args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            return False, None, _as_text(e.stdout) + _as_text(e.stderr) + (
                f"\n[timed out after {timeout}s — bkcrack does not fail fast on a wrong guess; "
                f"a timeout here is NOT evidence the guess is wrong, just inconclusive within the budget]"
            )
        out = result.stdout + result.stderr
        found = "Found a solution" in out or bool(re.search(r"^Keys$", out, re.MULTILINE))
        keys = None
        if found:
            km = KEYS_RE.search(out.split("Found a solution")[-1] if "Found a solution" in out else out)
            if km:
                keys = km.groups()
        return found, keys, out
    finally:
        os.unlink(plain_path)


def unique_deflate_variants(data: bytes):
    """(level, compressed_bytes) for levels 1-9, deduped — several levels
    routinely collapse to identical output for small/medium inputs."""
    seen = set()
    out = []
    for level in range(1, 10):
        compressed = deflate_raw(data, level)
        if compressed in seen:
            continue
        seen.add(compressed)
        out.append((level, compressed))
    return out


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# OOXML plaintext templates
# ---------------------------------------------------------------------------

def build_ooxml_content_types_guess(entries):
    """
    Best-effort reconstruction of [Content_Types].xml from entry names alone
    (visible in the unencrypted zip directory). Covers the common OOXML
    parts; unusual packages (custom XML parts, embedded objects/OLE, custom
    headers/footers with non-default IDs, etc.) will need manual Override
    entries added on top of this.
    """
    exts = sorted({e.name.rsplit(".", 1)[-1].lower() for e in entries if "." in e.name})
    names = {e.name for e in entries}

    default_ct = {
        "rels": "application/vnd.openxmlformats-package.relationships+xml",
        "xml": "application/xml",
        "jpeg": "image/jpeg",
        "jpg": "image/jpeg",
        "png": "image/png",
        "gif": "image/gif",
        "emf": "image/x-emf",
        "wmf": "image/x-wmf",
        "bin": "application/vnd.openxmlformats-officedocument.oleObject",
    }
    overrides = {
        "word/document.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        "xl/workbook.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        "ppt/presentation.xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
        "docProps/core.xml": "application/vnd.openxmlformats-package.core-properties+xml",
        "docProps/app.xml": "application/vnd.openxmlformats-officedocument.extended-properties+xml",
        "docProps/custom.xml": "application/vnd.openxmlformats-officedocument.custom-properties+xml",
    }

    defaults_xml = "".join(
        f'<Default Extension="{ext}" ContentType="{default_ct[ext]}"/>'
        for ext in exts if ext in default_ct
    )
    overrides_xml = "".join(
        f'<Override PartName="/{name}" ContentType="{ct}"/>'
        for name, ct in overrides.items() if name in names
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f"{defaults_xml}{overrides_xml}</Types>"
    ).encode()


def build_rels_templates(entry, all_entries):
    """
    Generate candidate full-content bytes for any .rels relationship file.
    Uses visible entry names to pick the right relationship targets.
    Returns list of (label, bytes).
    """
    templates = []
    names = {e.name for e in all_entries}
    REL_NS = 'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"'
    OD = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
    DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'

    def _rels_xml(*rels):
        inner = "".join(
            f'<Relationship Id="rId{i+1}" Type="{t}" Target="{tgt}"/>'
            for i, (t, tgt) in enumerate(rels)
        )
        return (DECL + f'<Relationships {REL_NS}>{inner}</Relationships>').encode()

    entry_name = entry.name

    # Root _rels/.rels — points to main document + optional core/app
    if entry_name == "_rels/.rels":
        core_rel = (f"{PKG}/metadata/core-properties", "docProps/core.xml")
        app_rel  = (f"{OD}/extended-properties", "docProps/app.xml")

        if any("word/" in n for n in names) or "word/document.xml" in names:
            rels = [(f"{OD}/officeDocument", "word/document.xml")]
            if "docProps/core.xml" in names: rels.append(core_rel)
            if "docProps/app.xml" in names:  rels.append(app_rel)
            templates.append(("rels-root-docx", _rels_xml(*rels)))

        if any("xl/" in n for n in names) or "xl/workbook.xml" in names:
            rels = [(f"{OD}/officeDocument", "xl/workbook.xml")]
            if "docProps/core.xml" in names: rels.append(core_rel)
            if "docProps/app.xml" in names:  rels.append(app_rel)
            templates.append(("rels-root-xlsx", _rels_xml(*rels)))

        if any("ppt/" in n for n in names) or "ppt/presentation.xml" in names:
            rels = [(f"{OD}/officeDocument", "ppt/presentation.xml")]
            if "docProps/core.xml" in names: rels.append(core_rel)
            if "docProps/app.xml" in names:  rels.append(app_rel)
            templates.append(("rels-root-pptx", _rels_xml(*rels)))

        # Minimal root rels (core + app only, no main document — unusual but possible)
        min_rels = []
        if "docProps/core.xml" in names: min_rels.append(core_rel)
        if "docProps/app.xml" in names:  min_rels.append(app_rel)
        if min_rels:
            templates.append(("rels-root-minimal", _rels_xml(*min_rels)))

    # word/_rels/document.xml.rels
    elif "word/_rels/document.xml.rels" == entry_name or entry_name.endswith("/_rels/document.xml.rels"):
        WML = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/wordprocessingml"
        rels = [(f"{OD}/styles", "styles.xml")]
        if "word/settings.xml" in names:     rels.append((f"{OD}/settings",    "settings.xml"))
        if "word/webSettings.xml" in names:  rels.append((f"{OD}/webSettings", "webSettings.xml"))
        if "word/fontTable.xml" in names:    rels.append((f"{OD}/fontTable",   "fontTable.xml"))
        if "word/theme/theme1.xml" in names: rels.append((f"{OD}/theme",       "theme/theme1.xml"))
        templates.append(("rels-document-word", _rels_xml(*rels)))

    # xl/_rels/workbook.xml.rels
    elif entry_name.endswith("/_rels/workbook.xml.rels") or entry_name == "xl/_rels/workbook.xml.rels":
        rels = [(f"{OD}/styles", "styles.xml")]
        # Add sheet relationships for visible sheets
        sheet_idx = 1
        for n in names:
            if re.match(r"xl/worksheets/sheet\d+\.xml", n):
                rels.insert(0, (f"{OD}/worksheet", f"worksheets/sheet{sheet_idx}.xml"))
                sheet_idx += 1
        if "xl/sharedStrings.xml" in names:
            rels.append((f"{OD}/sharedStrings", "sharedStrings.xml"))
        templates.append(("rels-workbook-xl", _rels_xml(*rels)))

    # Generic .rels fallback for any unrecognized relationship file
    else:
        # Empty relationships (sometimes used for stub parts)
        templates.append(("rels-empty", (
            DECL + f'<Relationships {REL_NS}/>'
        ).encode()))
        # Single self-pointing style relationship
        templates.append(("rels-styles-only", _rels_xml((f"{OD}/styles", "styles.xml"))))

    return templates


def build_core_xml_templates():
    """Candidate full-content bytes for docProps/core.xml (core properties)."""
    CPNS  = 'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
    DCNS  = 'xmlns:dc="http://purl.org/dc/elements/1.1/"'
    DCTERMS = 'xmlns:dcterms="http://purl.org/dc/terms/"'
    XSI   = 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    DECL  = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'

    templates = []

    # Minimal: empty creator + lastModifiedBy (common MS Office output)
    templates.append(("core-minimal-empty", (
        DECL +
        f'<cp:coreProperties {CPNS} {DCNS} {DCTERMS} {XSI}>'
        '<dc:creator></dc:creator>'
        '<cp:lastModifiedBy></cp:lastModifiedBy>'
        '</cp:coreProperties>'
    ).encode()))

    # Slightly fuller: adds revision and dates (xsi:type needed for dates)
    templates.append(("core-with-revision", (
        DECL +
        f'<cp:coreProperties {CPNS} {DCNS} {DCTERMS} {XSI}>'
        '<dc:creator></dc:creator>'
        '<cp:lastModifiedBy></cp:lastModifiedBy>'
        '<cp:revision>1</cp:revision>'
        '</cp:coreProperties>'
    ).encode()))

    # LibreOffice style (no standalone, different attribute order)
    DECL_LO = '<?xml version="1.0" encoding="UTF-8"?>\n'
    templates.append(("core-libreoffice", (
        DECL_LO +
        f'<cp:coreProperties {CPNS} {DCNS} {DCTERMS} {XSI}>'
        '<dc:title></dc:title>'
        '<dc:subject></dc:subject>'
        '<dc:creator></dc:creator>'
        '<dc:description></dc:description>'
        '<cp:lastModifiedBy></cp:lastModifiedBy>'
        '<cp:revision>1</cp:revision>'
        '</cp:coreProperties>'
    ).encode()))

    return templates


def build_app_xml_templates():
    """Candidate full-content bytes for docProps/app.xml (extended properties)."""
    NS = 'xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"'
    DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'

    templates = []
    for (label, app_name) in [
        ("app-word",        "Microsoft Office Word"),
        ("app-excel",       "Microsoft Excel"),
        ("app-ppt",         "Microsoft Office PowerPoint"),
        ("app-word-2016",   "Microsoft Office Word 2016"),
        ("app-libreoffice", "LibreOffice"),
        ("app-google-docs", "Google Docs"),
    ]:
        templates.append((label, (
            DECL +
            f'<Properties {NS}>'
            f'<Application>{app_name}</Application>'
            '</Properties>'
        ).encode()))

    return templates


def get_xml_templates_for_entry(entry, all_entries):
    """
    Return list of (label, full_content_bytes) guesses for a Deflate-compressed
    entry, ordered from most-specific to least-specific.

    For known OOXML part names, returns structured template(s) with the correct
    namespace and element layout — these are the guesses that can actually produce
    matching Deflate output. For unrecognised names, falls back to declaration-
    only bytes (which can only match if the entire entry IS just a declaration,
    e.g. very short placeholder XML).
    """
    name_lower = entry.name.lower()
    templates = []

    # --- Specific OOXML entry types ---
    if name_lower == "[content_types].xml":
        templates.append(("auto-content-types", build_ooxml_content_types_guess(all_entries)))

    if name_lower.endswith(".rels"):
        templates.extend(build_rels_templates(entry, all_entries))

    if name_lower in ("docprops/core.xml",) or name_lower.endswith("/core.xml"):
        templates.extend(build_core_xml_templates())

    if name_lower in ("docprops/app.xml",) or name_lower.endswith("/app.xml"):
        templates.extend(build_app_xml_templates())

    # --- Declaration-only as full content (only plausible for very small entries) ---
    # For Deflate, the declaration compressed in isolation rarely matches anything
    # in a real file — include only for entries small enough that the declaration
    # IS a plausible full content (≤200 bytes uncompressed leaves some room for
    # a root element after the declaration).
    if entry.uncompressed <= 200 or not templates:
        for label, decl_bytes in candidate_byte_variants():
            templates.append((f"decl-fullcontent:{label}", decl_bytes))

    return templates


# ---------------------------------------------------------------------------
# Core attack + extraction
# ---------------------------------------------------------------------------

def sweep_entry_xml(bkcrack_bin, archive, entry, all_entries,
                    extra_args, jobs, timeout, byte_limit,
                    force_decl_deflate=False, verbose=False):
    """
    Try every XML plaintext variant against one ZipCrypto entry.

    For Store entries: try each candidate declaration as raw bytes (capped to
    byte_limit) — this is reliable.

    For Deflate entries: try full-content templates for known OOXML part types
    (each at zlib levels 1-9), then optionally try isolated-declaration-compressed
    variants if force_decl_deflate is set (documented long shot — see REVISION
    NOTE).

    Returns (found:bool, keys:tuple|None, evidence:dict|None).
    """
    is_store   = entry.compression.lower() == "store"
    is_deflate = entry.compression.lower() == "deflate"

    if not is_store and not is_deflate:
        print(f"    [skip] unsupported compression {entry.compression!r}")
        return False, None, None

    if is_store:
        variants = list(candidate_byte_variants())
        print(f"    [Store] {len(variants)} declaration variants as raw plaintext ...")
        for label, decl_bytes in variants:
            data = decl_bytes[:byte_limit]
            if len(data) < MIN_PLAINTEXT_BYTES:
                continue
            if verbose:
                print(f"      trying {label!r} ({len(data)} bytes)")
            found, keys, out = run_bkcrack_plain_file(
                bkcrack_bin, archive, entry, data, 0, extra_args, jobs, timeout
            )
            if found:
                return True, keys, {"successful_candidate": label, "successful_level": None,
                                    "successful_compression": "store"}
        return False, None, None

    # Deflate path
    templates = get_xml_templates_for_entry(entry, all_entries)
    n_unique = sum(len(unique_deflate_variants(t)) for _, t in templates)
    print(f"    [Deflate] {len(templates)} template(s), ~{n_unique} unique compressed variants ...")

    attempt_n = 0
    for label, tmpl_bytes in templates:
        variants = unique_deflate_variants(tmpl_bytes)
        for level, compressed in variants:
            if len(compressed) < MIN_PLAINTEXT_BYTES:
                continue
            attempt_n += 1
            if verbose:
                print(f"      [{attempt_n}] {label!r} level={level} ({len(compressed)} B) "
                      f"leading={compressed[:8].hex()}")
            found, keys, out = run_bkcrack_plain_file(
                bkcrack_bin, archive, entry, compressed, 0, extra_args, jobs, timeout
            )
            if "[timed out" in out:
                print(f"      [{attempt_n}] {label!r} lv={level} → timed out (inconclusive — "
                      f"bkcrack does not fail fast; increase --timeout if this happens on the correct guess)")
            if found:
                return True, keys, {"successful_candidate": label, "successful_level": level,
                                    "successful_compression": "deflate"}

    if force_decl_deflate:
        decl_variants = list(candidate_byte_variants())
        print(f"    [Deflate, LAST RESORT] {len(decl_variants)} declaration candidates "
              f"compressed in isolation (unreliable for realistic files) ...")
        for label, decl_bytes in decl_variants:
            for level, compressed in unique_deflate_variants(decl_bytes):
                if len(compressed) < MIN_PLAINTEXT_BYTES:
                    continue
                attempt_n += 1
                found, keys, out = run_bkcrack_plain_file(
                    bkcrack_bin, archive, entry, compressed, 0, extra_args, jobs, timeout
                )
                if "[timed out" in out:
                    print(f"      [{attempt_n}] isolated-decl:{label!r} lv={level} → timed out")
                if found:
                    return True, keys, {"successful_candidate": f"isolated-decl:{label}",
                                        "successful_level": level,
                                        "successful_compression": "deflate-isolated-UNRELIABLE"}

    return False, None, None


def prove_extraction(bkcrack_bin, archive, keys, extract_dir, evidence):
    """
    Given recovered internal keys, decrypt the WHOLE archive (bkcrack -D),
    unzip the result (no password needed after decryption), and hash every
    extracted file. Writes a manifest.json with method, timing, and SHA-256
    hashes for chain-of-custody / auditability.

    Note: the recovered keys are bkcrack's INTERNAL ZipCrypto key representation,
    not the original password. Handle as engagement evidence per your scope's
    data-handling requirements.

    Returns (manifest_dict, error_str). On success, error_str is None.
    """
    os.makedirs(extract_dir, exist_ok=True)
    decrypted_zip = os.path.join(extract_dir, "decrypted.zip")
    files_dir = os.path.join(extract_dir, "files")

    # Step 1: decrypt whole archive
    cmd = [bkcrack_bin, "-C", archive, "-k", keys[0], keys[1], keys[2], "-D", decrypted_zip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or not os.path.isfile(decrypted_zip):
        return None, (
            "bkcrack recovered keys but the -D (decrypt whole archive) step failed:\n"
            + result.stdout + result.stderr
        )

    # Step 2: unzip the now-unencrypted archive
    os.makedirs(files_dir, exist_ok=True)
    extracted = []
    try:
        with zipfile.ZipFile(decrypted_zip) as zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                try:
                    zf.extract(zi, files_dir)
                    full_path = os.path.join(files_dir, zi.filename)
                    extracted.append({
                        "name": zi.filename,
                        "size_bytes": zi.file_size,
                        "sha256": sha256_file(full_path),
                    })
                except Exception as ex:
                    extracted.append({"name": zi.filename, "extract_error": str(ex)})
    except zipfile.BadZipFile as ex:
        return None, f"decrypted.zip is not a valid zip (wrong keys?): {ex}"

    manifest = {
        "source_archive": os.path.abspath(archive),
        "source_archive_sha256": sha256_file(archive),
        "retrieval_time_utc": evidence.get("retrieval_time_utc", datetime.datetime.utcnow().isoformat() + "Z"),
        "method": "bkcrack known-plaintext attack (Biham-Kocher), ZipCrypto internal key recovery",
        "successful_entry": evidence.get("successful_entry"),
        "successful_candidate": evidence.get("successful_candidate"),
        "successful_level": evidence.get("successful_level"),
        "successful_compression": evidence.get("successful_compression"),
        "recovered_internal_keys": list(keys),
        "key_note": (
            "These are bkcrack's internal ZipCrypto key representation (three 32-bit values), "
            "NOT the original password. One key set decrypts the entire archive. "
            "Handle as engagement evidence per your scope's data-handling requirements."
        ),
        "decrypted_archive": os.path.abspath(decrypted_zip),
        "decrypted_archive_sha256": sha256_file(decrypted_zip),
        "extracted_files": extracted,
    }
    manifest_path = os.path.join(extract_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    manifest["_manifest_path"] = manifest_path
    return manifest, None


# ---------------------------------------------------------------------------
# Interactive prompts (single-entry mode)
# ---------------------------------------------------------------------------

def prompt_archive():
    while True:
        path = input("Path to zip archive: ").strip()
        if os.path.isfile(path):
            return path
        print(f"  '{path}' not found — try again.")


def prompt_entry(bkcrack_bin, archive):
    entries = list_entries(bkcrack_bin, archive)
    print(f"{'Index':>5} {'Enc':>10} {'Comp':>11} {'Uncomp':>12} {'Packed':>8}  Name")
    for e in entries:
        print(f"{e.index:>5} {e.encryption:>10} {e.compression:>11} {e.uncompressed:>12} {e.packed:>8}  {e.name}")
    return input("File name (or index) inside the zip to target: ").strip()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("archive", nargs="?", help="zip file (prompted if omitted)")
    ap.add_argument("entry", nargs="?", help="entry name or index (prompted if omitted; not used with --all)")
    ap.add_argument("--offset", type=int, default=0,
                    help="known-plaintext offset relative to ciphertext start (default 0)")
    ap.add_argument("--bytes", type=int, default=16,
                    help=f"max leading bytes from each declaration candidate (Store entries only, "
                         f"default 16, minimum {MIN_PLAINTEXT_BYTES})")
    ap.add_argument("--reference", metavar="FILE",
                    help="full-content plaintext guess file, required for a Deflate-compressed "
                         "entry in single-entry mode")
    ap.add_argument("--auto-content-types", action="store_true",
                    help="build --reference automatically for an OOXML [Content_Types].xml entry "
                         "from the archive's own entry names (single-entry mode)")
    ap.add_argument("--all", action="store_true",
                    help="sweep EVERY ZipCrypto entry with every known XML header variant; "
                         "on first key recovery, prove extraction by decrypting the whole archive "
                         "and hashing all files")
    ap.add_argument("--extract-dir", metavar="DIR",
                    help="where to write the decrypted archive + extracted files on success "
                         "(default: <archive_basename>_extracted/ next to the archive)")
    ap.add_argument("--force-declaration-guess", action="store_true",
                    help="for Deflate entries, also try isolated short declaration bytes compressed "
                         "(empirically unreliable for realistic files — last resort only)")
    ap.add_argument("--bkcrack", default="bkcrack",
                    help="path to the bkcrack binary (default: 'bkcrack' on PATH)")
    ap.add_argument("--jobs", type=int, default=None,
                    help="passed through to bkcrack -j (number of parallel threads)")
    ap.add_argument("--timeout", type=int, default=None,
                    help="per-attempt timeout in seconds (bkcrack never fails fast on wrong guesses — "
                         "a timeout is inconclusive, not a rejection)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each individual attempt as it runs")
    ap.add_argument("--exhaustive", action="store_true",
                    help="passed through to bkcrack -e (exhaustive search — slower but finds all solutions)")
    args = ap.parse_args()

    require_bkcrack(args.bkcrack)

    if args.bytes < MIN_PLAINTEXT_BYTES:
        sys.exit(f"error: --bytes must be >= {MIN_PLAINTEXT_BYTES} (bkcrack's hard minimum)")

    archive = args.archive if args.archive and os.path.isfile(args.archive) else prompt_archive()
    entries = list_entries(args.bkcrack, archive)

    extra = []
    if args.exhaustive:
        extra += ["-e"]

    extract_dir = args.extract_dir or (
        os.path.join(os.path.dirname(os.path.abspath(archive)),
                     os.path.splitext(os.path.basename(archive))[0] + "_extracted")
    )

    # ===========================================================================
    # --all mode: sweep every ZipCrypto entry
    # ===========================================================================
    if args.all:
        zipcrypto_entries = [
            e for e in entries
            if e.encryption.lower() in ("zipcrypto", "pkware", "traditional pkware")
        ]
        if not zipcrypto_entries:
            sys.exit("No ZipCrypto-encrypted entries found in archive.")

        print(f"Archive: {archive}")
        print(f"Sweeping {len(zipcrypto_entries)} ZipCrypto entry/entries with all XML header variants.")
        if args.timeout:
            print(f"Per-attempt timeout: {args.timeout}s")
            if args.timeout < 180:
                print(f"  WARNING: timeout < 180s may kill correct guesses before bkcrack finishes.")
                print(f"  A correct Deflate guess typically takes 1-3 minutes on 2 threads depending on")
                print(f"  hardware and where in the keyspace the correct solution falls (bkcrack checks")
                print(f"  ~36 000 Z values sequentially; solution may appear at 1% or 99% of those).")
                print(f"  Wrong guesses take the full keyspace before concluding failure — even longer.")
                print(f"  Recommended: --timeout 300 --jobs <nproc> for a usable sweep.")
        else:
            print("Per-attempt timeout: none (each wrong guess may run many minutes — "
                  "use --timeout 300 --jobs <nproc> to bound the search)")
        print(f"Output directory on success: {extract_dir}")
        print()

        retrieval_time = datetime.datetime.utcnow().isoformat() + "Z"

        for entry in zipcrypto_entries:
            print(f"[entry {entry.index}] {entry.name!r}  "
                  f"({entry.compression}, {entry.uncompressed} B uncompressed / {entry.packed} B packed)")

            found, keys, evidence = sweep_entry_xml(
                args.bkcrack, archive, entry, entries,
                extra, args.jobs, args.timeout, args.bytes,
                force_decl_deflate=args.force_declaration_guess,
                verbose=args.verbose,
            )

            if found and keys:
                print(f"\n{'='*60}")
                print(f"*** KEY RECOVERY SUCCESS ***")
                print(f"Entry   : [{entry.index}] {entry.name!r}")
                print(f"Keys    : {keys[0]} {keys[1]} {keys[2]}")
                print(f"Method  : {evidence.get('successful_candidate')!r}  "
                      f"zlib-level={evidence.get('successful_level')}  "
                      f"comp={evidence.get('successful_compression')}")
                print(f"{'='*60}")
                print()
                print(f"Decrypting full archive and extracting to: {extract_dir}")

                evidence["successful_entry"] = entry.name
                evidence["retrieval_time_utc"] = retrieval_time

                manifest, err = prove_extraction(args.bkcrack, archive, keys, extract_dir, evidence)
                if err:
                    print(f"\nerror during extraction: {err}")
                    print(f"\nKeys are valid — you can decrypt manually:")
                    print(f"  bkcrack -C {archive} -k {keys[0]} {keys[1]} {keys[2]} -D decrypted.zip")
                    sys.exit(1)

                print(f"\n{'='*60}")
                print(f"EXTRACTION PROOF")
                print(f"{'='*60}")
                print(f"decrypted archive : {manifest['decrypted_archive']}")
                print(f"  sha256          : {manifest['decrypted_archive_sha256']}")
                print(f"source archive    : {manifest['source_archive']}")
                print(f"  sha256          : {manifest['source_archive_sha256']}")
                print(f"manifest          : {manifest['_manifest_path']}")
                print(f"\nExtracted {len(manifest['extracted_files'])} file(s):")
                for fi in manifest["extracted_files"]:
                    if "sha256" in fi:
                        print(f"  {fi['name']}  [{fi['size_bytes']} B]  sha256={fi['sha256']}")
                    else:
                        print(f"  {fi['name']}  [extract error: {fi.get('extract_error')}]")
                print()
                print(f"Summary tuple for reporting:")
                print(f"  keys={keys[0]} {keys[1]} {keys[2]}")
                sys.exit(0)

            print(f"    no match for entry {entry.index}\n")

        print("No match found for any ZipCrypto entry after sweeping all XML variants.")
        print()
        print("Next steps:")
        print("  1. If the files are not OOXML, try --reference with a known plaintext sample")
        print("     from the same application/version that produced the zip.")
        print("  2. If the entries are Deflate-compressed, you need a full file template that")
        print("     matches byte-for-byte; partial matches don't work under Deflate.")
        print("  3. Add --force-declaration-guess to also try isolated short declarations against")
        print("     Deflate entries (low probability, but worth trying if nothing else is available).")
        sys.exit(1)

    # ===========================================================================
    # Single-entry mode (original behaviour, preserved)
    # ===========================================================================
    entry_selector = args.entry if args.entry else prompt_entry(args.bkcrack, archive)
    entry = resolve_entry(entries, entry_selector)

    print(f"target entry [{entry.index}] {entry.name!r}: {entry.compression}, "
          f"{entry.uncompressed} bytes uncompressed / {entry.packed} bytes packed")

    is_store   = entry.compression.lower() == "store"
    is_deflate = entry.compression.lower() == "deflate"

    if not is_store and not is_deflate:
        sys.exit(f"error: unsupported compression method {entry.compression!r} — this script only "
                  f"handles Store and Deflate.")

    if args.auto_content_types and not args.reference:
        guess = build_ooxml_content_types_guess(entries)
        tf_path = os.path.join(tempfile.gettempdir(), "auto_content_types_guess.xml")
        with open(tf_path, "wb") as f:
            f.write(guess)
        print(f"[auto-content-types] wrote best-effort guess ({len(guess)} bytes) to {tf_path}")
        print("  NOTE: this is a heuristic from visible entry names/extensions only.")
        args.reference = tf_path

    if is_store:
        print("\n[Store entry] plaintext == ciphertext bytes directly, no compression step needed.")
        tried = 0
        for label, raw in candidate_byte_variants():
            data = raw[: args.bytes] if len(raw) >= args.bytes else raw
            if len(data) < MIN_PLAINTEXT_BYTES:
                continue
            tried += 1
            print(f"\n[{tried}] plaintext={label!r} ({len(data)} bytes)")
            found, keys, out = run_bkcrack_plain_file(
                args.bkcrack, archive, entry, data, args.offset, extra, args.jobs, args.timeout
            )
            print(out.strip().splitlines()[-1] if out.strip() else "(no output)")
            if found:
                print(f"\n*** Match — recovered keys: {keys} ***")
                print(f"    plaintext used: {label!r}")
                sys.exit(0)
        print(f"\nNo match after {tried} attempt(s).")
        sys.exit(1)

    # Deflate entry — single-entry mode
    if args.reference:
        with open(args.reference, "rb") as f:
            ref_data = f.read()
        print(f"\n[Deflate entry] recompressing full reference ({len(ref_data)} bytes) at levels 1-9 ...")
        tried = 0
        for level, compressed in unique_deflate_variants(ref_data):
            if len(compressed) < MIN_PLAINTEXT_BYTES:
                continue
            tried += 1
            print(f"\n[{tried}] level={level} recompressed_len={len(compressed)} "
                  f"leading_hex={compressed[:16].hex()}")
            found, keys, out = run_bkcrack_plain_file(
                args.bkcrack, archive, entry, compressed, args.offset, extra, args.jobs, args.timeout
            )
            tail = out.strip().splitlines()[-1] if out.strip() else "(no output)"
            print(tail)
            if found:
                print(f"\n*** Match — recovered keys: {keys} ***")
                print(f"    zlib level : {level}")
                print(f"    reference  : {args.reference}")
                sys.exit(0)
        print(f"\nNo match after {tried} distinct level(s).")
        sys.exit(1)

    if args.force_declaration_guess:
        print("\n[Deflate entry, --force-declaration-guess] WARNING: recompressing a short candidate in")
        print("isolation does not reproduce how it would be encoded as part of a larger real file's")
        print("compressed block (confirmed empirically — see bkcrack_xml_guess_findings.md). This is a")
        print("long shot that only has a chance if the entry's *entire* content is this short.")
        tried = 0
        for candidate in CANDIDATES:
            for level, compressed in unique_deflate_variants(candidate.encode()):
                if len(compressed) < MIN_PLAINTEXT_BYTES:
                    continue
                tried += 1
                data = compressed[: args.bytes]
                print(f"\n[{tried}] level={level} {candidate!r} hex={data.hex()}")
                found, keys, out = run_bkcrack_plain_file(
                    args.bkcrack, archive, entry, data, args.offset, extra, args.jobs, args.timeout
                )
                tail = out.strip().splitlines()[-1] if out.strip() else "(no output)"
                print(tail)
                if found:
                    print(f"\n*** Match — recovered keys: {keys} ***")
                    sys.exit(0)
        print(f"\nNo match after {tried} attempt(s).")
        sys.exit(1)

    sys.exit(
        "\nerror: Deflate-compressed entry — need a full-content reference, not just the declaration.\n\n"
        "Options:\n"
        "  --all                  sweep every entry with all built-in XML templates (recommended)\n"
        "  --reference FILE       provide your own full-content plaintext guess\n"
        "  --auto-content-types   auto-build a [Content_Types].xml reference (OOXML archives)\n"
        "  --force-declaration-guess  try isolated short declaration anyway (long shot)\n"
        "\nSee bkcrack_xml_guess_findings.md for why the isolated-guess technique doesn't work."
    )


if __name__ == "__main__":
    main()
