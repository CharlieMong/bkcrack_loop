# bkcrack_loop

bkcrack_xml_guess.py

A known-plaintext attack helper for recovering ZipCrypto internal keys from zip archives whose entries are expected to contain XML content. Built around bkcrack (Biham-Kocher attack implementation). Designed for use during authorised penetration testing engagements where ZipCrypto-encrypted archives are in scope.

Background

ZipCrypto (also called Traditional PKWARE encryption) is the legacy zip encryption scheme. It is vulnerable to a known-plaintext attack: given as few as 8 contiguous bytes of the plaintext that correspond to a known position in the ciphertext, bkcrack can recover the archive's internal key state. That key state decrypts every entry in the archive regardless of how many files it contains.

The plaintext used in the attack is what was fed to the ZipCrypto cipher — meaning:

For Store (uncompressed) entries: the raw file bytes.
For Deflate-compressed entries: the compressed bytes, not the original file content.

XML files — particularly those from OOXML packages (.docx, .xlsx, .pptx) — are extremely predictable in their structure. Their [Content_Types].xml, .rels, docProps/core.xml, and docProps/app.xml parts follow well-known schemas and can be reconstructed with high fidelity from the unencrypted zip directory metadata alone (entry names and extensions are never encrypted in a standard zip).

This script automates that reconstruction and drives bkcrack accordingly, then proves successful decryption by producing a chain-of-custody manifest.

Why Not Just Compress the XML Declaration?

A common naive approach is to take the XML declaration (<?xml version="1.0" encoding="UTF-8"?>) and compress it in isolation at various zlib levels, then feed the leading bytes to bkcrack as the known plaintext for a Deflate-compressed entry. This does not work for realistic files.

Deflate's Huffman coding is computed over the statistics of the entire compressed block. Compressing a 40-byte snippet alone produces a completely different bitstream from the bytes that same snippet would produce as the prefix of a multi-hundred-byte file. In empirical testing against a real ZipCrypto+Deflate archive, the isolated-declaration approach produced compressed bytes with zero relationship to the actual ciphertext — while recompressing the full reconstructed file at the matching zlib level reproduced the ciphertext byte-for-byte and recovered the keys.

This script compresses complete reconstructed file content (not isolated fragments) and feeds the result to bkcrack via -p (plain file), the same mechanism documented in bkcrack's own tutorial.

How It Works
Store entries

All 58 XML declaration variants (29 base declarations covering UTF-8, ISO-8859-1, US-ASCII, Windows-1252, UTF-16, various standalone and quote styles, and both CRLF and LF line endings; each with and without a UTF-8 BOM prepended) are tried directly as raw known plaintext against the entry. This is reliable and fast — bkcrack rejects wrong guesses quickly when the ciphertext is short.

Deflate entries — OOXML part types

For entries with recognised OOXML part names, the script reconstructs a plausible full-content plaintext and recompresses it at zlib levels 1–9 (with deduplication: multiple levels frequently produce identical output for small inputs). The entry types covered and their reconstruction strategy are:

[Content_Types].xml: built from visible entry names and extensions in the zip directory using known OOXML content-type mappings for the standard Default and Override entries.
_rels/.rels and other .rels files: relationship targets are inferred from visible entry paths (detecting docx/xlsx/pptx from word/, xl/, ppt/ prefixes; wiring in docProps/core.xml and docProps/app.xml when present; generating workbook sheet relationships for visible worksheet paths).
docProps/core.xml: three variants covering minimal Microsoft Office output (empty creator fields), output with a revision element, and LibreOffice-style output.
docProps/app.xml: six variants covering Microsoft Office Word, Excel, PowerPoint, Word 2016, LibreOffice, and Google Docs as the Application element value.
Deflate entries — unknown or unrecognised names

Declaration-only bytes used as full file content are tried for entries whose uncompressed size is 200 bytes or fewer (plausible for stub XML). For larger entries with unrecognised names, a --reference file must be supplied by the operator.

Key recovery and extraction proof

On the first successful key recovery in --all mode, the script:

Calls bkcrack -D to decrypt the entire archive to a new zip file using the recovered internal key triple.
Extracts every file from the decrypted archive using Python's zipfile module.
SHA-256 hashes the source archive, the decrypted archive, and every extracted file.
Writes manifest.json to the output directory with all of the above plus method, timing, and entry provenance.

Because ZipCrypto derives one internal key state for the entire archive from the password, a single successful entry attack decrypts all entries.

Requirements
Python 3.7 or later (standard library only; no third-party packages required)
bkcrack on PATH, or a full path passed via --bkcrack
The zip command (Info-Zip) is required only by the self-test script, not by the main script

Build bkcrack from source if not already available:

git clone https://github.com/kimci86/bkcrack.git
cmake -S bkcrack -B bkcrack/build -DCMAKE_INSTALL_PREFIX=.
cmake --build bkcrack/build --config Release --target install
Usage
Recommended: full archive sweep
python3 bkcrack_xml_guess.py TARGET.zip --all \
    --bkcrack /path/to/bkcrack \
    --jobs $(nproc) \
    --timeout 300 \
    --extract-dir ./TARGET_proof

Iterates every ZipCrypto entry. On key recovery, immediately decrypts the whole archive, extracts all files, and writes manifest.json. Exits 0 on success, 1 if no entry yielded a match.

Single entry — Store (uncompressed) entry
python3 bkcrack_xml_guess.py TARGET.zip 0 --timeout 60

0 is the entry index. Entry names can also be used:

python3 bkcrack_xml_guess.py TARGET.zip "docProps/core.xml"
Single entry — Deflate entry, auto-built reference
python3 bkcrack_xml_guess.py TARGET.zip "[Content_Types].xml" --auto-content-types

Builds a best-effort [Content_Types].xml reference from the visible archive entry names, recompresses it at levels 1–9, and tries each against bkcrack.

Single entry — Deflate entry, operator-supplied reference
python3 bkcrack_xml_guess.py TARGET.zip "word/document.xml" --reference known_good.xml

The reference file must approximate the entire original plaintext, not just its first line. Even a close structural match from the same application version is usually enough — the key is matching zlib level, which the script covers by trying all levels.

Interactive mode

If archive and/or entry are omitted, the script prompts for them:

python3 bkcrack_xml_guess.py
python3 bkcrack_xml_guess.py TARGET.zip   # prompts for entry only
Options
Option	Default	Description
archive	prompted	Path to the zip archive.
entry	prompted	Entry name or numeric index. Not used with --all.
--all	off	Sweep every ZipCrypto entry with all built-in XML templates. On success, decrypt the full archive and write a manifest.
--extract-dir DIR	<archive>_extracted/	Directory for the decrypted archive, extracted files, and manifest.json.
--reference FILE	none	Full-content plaintext guess for a single Deflate-compressed entry.
--auto-content-types	off	Auto-build a [Content_Types].xml reference from visible entry names (single-entry mode).
--force-declaration-guess	off	Also try isolated short XML declarations compressed in isolation against Deflate entries. Documented long shot — unreliable for realistic files.
--bkcrack PATH	bkcrack	Path to the bkcrack binary.
--jobs N	bkcrack default	Number of parallel threads passed to bkcrack -j. Use $(nproc) to saturate available cores.
--timeout N	none	Per-attempt timeout in seconds. A timeout is inconclusive — bkcrack does not fail fast on wrong guesses. See timing notes below.
--bytes N	16	Maximum leading bytes from each declaration candidate (Store entries only). Minimum 8.
--offset N	0	Known-plaintext byte offset relative to ciphertext start.
--exhaustive	off	Passed through to bkcrack -e (exhaustive search — finds all solutions, slower).
--verbose	off	Print each individual attempt as it runs, including compressed size and leading hex bytes.
Timing Guidance

bkcrack does not fail fast on incorrect guesses. For a Deflate-compressed entry, a wrong guess runs the full keyspace before concluding failure. For correct guesses, the solution can appear anywhere in the search space — empirically, for a 255-byte ciphertext ([Content_Types].xml in a minimal docx), a correct guess at zlib level 6 took approximately 112 seconds on 2 threads, landing at around 83% of the Z-value search.

Wrong guesses are often rejected immediately when the compressed length of the candidate exceeds the packed size of the ciphertext — the size check fires before the full attack runs. This is why wrong levels for a given template are fast to eliminate, but a wrong template whose compressed output happens to fit the size window will run to completion.

Practical defaults for engagements:

--timeout 300 — allows 5 minutes per attempt, covering the upper end of correct-guess timing on modest hardware.
--jobs $(nproc) — saturates available CPU cores; reduces wall-clock time proportionally.
Avoid --timeout values below 180 seconds when attacking Deflate entries — correct guesses can be killed before completion, producing a false negative.
Output

On successful key recovery in --all mode, the following are written to --extract-dir:

TARGET_proof/
  decrypted.zip           # Full archive decrypted — no password required to open
  files/                  # All extracted plaintext files
    [Content_Types].xml
    word/document.xml
    ...
  manifest.json           # Chain-of-custody record

manifest.json contains:

Absolute path and SHA-256 of the source (encrypted) archive
Absolute path and SHA-256 of the decrypted archive
UTC timestamp of the attack run
Attack method description
Which entry was successfully attacked and which plaintext template matched
The recovered internal key triple (three 32-bit hex values)
SHA-256 and byte size of every extracted file

The recovered keys are bkcrack's internal ZipCrypto representation, not the original password. They are sufficient to decrypt the archive but cannot be reversed to the password without additional attack steps. Handle as engagement evidence per your scope's data-handling requirements.

When Built-in Templates Do Not Match

If --all sweeps every entry and finds no match, the archive is either not OOXML or contains non-standard parts the built-in templates do not cover. Next steps:

Examine the archive listing (bkcrack -L TARGET.zip) to identify entry names and sizes. Note which entries are smallest — smaller ciphertexts shrink the keyspace for wrong guesses.
Obtain a reference plaintext from the same application and version that produced the archive. Even a structurally identical file (same software, same document type, same export settings) is usually sufficient.
Run single-entry mode with --reference against the most predictable entry (relationship files and properties documents are often more templated than body content).
If the content type is genuinely unknown, --force-declaration-guess can be added to --all as a last resort. Expect it to have a low success rate against realistic Deflate-compressed content.
Self-test

test_bkcrack_xml_guess.sh builds a synthetic OOXML-style encrypted archive with a known password and verifies the attack pipeline end-to-end:

Test A: --reference with the exact real plaintext recovers the correct internal keys.
Test B: --auto-content-types recovers the same keys when the archive content matches the auto-generator's template.
Test C: --force-declaration-guess (the isolated-declaration technique) does not recover keys within the test budget, confirming the byte-level mismatch documented in the revision notes.
bash test_bkcrack_xml_guess.sh

Runtime is approximately 5–10 minutes on a modern desktop (two correct-guess attacks plus one full-timeout run of the negative test).

Operational Notes
The script is read-only with respect to the target archive. It writes only to --extract-dir and to a temporary directory for intermediate plaintext files (cleaned up after each attempt).
No credentials, keys, or recovered plaintext are written to stdout in clear text during the sweep — the manifest is the authoritative record.
Run on a system you control. The extracted files will be the decrypted contents of the archive; handle them according to your engagement's data classification requirements.
The script does not attempt password recovery. The recovered key triple is a distinct credential from the original password.

See task progress for longer tasks.

bkcrack_xml_guess_findings.md
bkcrack_xml_guess.py
test_bkcrack_xml_guess.sh
README.md

Track tools and referenced files used in this task.

Downloaded README.md S