#!/usr/bin/env python3
# -- coding: utf-8 --
"""Exercise the NetExec CLI against a synthetic SMB server on 127.0.0.1.

Run only when this loopback fixture is explicitly authorized. All test files and
configuration live in an isolated temporary directory. No other host is tested.
"""

# Imports
import io
import json
import os
import multiprocessing
import logging
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile

from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smbserver import SimpleSMBServer
from PIL import Image, ImageDraw, ImageFont


def office_document(extension, text):
    content = escape(text)
    relationships = "http://schemas.openxmlformats.org/package/2006/relationships"
    office_relationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    if extension == "docx":
        main = "word/document.xml"
        content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
        files = {main: f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{content}</w:t></w:r></w:p></w:body></w:document>'}
    elif extension == "xlsx":
        main = "xl/workbook.xml"
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
        files = {
            main: f'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="{office_relationships}"><sheets><sheet name="Test" sheetId="1" r:id="rId1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": f'<Relationships xmlns="{relationships}"><Relationship Id="rId1" Type="{office_relationships}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            "xl/worksheets/sheet1.xml": f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{content}</t></is></c></row></sheetData></worksheet>',
        }
    else:
        main = "ppt/presentation.xml"
        content_type = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
        files = {
            main: f'<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="{office_relationships}"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>',
            "ppt/_rels/presentation.xml.rels": f'<Relationships xmlns="{relationships}"><Relationship Id="rId1" Type="{office_relationships}/slide" Target="slides/slide1.xml"/></Relationships>',
            "ppt/slides/slide1.xml": f'<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>{content}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>',
        }
    overrides = f'<Override PartName="/{main}" ContentType="{content_type}"/>'
    if extension == "xlsx":
        overrides += '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    elif extension == "pptx":
        overrides += '<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
    files["[Content_Types].xml"] = f'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>{overrides}</Types>'
    files["_rels/.rels"] = f'<Relationships xmlns="{relationships}"><Relationship Id="rId1" Type="{office_relationships}/officeDocument" Target="{main}"/></Relationships>'
    output = io.BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def pdf_document(text):
    stream = f"BT /F1 12 Tf 40 750 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, data in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + data + b"\nendobj\n")
    xref = len(output)
    output.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def scanned_image():
    image = Image.new("RGB", (800, 100), "white")
    ImageDraw.Draw(image).text((25, 25), "FIXTURE MARKER", font=ImageFont.load_default(size=40), fill="black")
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def open_document(extension, text):
    mime_type = {"odt": "text", "ods": "spreadsheet"}[extension]
    paragraph = f"<text:p>{escape(text)}</text:p>"
    if extension == "ods":
        paragraph = f'<table:table table:name="Test"><table:table-row><table:table-cell office:value-type="string">{paragraph}</table:table-cell></table:table-row></table:table>'
    content = f'<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"><office:body><office:{mime_type}>{paragraph}</office:{mime_type}></office:body></office:document-content>'
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("mimetype", f"application/vnd.oasis.opendocument.{mime_type}")
        archive.writestr("content.xml", content)
        archive.writestr("META-INF/manifest.xml", f'<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.{mime_type}"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/></manifest:manifest>')
    return output.getvalue()


def fixture_files():
    text = "password=synthetic-test-value fixture.marker"
    files = {
        "web.config": text.encode(),
        "notes.txt": b"fixture.marker fixture.marker fixtureXmarker\nNo credential assignment here.",
        "other.txt": b"Ordinary documentation.",
        "old.txt": text.encode(),
        "large.txt": b"x" * 2048,
        "nul.bin": b"\x00password=synthetic-test-value",
        "report.pdf": pdf_document(text),
        "corrupt.docx": b"invalid document bytes",
        "empty.pdf": pdf_document(""),
        "huge.docx": office_document("docx", "x" * 8192),
        "nested/deeper/plan.txt": text.encode(),
        "nested/reports/plan.txt": text.encode(),
        "skip/plan.txt": text.encode(),
        "extensionless": text.encode(),
        "utf16.txt": text.encode("utf-16"),
        "chunked.txt": b" " * 4093 + text.encode(),
        "scan.png": scanned_image(),
        "report.rtf": ("{\\rtf1\\ansi " + text + "}").encode(),
    }
    for extension in ("docx", "xlsx", "pptx"):
        files[f"report.{extension}"] = office_document(extension, text)
    for extension in ("odt", "ods"):
        files[f"report.{extension}"] = open_document(extension, text)
    return {"DOCUMENTS": files, "OTHER": {"notes.txt": text.encode()}, "IPC$": {}}


def serve_fixture(root, ready):
    logging.getLogger("impacket").setLevel(logging.CRITICAL)
    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=0)
    server.setSMB2Support(True)
    server.setSMBChallenge("4141414141414141")
    server.addCredential("fixture", 0, compute_lmhash("SyntheticTest123!"), compute_nthash("SyntheticTest123!"))
    for name in ("DOCUMENTS", "OTHER"):
        server.addShare(name, str(Path(root) / name), readOnly="yes")
    ready.send(server.getServer().server_address[1])
    ready.close()
    server.start()


def check_cli(ocr=False):
    runs = 0
    with TemporaryDirectory(prefix="nxc-spider-fixture-") as temp:
        root = Path(temp)

        for share, files in fixture_files().items():
            if share == "IPC$":
                continue
            for name, data in files.items():
                target = root / share / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                timestamp = datetime(2020 if name == "old.txt" else 2026, 1, 1, tzinfo=UTC).timestamp()
                os.utime(target, (timestamp, timestamp))
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        server = context.Process(target=serve_fixture, args=(str(root), child), daemon=True)
        server.start()
        child.close()
        if not parent.poll(30):
            server.terminate()
            server.join(10)
            raise AssertionError("SMB fixture failed to start")
        port = parent.recv()
        parent.close()

        def run(*options, expected=0, output=None, arguments=None):
            nonlocal runs
            runs += 1
            output = output or root / f"run-{runs}"
            env = dict(os.environ, NXC_PATH=str(root / "config"), PYTHONPATH=str(Path(__file__).resolve().parents[1]))
            args = [sys.executable, "-m", "nxc.netexec", "smb", "127.0.0.1", "--port", str(port), "--no-smbv1", "--local-auth", "-u", "fixture", "-p", "SyntheticTest123!"]
            args += arguments if arguments is not None else ["-M", "spider_plus", "-o", f"OUTPUT_FOLDER={output}", *options]
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=90, check=False)
            if result.returncode != expected:
                raise AssertionError(f"{options}: exit {result.returncode}, expected {expected}\n{result.stdout}\n{result.stderr}")
            if expected:
                return None
            if arguments is not None:
                return result.stdout
            metadata = output / "127.0.0.1.json"
            if not metadata.exists():
                raise AssertionError(f"Module did not write metadata: {options}\n{result.stdout}\n{result.stderr}")
            return json.loads(metadata.read_text())

        try:
            baseline = run()
            assert set(baseline) == {"DOCUMENTS", "OTHER"}, set(baseline)
            assert baseline["DOCUMENTS"]["web.config"]["sensitive"]["content_status"] == "not_requested"
            assert baseline["DOCUMENTS"]["report.docx"]["sensitive"]["content_status"] == "not_requested"
            documents = run("DOCUMENTS=True", "SHARES=documents")
            for name in ("report.docx", "report.xlsx", "report.pptx", "report.pdf", "report.odt", "report.ods", "report.rtf"):
                finding = documents["DOCUMENTS"][name]["sensitive"]
                assert finding["content_status"] == "checked", (name, finding)
                assert "credential assignment" in finding["content_matches"], (name, finding)
            assert documents["DOCUMENTS"]["corrupt.docx"]["sensitive"]["content_status"] == "extraction_error"
            assert documents["DOCUMENTS"]["empty.pdf"]["sensitive"]["content_status"] == "no_text"
            assert documents["DOCUMENTS"]["scan.png"]["sensitive"]["content_status"] == "skipped_type"
            if ocr:
                scanned = run("DOCUMENTS=True", "OCR=True", "NAME_REGEX=scan\\.png$", "CONTENT_REGEX=FIXTURE\\s+MARKER")
                assert scanned["DOCUMENTS"]["scan.png"]["search"]["content_matches"], scanned["DOCUMENTS"]["scan.png"]
            custom = run("SENSITIVE_CHECK=False", "CONTENT_REGEX=fixture\\.marker", "SHARES=documents", "NAME_REGEX=notes\\.txt$")
            assert "sensitive" not in custom["DOCUMENTS"]["notes.txt"]
            assert custom["DOCUMENTS"]["notes.txt"]["search"]["content_matches"] == [{"pattern": "fixture\\.marker", "count": 2}]
            assert custom["DOCUMENTS"]["other.txt"]["search"]["content_status"] == "excluded"
            terms = root / "terms.txt"
            terms.write_text("# comment\n\nfixture.marker\n", encoding="utf-8")
            wordlist = run(f"CONTENT_WORDLIST={terms}", "NAME_REGEX=notes\\.txt$", "SENSITIVE_CHECK=False")
            assert wordlist["DOCUMENTS"]["notes.txt"]["search"]["content_matches"][0]["count"] == 2
            recent = run("MODIFIED_AFTER=2026-01-01", "MODIFIED_BEFORE=2026-01-02", "SENSITIVE_READ_CONTENT=True")
            assert recent["DOCUMENTS"]["old.txt"]["filter_status"] == "modified_after"
            assert recent["DOCUMENTS"]["notes.txt"].get("sensitive", {}).get("content_status") == "checked", recent["DOCUMENTS"]["notes.txt"]
            before = run("MODIFIED_BEFORE=2026-01-01")
            assert before["DOCUMENTS"]["notes.txt"]["filter_status"] == "modified_before"
            assert "filter_status" not in before["DOCUMENTS"]["old.txt"]
            shallow = run("DEPTH=0", "SHARES=Documents")
            assert set(shallow) == {"DOCUMENTS"}
            assert not any("/" in name for name in shallow["DOCUMENTS"])
            depth = run("DEPTH=1")
            assert "nested/reports/plan.txt" not in depth["DOCUMENTS"]
            directories = run("INCLUDE_DIRS=nested/reports", "EXCLUDE_DIRS=skip", "INCLUDE_EXTS=.txt", "CONTENT_REGEX=fixture")
            assert directories["DOCUMENTS"]["nested/reports/plan.txt"]["search"]["content_matches"]
            assert directories["DOCUMENTS"]["nested/deeper/plan.txt"]["filter_status"] == "directory"
            assert "skip/plan.txt" not in directories["DOCUMENTS"]
            extensionless = run("INCLUDE_EXTS=<none>", "CONTENT_REGEX=fixture")
            assert extensionless["DOCUMENTS"]["extensionless"]["search"]["content_matches"]
            assert extensionless["DOCUMENTS"]["notes.txt"]["filter_status"] == "extension"
            text = run("SENSITIVE_READ_CONTENT=True", "CONTENT_REGEX=fixture\\.marker")
            for name in ("utf16.txt", "chunked.txt"):
                assert text["DOCUMENTS"][name]["search"]["content_matches"]
            for name, status in (("nul.bin", "skipped_binary"), ("report.docx", "skipped_type")):
                assert text["DOCUMENTS"][name]["search"]["content_status"] == status, name
            bounded = run("DOCUMENTS=True", "SENSITIVE_MAX_FILE_SIZE=2048")
            assert bounded["DOCUMENTS"]["huge.docx"]["sensitive"]["content_status"] == "skipped_extracted_size"
            small = run("SENSITIVE_READ_CONTENT=True", "SENSITIVE_MAX_FILE_SIZE=16")
            assert small["DOCUMENTS"]["web.config"]["sensitive"]["content_status"] == "skipped_size"
            excluded = run("CONTENT_REGEX=fixture", "EXCLUDE_EXTS=txt")
            assert excluded["DOCUMENTS"]["notes.txt"]["search"]["content_status"] == "excluded"
            download_output = root / "download"
            for _ in range(2):
                downloaded = run("DOCUMENTS=True", "DOWNLOAD_FLAG=True", "NAME_REGEX=^report\\.", output=download_output)
                assert downloaded["DOCUMENTS"]["report.docx"]["sensitive"]["content_source"] == "download"
                assert downloaded["DOCUMENTS"]["report.docx"]["sensitive"]["content_matches"]
            assert (download_output / "127.0.0.1/DOCUMENTS/report.docx").exists()
            for option in ("NAME_REGEX=[", "CONTENT_REGEX=[", "DEPTH=-1", "DEPTH=bad", "MODIFIED_AFTER=bad", "MODIFIED_BEFORE=2026-02-30", "DOCUMENTS=bad", "OCR=True", "SENSITIVE_MAX_FILE_SIZE=0", "MODIFIED_AFTER=2027-01-01 MODIFIED_BEFORE=2026-01-01"):
                run(*option.split(), expected=1)
            run(f"CONTENT_WORDLIST={root / 'missing'}", expected=1)
            terms.write_text("# empty\n\n", encoding="utf-8")
            run(f"CONTENT_WORDLIST={terms}", expected=1)
            modified = datetime.fromtimestamp(datetime(2020, 1, 1, tzinfo=UTC).timestamp())
            listing = run(arguments=["--share", "DOCUMENTS", "--dir"])
            assert modified.ctime() in listing, listing
            assert "old.txt" in listing, listing
            spider = run(arguments=["--spider", "DOCUMENTS", "--pattern", "old.txt", "--depth", "0"])
            assert modified.strftime("%Y-%m-%d %H:%M") in spider, spider
        finally:
            server.terminate()
            server.join(10)
            if server.is_alive():
                server.kill()
                server.join(10)
    print(f"Passed {runs} NetExec CLI invocations against the synthetic SMB fixture on 127.0.0.1.")


if __name__ == "__main__":
    if sys.argv[1:] not in (["--check"], ["--check", "--ocr"]):
        raise SystemExit("Usage: python tests/spider_plus_fixture.py --check [--ocr] (requires authorization for 127.0.0.1)")
    check_cli(ocr="--ocr" in sys.argv)
