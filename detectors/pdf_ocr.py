"""
Local OCR bridge for image-heavy PDFs.

This module shells out to a small Swift helper that uses macOS Vision OCR so
the main Python service stays compatible with modern Python runtimes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


SWIFT_OCR_SCRIPT = (
    Path(__file__).resolve().parent.parent / "tools" / "privacy-filter-local" / "vision_ocr.swift"
)
OBJC_OCR_SOURCE = (
    Path(__file__).resolve().parent.parent / "tools" / "privacy-filter-local" / "vision_ocr.m"
)
OBJC_OCR_BINARY = Path("/private/tmp/privacy-filter-vision-ocr-helper")
OCR_RENDER_SCALE = 3.0


def _get_swift_binary() -> str:
    swift_bin = shutil.which("swift")
    if swift_bin:
        return swift_bin
    fallback = Path("/usr/bin/swift")
    if fallback.exists():
        return str(fallback)
    raise OSError("swift not installed; cannot OCR PDF with Vision")


def _ensure_ocr_script() -> Path:
    if SWIFT_OCR_SCRIPT.exists():
        return SWIFT_OCR_SCRIPT
    raise OSError(f"Vision OCR helper not found: {SWIFT_OCR_SCRIPT}")


def _ensure_objc_source() -> Path:
    if OBJC_OCR_SOURCE.exists():
        return OBJC_OCR_SOURCE
    raise OSError(f"Vision OCR helper not found: {OBJC_OCR_SOURCE}")


def _get_clang_binary() -> str:
    clang_bin = shutil.which("clang")
    if clang_bin:
        return clang_bin
    fallback = Path("/usr/bin/clang")
    if fallback.exists():
        return str(fallback)
    raise OSError("clang not installed; cannot build Vision OCR helper")


def _render_pdf_pages(path: str, page_numbers: list[int] | None = None) -> tuple[Path, list[dict[str, object]]]:
    try:
        import fitz
    except ImportError as exc:
        raise ImportError("PyMuPDF not installed; cannot OCR PDF") from exc

    doc = fitz.open(path)
    try:
        indexes = page_numbers if page_numbers is not None else list(range(doc.page_count))
        temp_dir = Path(tempfile.mkdtemp(prefix="pdf-vision-ocr-"))
        pages: list[dict[str, object]] = []
        for page_number in indexes:
            page = doc.load_page(page_number)
            pix = page.get_pixmap(matrix=fitz.Matrix(OCR_RENDER_SCALE, OCR_RENDER_SCALE), alpha=False)
            image_path = temp_dir / f"page-{page_number}.png"
            pix.save(str(image_path))
            pages.append(
                {
                    "page_index": page_number,
                    "page_width": float(page.rect.width),
                    "page_height": float(page.rect.height),
                    "image_width": float(pix.width),
                    "image_height": float(pix.height),
                    "image_path": str(image_path),
                }
            )
        return temp_dir, pages
    finally:
        doc.close()


def _run_swift_ocr(image_paths: list[str]) -> list[dict[str, object]]:
    if not image_paths:
        return []

    script_path = _ensure_ocr_script()
    module_cache = Path(tempfile.mkdtemp(prefix="swift-module-cache-", dir="/private/tmp"))
    cmd = [
        _get_swift_binary(),
        "-module-cache-path",
        str(module_cache),
        str(script_path),
        *image_paths,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    shutil.rmtree(module_cache, ignore_errors=True)
    if result.returncode != 0:
        stderr = result.stderr.strip() or "unknown swift OCR failure"
        raise RuntimeError(f"Vision OCR failed: {stderr}")
    return _parse_ocr_payload(result.stdout)


def _compile_objc_helper() -> Path:
    source = _ensure_objc_source()
    if OBJC_OCR_BINARY.exists() and OBJC_OCR_BINARY.stat().st_mtime >= source.stat().st_mtime:
        return OBJC_OCR_BINARY

    module_cache = Path("/private/tmp/clang-module-cache")
    module_cache.mkdir(parents=True, exist_ok=True)
    cmd = [
        _get_clang_binary(),
        "-fobjc-arc",
        "-fmodules",
        f"-fmodules-cache-path={module_cache}",
        "-framework",
        "Foundation",
        "-framework",
        "Vision",
        "-framework",
        "ImageIO",
        str(source),
        "-o",
        str(OBJC_OCR_BINARY),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() or "unknown clang compile failure"
        raise RuntimeError(f"Vision OCR compile failed: {stderr}")
    return OBJC_OCR_BINARY


def _run_objc_ocr(image_paths: list[str]) -> list[dict[str, object]]:
    helper_binary = _compile_objc_helper()
    result = subprocess.run([str(helper_binary), *image_paths], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() or "unknown Vision OCR helper failure"
        raise RuntimeError(f"Vision OCR failed: {stderr}")
    return _parse_ocr_payload(result.stdout)


def _parse_ocr_payload(stdout: str) -> list[dict[str, object]]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Vision OCR returned invalid JSON") from exc

    if not isinstance(payload, list):
        raise RuntimeError("Vision OCR payload must be a JSON array")
    return payload


def _run_vision_ocr(image_paths: list[str]) -> list[dict[str, object]]:
    try:
        return _run_swift_ocr(image_paths)
    except RuntimeError as swift_error:
        try:
            return _run_objc_ocr(image_paths)
        except RuntimeError as objc_error:
            raise RuntimeError(f"{swift_error}\n{objc_error}") from objc_error


def extract_pdf_pages_with_ocr(path: str, page_numbers: list[int] | None = None) -> list[dict[str, object]]:
    temp_dir, pages = _render_pdf_pages(path, page_numbers)
    if not pages:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return []
    try:
        raw_pages = _run_vision_ocr([str(page["image_path"]) for page in pages])
        if len(raw_pages) != len(pages):
            raise RuntimeError("Vision OCR returned a mismatched page count")

        normalized_pages: list[dict[str, object]] = []
        for page_meta, raw_page in zip(pages, raw_pages):
            if not isinstance(raw_page, dict):
                raise RuntimeError("Vision OCR page payload must be an object")
            normalized_pages.append(
                {
                    "page_index": page_meta["page_index"],
                    "page_width": page_meta["page_width"],
                    "page_height": page_meta["page_height"],
                    "image_width": page_meta["image_width"],
                    "image_height": page_meta["image_height"],
                    "lines": raw_page.get("lines", []),
                }
            )
        return normalized_pages
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def extract_pdf_text_with_ocr(path: str, page_numbers: list[int] | None = None) -> list[str]:
    texts: list[str] = []
    for page in extract_pdf_pages_with_ocr(path, page_numbers):
        lines = page.get("lines", [])
        page_lines = []
        for line in lines:
            if not isinstance(line, dict):
                continue
            text = str(line.get("text", "")).strip()
            if text:
                page_lines.append(text)
        texts.append("\n".join(page_lines))
    return texts
