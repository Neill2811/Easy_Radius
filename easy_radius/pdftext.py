"""A small text-only PDF writer. No extra library."""

from __future__ import annotations


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_pdf(lines: list[str]) -> bytes:
    pages: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        wrapped = _wrap(line, 90) or [""]
        for piece in wrapped:
            if len(current) >= 48:
                pages.append(current)
                current = []
            current.append(piece)
    if current or not pages:
        pages.append(current)
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    font_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    content_ids = []
    for page_lines in pages:
        stream = ["BT /F1 11 Tf 48 800 Td 14 TL"]
        for index, line in enumerate(page_lines):
            operator = "Tj" if index == 0 else "'"
            if index == 0:
                stream.append(f"({_escape(line)}) Tj")
            else:
                stream.append(f"({_escape(line)}) '")
        data = ("\n".join(stream) + "\nET\n").encode("latin-1", "replace")
        content_ids.append(add(b"<< /Length %d >>\nstream\n" % len(data) + data + b"endstream"))
    page_ids = []
    for content_id in content_ids:
        page_ids.append(
            add(
                f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 595 842] "
                f"/Contents {content_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>".encode()
            )
        )
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    pages_id = add(f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode())
    for page_id in page_ids:
        objects[page_id - 1] = objects[page_id - 1].replace(b"/Parent 0 0 R", f"/Parent {pages_id} 0 R".encode())
    catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode())
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer << /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def _wrap(line: str, width: int) -> list[str]:
    text = line.replace("\t", " ")
    if len(text) <= width:
        return [text]
    parts = []
    while text:
        parts.append(text[:width])
        text = text[width:]
    return parts
