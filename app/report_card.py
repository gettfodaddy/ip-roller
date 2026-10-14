"""Render a compact dark report card image for Telegram photo messages."""

from __future__ import annotations

import html
import io
import re
import textwrap
from pathlib import Path


FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "C:/Windows/Fonts/segoeui.ttf",
    "C:/Windows/Fonts/arial.ttf",
)
MONO_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    "C:/Windows/Fonts/consola.ttf",
)
BOLD_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
    "C:/Windows/Fonts/segoeuib.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
)

ICON_REPLACEMENTS = {
    "📊": "◆", "🧪": "◆", "📦": "●", "🎯": "●", "⚪": "●", "🔁": "↻",
    "✨": "✦", "📈": "↗", "🚦": "!", "🌐": "◉", "👥": "♙", "💳": "₽",
}


def render_report_card_png(formatted_report: str) -> bytes:
    """Turn the report's semantic HTML/text into a polished dark card PNG."""
    from PIL import Image, ImageDraw, ImageFont

    plain = html.unescape(re.sub(r"<[^>]*>", "", formatted_report))
    lines = [line.strip() for line in plain.splitlines()]
    title = lines[0] if lines else "СВОДКА ROLLER IP"
    period = lines[1] if len(lines) > 1 else ""
    content = lines[3:]
    for emoji, replacement in ICON_REPLACEMENTS.items():
        title = title.replace(emoji, replacement)
        period = period.replace(emoji, replacement)
        content = [line.replace(emoji, replacement) for line in content]
    title = title.replace("\ufe0f", "")
    period = period.replace("\ufe0f", "")
    content = [line.replace("\ufe0f", "") for line in content]

    width = 1040
    left = 54
    content_width = width - left * 2
    font_path = next((path for path in FONT_CANDIDATES if Path(path).is_file()), None)
    mono_path = next((path for path in MONO_CANDIDATES if Path(path).is_file()), font_path)
    if not font_path:
        raise RuntimeError("Не найден шрифт с поддержкой кириллицы (нужен fonts-dejavu-core)")
    regular = ImageFont.truetype(font_path, 26)
    bold_path = next((path for path in BOLD_CANDIDATES if Path(path).is_file()), font_path)
    bold = ImageFont.truetype(bold_path, 26)
    title_font = ImageFont.truetype(bold_path, 31)
    section_font = ImageFont.truetype(bold_path, 22)
    mono = ImageFont.truetype(mono_path, 23)

    def wrap_to_width(text: str, font, max_width: int) -> list[str]:
        words = text.split()
        output: list[str] = []
        current = ""
        probe = Image.new("RGB", (1, 1))
        draw = ImageDraw.Draw(probe)
        for word in words:
            candidate = f"{current} {word}".strip()
            if current and draw.textlength(candidate, font=font) > max_width:
                output.append(current)
                current = word
            else:
                current = candidate
        if current:
            output.append(current)
        return output or [""]

    prepared: list[tuple[str, str]] = []
    for index, line in enumerate(content):
        if not line:
            prepared.append(("space", ""))
        elif line.isupper() and len(line) > 3:
            prepared.append(("section", line))
        elif re.match(r"^\S+\s+· IP \d+\s+· БС \d+\s+· повторы \d+$", line):
            prepared.append(("region", line))
        elif line.startswith("Повтор —"):
            prepared.append(("footer", line))
        else:
            prepared.append(("body", line))

    # Measure the card height before drawing so it expands for a long region list.
    body_rows: list[tuple[str, str]] = []
    for kind, text in prepared:
        if kind == "body":
            body_rows.extend((kind, part) for part in wrap_to_width(text, regular, content_width - 24))
        elif kind == "footer":
            body_rows.extend((kind, part) for part in wrap_to_width(text, regular, content_width - 24))
        else:
            body_rows.append((kind, text))
    height = 220 + sum(
        22 if kind == "space" else 91 if kind == "section" and text == "ПО ЗОНАМ"
        else 48 if kind == "section" else 42
        for kind, text in body_rows
    ) + 40

    image = Image.new("RGB", (width, height), "#0b1420")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((20, 20, width - 20, height - 20), radius=28, fill="#182737")
    for bounds in ((48, 43, 258, 85), (272, 43, 589, 85), (603, 43, 807, 85)):
        draw.rounded_rectangle(bounds, radius=19, fill="#263d50")
    draw.text((70, 51), "◆  ROLLER", font=section_font, fill="#61d8ed")
    draw.text((294, 51), "◷  ПОЧАСОВОЙ ОТЧЁТ", font=section_font, fill="#d7e6f2")
    draw.text((626, 51), "SELECTEL", font=section_font, fill="#d7e6f2")
    draw.text((left, 105), title, font=title_font, fill="#f4f7fb")
    draw.text((left, 151), period, font=mono, fill="#79bce9")
    draw.line((left, 190, width - left, 190), fill="#344b5f", width=2)

    y = 207
    region_index = 0
    for kind, text in body_rows:
        if kind == "space":
            y += 12
            continue
        if kind == "section":
            draw.text((left, y), text, font=section_font, fill="#8be4ed")
            y += 44
            if text == "ПО ЗОНАМ":
                draw.rounded_rectangle((left - 10, y - 3, width - left + 10, y + 38), radius=5, fill="#263b4e")
                draw.text((left, y + 4), "Зона", font=section_font, fill="#bdcddd")
                draw.text((left + 300, y + 4), "IP", font=section_font, fill="#bdcddd")
                draw.text((left + 470, y + 4), "Совпадения", font=section_font, fill="#bdcddd")
                draw.text((left + 760, y + 4), "Повторы", font=section_font, fill="#bdcddd")
                y += 43
        elif kind == "region":
            if region_index % 2 == 0:
                draw.rounded_rectangle((left - 10, y - 5, width - left + 10, y + 35), radius=6, fill="#223648")
            match = re.match(r"^(\S+)\s+· IP (\d+)\s+· БС (\d+)\s+· повторы (\d+)$", text)
            if match:
                region, ip_count, matches, repeats = match.groups()
                draw.text((left, y), region, font=mono, fill="#9fd5fa")
                draw.text((left + 300, y), ip_count, font=regular, fill="#e2eaf2")
                draw.text((left + 470, y), matches, font=regular, fill="#e2eaf2")
                draw.text((left + 760, y), repeats, font=regular, fill="#e2eaf2")
            else:
                draw.text((left, y), text, font=mono, fill="#e2eaf2")
            y += 42
            region_index += 1
        elif kind == "footer":
            y += 6
            draw.text((left, y), text, font=regular, fill="#a9bdce")
            y += 42
        else:
            draw.text((left, y), text, font=regular, fill="#eef3f8")
            y += 42

    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()
