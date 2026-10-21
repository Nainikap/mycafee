"""Builds docs/NetSentry_Documentation.pdf. Run with the scratch pdfenv (reportlab, svglib)."""

import json
import sys
from pathlib import Path

from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate, PageBreak, PageTemplate, Paragraph,
    Preformatted, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

SP = Path(__file__).parent
ROOT = Path(r"C:\MyProjects\mycafee")
OUT = ROOT / "docs" / "NetSentry_Documentation.pdf"
DATA = json.loads((SP / "chart.json").read_text(encoding="utf-8"))

F = r"C:\Windows\Fonts"
pdfmetrics.registerFont(TTFont("Body", f"{F}\\segoeui.ttf"))
pdfmetrics.registerFont(TTFont("Body-Bold", f"{F}\\segoeuib.ttf"))
pdfmetrics.registerFont(TTFont("Body-Italic", f"{F}\\segoeuii.ttf"))
pdfmetrics.registerFont(TTFont("Body-BoldItalic", f"{F}\\segoeuiz.ttf"))
pdfmetrics.registerFont(TTFont("Semi", f"{F}\\seguisb.ttf"))
pdfmetrics.registerFont(TTFont("Mono", f"{F}\\consola.ttf"))
pdfmetrics.registerFont(TTFont("Mono-Bold", f"{F}\\consolab.ttf"))
pdfmetrics.registerFontFamily("Body", normal="Body", bold="Body-Bold", italic="Body-Italic",
                              boldItalic="Body-BoldItalic")
pdfmetrics.registerFontFamily("Mono", normal="Mono", bold="Mono-Bold", italic="Mono", boldItalic="Mono-Bold")

# ---------------------------------------------------------------- palette (text tokens + validated series)
INK = colors.HexColor("#1d1f24")
INK2 = colors.HexColor("#4a4f5a")
MUTED = colors.HexColor("#7a808c")
RULE = colors.HexColor("#d9dce1")
PANEL = colors.HexColor("#f4f5f7")
ACCENT = colors.HexColor("#1f4e8c")
ACCENT_SOFT = colors.HexColor("#e8eff8")
SERIES = [colors.HexColor(h) for h in ("#2a78d6", "#eb6834", "#1baf7a", "#eda100")]
REF_GRAY = colors.HexColor("#9aa0aa")
LAYER_FILLS = [colors.HexColor(h) for h in ("#eaf2fc", "#eef8f3", "#fdf3e9", "#f3f0fc")]
LAYER_STROKES = [colors.HexColor(h) for h in ("#2a78d6", "#1baf7a", "#eb6834", "#6250d6")]

W, H = A4
MARGIN = 20 * mm
CW = W - 2 * MARGIN  # content width

# ---------------------------------------------------------------- styles
S = {}
S["body"] = ParagraphStyle("body", fontName="Body", fontSize=9.6, leading=14.2, textColor=INK, spaceAfter=6)
S["small"] = ParagraphStyle("small", parent=S["body"], fontSize=8.3, leading=11.5, textColor=INK2, spaceAfter=3)
S["cell"] = ParagraphStyle("cell", parent=S["body"], fontSize=8.4, leading=11.2, spaceAfter=0)
S["cellh"] = ParagraphStyle("cellh", parent=S["cell"], fontName="Body-Bold", textColor=colors.white)
S["cellmono"] = ParagraphStyle("cellmono", parent=S["cell"], fontName="Mono", fontSize=7.9)
S["h1"] = ParagraphStyle("h1", fontName="Body-Bold", fontSize=19, leading=24, textColor=ACCENT, spaceBefore=4,
                         spaceAfter=10)
S["h2"] = ParagraphStyle("h2", fontName="Body-Bold", fontSize=12.6, leading=17, textColor=INK, spaceBefore=12,
                         spaceAfter=5)
S["h3"] = ParagraphStyle("h3", fontName="Semi", fontSize=10.4, leading=14, textColor=ACCENT, spaceBefore=8,
                         spaceAfter=3)
S["bullet"] = ParagraphStyle("bullet", parent=S["body"], leftIndent=13, bulletIndent=3, spaceAfter=3)
S["code"] = ParagraphStyle("code", fontName="Mono", fontSize=7.8, leading=10.4, textColor=INK, backColor=PANEL,
                           borderPadding=(6, 6, 6, 6), leftIndent=6, rightIndent=6, spaceBefore=4, spaceAfter=10)
S["caption"] = ParagraphStyle("caption", parent=S["small"], fontName="Body-Italic", alignment=TA_CENTER,
                              spaceBefore=3, spaceAfter=10)
S["callout"] = ParagraphStyle("callout", parent=S["body"], backColor=ACCENT_SOFT, borderPadding=(7, 9, 7, 9),
                              leftIndent=9, rightIndent=9, spaceBefore=6, spaceAfter=12, textColor=INK)
S["formula"] = ParagraphStyle("formula", parent=S["body"], fontName="Mono", fontSize=9, leading=13,
                              alignment=TA_CENTER, backColor=PANEL, borderPadding=(6, 6, 6, 6), leftIndent=30,
                              rightIndent=30, spaceBefore=4, spaceAfter=10)
S["toc1"] = ParagraphStyle("toc1", fontName="Body-Bold", fontSize=10.2, leading=16, textColor=INK, leftIndent=0)
S["toc2"] = ParagraphStyle("toc2", fontName="Body", fontSize=9, leading=13, textColor=INK2, leftIndent=16)

story: list = []
_sec = [0, 0]


def P(text: str, style: str = "body") -> Paragraph:
    if style == "formula":  # keep the visual gaps between parts of a formula
        import re

        text = re.sub(r" {3,}", lambda m: "&nbsp;" * len(m.group()), text)
    return Paragraph(text, S[style])


def H1(text: str) -> None:
    _sec[0] += 1
    _sec[1] = 0
    story.append(PageBreak())
    p = Paragraph(f"{_sec[0]}&nbsp;&nbsp;{text}", S["h1"])
    p._toc = (0, f"{_sec[0]}  {text}")
    story.append(p)
    story.append(Rule())


def HA(text: str) -> None:
    story.append(PageBreak())
    p = Paragraph(text, S["h1"])
    p._toc = (0, text)
    story.append(p)
    story.append(Rule())


def H2(text: str, need: float = 40) -> None:
    _sec[1] += 1
    p = Paragraph(f"{_sec[0]}.{_sec[1]}&nbsp;&nbsp;{text}", S["h2"])
    p._toc = (1, f"{_sec[0]}.{_sec[1]}  {text}")
    story.append(CondPageBreak(need * mm))
    story.append(p)


def H3(text: str) -> None:
    story.append(P(text, "h3"))


def B(items: list[str]) -> None:
    for it in items:
        story.append(Paragraph(it, S["bullet"], bulletText="•"))
    story.append(Spacer(1, 4))


def CODE(text: str) -> None:
    story.append(Preformatted(text.strip("\n"), S["code"]))


def NOTE(text: str) -> None:
    story.append(P(text, "callout"))


def CAP(text: str) -> None:
    story.append(P(text, "caption"))


class Rule(Spacer):
    def __init__(self) -> None:
        super().__init__(CW, 8)

    def draw(self) -> None:
        self.canv.setStrokeColor(RULE)
        self.canv.setLineWidth(0.8)
        self.canv.line(0, 6, CW, 6)


def T(rows: list[list], widths: list[float], header: bool = True, mono_cols: tuple = (), zebra: bool = True,
      font_size: float | None = None) -> None:
    data = []
    for i, row in enumerate(rows):
        cells = []
        for j, c in enumerate(row):
            if isinstance(c, str):
                st = "cellh" if header and i == 0 else ("cellmono" if j in mono_cols else "cell")
                style = S[st]
                if font_size:
                    style = ParagraphStyle(f"x{st}{font_size}", parent=style, fontSize=font_size,
                                           leading=font_size * 1.33)
                cells.append(Paragraph(c, style))
            else:
                cells.append(c)
        data.append(cells)
    total = sum(widths)
    t = Table(data, colWidths=[w / total * CW for w in widths], repeatRows=1 if header else 0)
    cmds = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
    ]
    if header:
        cmds += [("BACKGROUND", (0, 0), (-1, 0), ACCENT)]
    if zebra:
        for r in range(1 if header else 0, len(data)):
            if r % 2 == 0:
                cmds.append(("BACKGROUND", (0, r), (-1, r), PANEL))
    t.setStyle(TableStyle(cmds))
    story.append(t)
    story.append(Spacer(1, 10))


# ---------------------------------------------------------------- drawing helpers


def text_lines(d: Drawing, x: float, y: float, lines: list[str], size: float = 7.5, font: str = "Body",
               color=INK, anchor: str = "middle", leading: float | None = None) -> None:
    leading = leading or size * 1.25
    for i, ln in enumerate(lines):
        d.add(String(x, y - i * leading, ln, fontName=font, fontSize=size, fillColor=color, textAnchor=anchor))


def box(d: Drawing, x: float, y: float, w: float, h: float, title: str, sub: list[str] | None = None,
        fill=colors.white, stroke=INK2, dashed: bool = False, title_size: float = 7.8, r: float = 4) -> None:
    rect = Rect(x, y, w, h, rx=r, ry=r, fillColor=fill, strokeColor=stroke, strokeWidth=0.9)
    if dashed:
        rect.strokeDashArray = [3, 2]
    d.add(rect)
    lines = 1 + len(sub or [])
    top = y + h / 2 + (lines - 1) * 4.6 - 2.6
    d.add(String(x + w / 2, top, title, fontName="Body-Bold", fontSize=title_size, fillColor=INK,
                 textAnchor="middle"))
    if sub:
        text_lines(d, x + w / 2, top - 9.5, sub, size=6.6, color=INK2, leading=8.4)


def arrow(d: Drawing, x1: float, y1: float, x2: float, y2: float, color=INK2, width: float = 1.0,
          head: float = 5, dashed: bool = False) -> None:
    ln = Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=width)
    if dashed:
        ln.strokeDashArray = [3, 2]
    d.add(ln)
    import math

    a = math.atan2(y2 - y1, x2 - x1)
    p1 = (x2 - head * math.cos(a - 0.4), y2 - head * math.sin(a - 0.4))
    p2 = (x2 - head * math.cos(a + 0.4), y2 - head * math.sin(a + 0.4))
    d.add(Polygon([x2, y2, *p1, *p2], fillColor=color, strokeColor=color, strokeWidth=0.5))


def poly_arrow(d: Drawing, pts: list[tuple[float, float]], color=INK2, width: float = 1.0, dashed: bool = False):
    for (x1, y1), (x2, y2) in zip(pts[:-2], pts[1:-1]):
        ln = Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=width)
        if dashed:
            ln.strokeDashArray = [3, 2]
        d.add(ln)
    arrow(d, *pts[-2], *pts[-1], color=color, width=width, dashed=dashed)


def label(d: Drawing, x: float, y: float, s: str, size: float = 6.6, color=INK2, anchor: str = "middle",
          font: str = "Body-Italic") -> None:
    d.add(String(x, y, s, fontName=font, fontSize=size, fillColor=color, textAnchor=anchor))


# ---------------------------------------------------------------- diagrams


def diagram_architecture() -> Drawing:
    w, h = CW, 330
    d = Drawing(w, h)
    cols = [
        ("1 · Capture", [("SocketPoller", ["psutil · every 2 s"]), ("ProcessResolver", ["name · exe · parents"]),
                         ("PacketSniffer", ["Scapy + Npcap (admin)"]), ("IdleMonitor", ["GetLastInputInfo"])]),
        ("2 · Correlation", [("Attributor", ["packet flow → PID"]), ("FlowTable", ["open · closing · closed"]),
                             ("Enricher", ["DNS → SNI → rDNS"])]),
        ("3 · Analysis", [("FeatureExtractor", ["1-min buckets · 5-min window"]), ("Baselines", ["EWMA · known sets"]),
                          ("8 Heuristics", ["H1 … H8, each 0–1"]), ("Scorer + Policy", ["noisy-OR → 0–100"]),
                          ("AlertManager", ["open · resolve · dedupe"])]),
        ("4 · Presentation", [("EventBus", ["async pub/sub"]), ("Textual TUI", ["live table · alerts"]),
                              ("CLI / headless", ["status · alerts · export"]), ("Web dashboard", ["planned (P8)"])]),
    ]
    gap = 14
    colw = (w - gap * 3) / 4
    top = h - 6
    col_h = 236
    bx_h = 34
    for i, (title, comps) in enumerate(cols):
        x = i * (colw + gap)
        d.add(Rect(x, top - col_h, colw, col_h, rx=6, ry=6, fillColor=LAYER_FILLS[i], strokeColor=LAYER_STROKES[i],
                   strokeWidth=1))
        d.add(String(x + colw / 2, top - 15, title, fontName="Body-Bold", fontSize=9, fillColor=LAYER_STROKES[i],
                     textAnchor="middle"))
        n = len(comps)
        avail = col_h - 30
        step = avail / n
        for j, (name, sub) in enumerate(comps):
            by = top - 26 - step * j - (step + bx_h) / 2 + 2
            box(d, x + 8, by, colw - 16, bx_h, name, sub, dashed=name == "Web dashboard",
                stroke=LAYER_STROKES[i] if name != "Web dashboard" else MUTED)
        if i < 3:
            arrow(d, x + colw + 2, top - col_h / 2, x + colw + gap - 2, top - col_h / 2, color=INK, width=1.4)
    # storage
    sy = 22
    d.add(Rect(colw * 0.55, sy, w - colw * 1.1, 30, rx=8, ry=8, fillColor=PANEL, strokeColor=INK2, strokeWidth=0.9))
    d.add(String(w / 2, sy + 17, "SQLite (WAL)  ·  flows · app_minutes · baselines · alerts · policy_rules · user_actions",
                 fontName="Body-Bold", fontSize=7.6, fillColor=INK, textAnchor="middle"))
    d.add(String(w / 2, sy + 7, "one transaction per tick · history survives restarts", fontName="Body",
                 fontSize=6.6, fillColor=INK2, textAnchor="middle"))
    for i in (1, 2):
        cx = i * (colw + gap) + colw / 2
        arrow(d, cx, top - col_h - 2, cx, sy + 32, color=INK2)
    # feedback loop
    px = 3 * (colw + gap) + colw / 2
    ax = 2 * (colw + gap) + colw * 0.8
    fy = top - col_h - 14
    poly_arrow(d, [(px + 18, top - col_h - 2), (px + 18, fy), (ax, fy), (ax, top - col_h - 2)], color=ACCENT,
               width=1.2, dashed=True)
    label(d, (px + ax) / 2 + 8, fy - 9, "user decisions: allow · deny · mute · “this is normal”", color=ACCENT)
    # config
    d.add(String(2 * (colw + gap) + colw / 2, 6, "", fontSize=1))
    label(d, 4, 6, "config/rules.yaml · ports.yaml · lolbins.yaml · blocklists/*.txt are hot-reloaded every 10 s",
          anchor="start", color=MUTED)
    return d


def diagram_pipeline() -> Drawing:
    w, h = CW, 175
    d = Drawing(w, h)
    steps = [("Poll", "socket table"), ("Drain", "sniffer counters"), ("Resolve", "processes"),
             ("Attribute", "flow → PID"), ("Flow table", "open/close"), ("Enrich", "names"),
             ("Features", "buckets"), ("Heuristics", "H1–H8"), ("Policy", "allow/deny"),
             ("Score", "noisy-OR"), ("Alerts", "lifecycle"), ("Persist", "SQLite"), ("Publish", "EventBus")]
    n1 = 7
    bw, bh, gap = (w - 6 * 10) / 7, 40, 10
    y1, y2 = h - 50, 30
    pos = []
    for i, (t, s) in enumerate(steps):
        if i < n1:
            x, y = i * (bw + gap), y1
        else:
            k = i - n1
            x, y = w - bw - k * (bw + gap) - (bw + gap) / 2, y2
        pos.append((x, y))
        layer = 0 if i < 3 else 1 if i < 6 else 2 if i < 11 else 3
        box(d, x, y, bw, bh, f"{i + 1}. {t}", [s], fill=LAYER_FILLS[layer], stroke=LAYER_STROKES[layer])
    for i in range(len(steps) - 1):
        (x1, y1_), (x2, y2_) = pos[i], pos[i + 1]
        if i < n1 - 1:
            arrow(d, x1 + bw + 1, y1_ + bh / 2, x2 - 1, y2_ + bh / 2)
        elif i == n1 - 1:
            poly_arrow(d, [(x1 + bw / 2, y1_ - 1), (x1 + bw / 2, (y1_ + y2_ + bh) / 2), (x2 + bw / 2,
                                                                                          (y1_ + y2_ + bh) / 2),
                           (x2 + bw / 2, y2_ + bh + 1)])
        else:
            arrow(d, x1 - 1, y1_ + bh / 2, x2 + bw + 1, y2_ + bh / 2)
    label(d, w / 2, 8, "one tick every 2 s · typical cost 5–15 ms on the test laptop · target under 250 ms",
          color=MUTED)
    return d


def state_diagram(states: dict[str, tuple[float, float]], edges: list[tuple], w: float, h: float,
                  start: tuple[str, ...] = ()) -> Drawing:
    d = Drawing(w, h)
    bw, bh = 78, 26
    for name, (x, y) in states.items():
        terminal = name in ("Closed", "Resolved", "False positive", "Unknown")
        box(d, x - bw / 2, y - bh / 2, bw, bh, name, fill=PANEL if terminal else colors.white,
            stroke=ACCENT if not terminal else INK2, r=11)
    for s in start:
        x, y = states[s]
        d.add(Rect(x - bw / 2 - 30, y - 3, 6, 6, rx=3, ry=3, fillColor=INK, strokeColor=INK))
        arrow(d, x - bw / 2 - 24, y, x - bw / 2 - 1, y)
    for e in edges:
        a, b, text = e[0], e[1], e[2]
        bend = e[3] if len(e) > 3 else None
        (x1, y1), (x2, y2) = states[a], states[b]
        if bend == "loop":
            pts = [(x1 + 12, y1 + bh / 2), (x1 + 12, y1 + bh / 2 + 14), (x1 - 12, y1 + bh / 2 + 14),
                   (x1 - 12, y1 + bh / 2 + 1)]
            poly_arrow(d, pts)
            label(d, x1, y1 + bh / 2 + 18, text)
            continue
        if bend:
            pts = [(x1 + bend[0], y1 + bend[1]), (x1 + bend[0], y1 + bend[2]), (x2 + bend[3], y1 + bend[2]),
                   (x2 + bend[3], y2 + bend[4])]
            poly_arrow(d, pts)
            label(d, (x1 + x2) / 2, y1 + bend[2] + (4 if bend[2] > 0 else -9), text)
            continue
        import math

        dx, dy = x2 - x1, y2 - y1
        L = math.hypot(dx, dy)
        ux, uy = dx / L, dy / L
        # clip to box edges
        def clip(ux, uy):
            tx = (bw / 2 + 2) / abs(ux) if ux else 1e9
            ty = (bh / 2 + 2) / abs(uy) if uy else 1e9
            return min(tx, ty)
        c = clip(ux, uy)
        arrow(d, x1 + ux * c, y1 + uy * c, x2 - ux * c, y2 - uy * c)
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        label(d, mx + (0 if abs(dx) > abs(dy) else 4), my + (4 if abs(dx) > abs(dy) else 0), text,
              anchor="middle" if abs(dx) > abs(dy) else "start")
    return d


def diagram_flow_lifecycle() -> Drawing:
    w = CW
    st = {"Pending": (95, 120), "Open": (250, 120), "Closing": (405, 120), "Unknown": (95, 35),
          "Closed": (405, 35)}
    edges = [("Pending", "Open", "socket appears ≤ 2 ticks"), ("Open", "Closing", "missing from 1 poll"),
             ("Closing", "Closed", "missing from 2 polls"), ("Pending", "Unknown", "no socket after 2 ticks"),
             ("Open", "Open", "seen again: last_seen, bytes", "loop"),
             ("Closing", "Open", "reappears", (-20, -13, -26, 20, -13))]
    d = state_diagram(st, edges, w, 165, start=("Pending",))
    label(d, 250, 31, "a socket seen in a poll opens a flow directly in Open", color=MUTED)
    return d


def diagram_alert_lifecycle() -> Drawing:
    d = Drawing(CW, 175)
    bw, bh = 86, 26
    pos = {"Open": (110, 120), "Acked": (300, 120), "Resolved": (110, 30), "False positive": (410, 30)}
    for name, (x, y) in pos.items():
        terminal = name in ("Resolved", "False positive")
        box(d, x - bw / 2, y - bh / 2, bw, bh, name, fill=PANEL if terminal else colors.white,
            stroke=INK2 if terminal else ACCENT, r=11)
    ox, oy = pos["Open"]
    ax_, ay = pos["Acked"]
    rx, ry = pos["Resolved"]
    fx, fy = pos["False positive"]
    # start
    d.add(Rect(ox - 3, oy + 42, 6, 6, rx=3, ry=3, fillColor=INK, strokeColor=INK))
    arrow(d, ox, oy + 42, ox, oy + bh / 2 + 1)
    label(d, ox + 5, oy + 30, "verdict reaches Medium", anchor="start")
    # open -> acked
    arrow(d, ox + bw / 2 + 1, oy, ax_ - bw / 2 - 1, ay)
    label(d, (ox + ax_) / 2, oy + 5, "acknowledge (k)")
    # open -> resolved
    arrow(d, ox, oy - bh / 2 - 1, rx, ry + bh / 2 + 1)
    label(d, ox + 5, (oy + ry) / 2, "below Medium for 5 min", anchor="start")
    # acked -> resolved (down then left)
    poly_arrow(d, [(ax_ - 20, ay - bh / 2 - 1), (ax_ - 20, ry), (rx + bw / 2 + 1, ry)])
    label(d, ax_ - 24, (ay + ry) / 2 - 8, "below Medium for 5 min", anchor="end")
    # acked -> false positive
    poly_arrow(d, [(ax_ + bw / 2 + 1, ay), (fx, ay), (fx, fy + bh / 2 + 1)])
    label(d, fx + 5, (ay + fy) / 2 + 8, "“this is normal” (n)", anchor="start")
    label(d, fx + 5, (ay + fy) / 2 - 1, "from Open or Acked", anchor="start")
    # resolved -> open (reopen)
    poly_arrow(d, [(rx - bw / 2 - 1, ry), (rx - bw / 2 - 26, ry), (rx - bw / 2 - 26, oy),
                   (ox - bw / 2 - 1, oy)], dashed=True)
    label(d, rx - bw / 2 - 30, (oy + ry) / 2 + 4, "reopens if it", anchor="end")
    label(d, rx - bw / 2 - 30, (oy + ry) / 2 - 5, "flares up ≤ 15 min", anchor="end")
    return d


def chart_scores() -> Drawing:
    w, h = CW, 250
    d = Drawing(w, h)
    order = [("updater.exe", "beacon from %TEMP% → :4444"), ("OneDrive.exe", "200 MB upload to new IP"),
             ("chrome.exe", "blocklisted IP"), ("powershell.exe", "Word → PowerShell")]
    lp = LinePlot()
    lp.x, lp.y, lp.width, lp.height = 34, 40, w - 150, h - 78
    data = []
    for name, _ in order:
        pts = [(round(t, 3), s) for t, s in DATA["series"][name]]
        data.append(pts)
    teams = [(round(t, 3), s) for t, s in DATA["series"]["ms-teams.exe"]]
    data.append(teams)
    lp.data = data
    for i in range(4):
        lp.lines[i].strokeColor = SERIES[i]
        lp.lines[i].strokeWidth = 1.6
    lp.lines[4].strokeColor = REF_GRAY
    lp.lines[4].strokeWidth = 1.0
    lp.lines[4].strokeDashArray = [2, 2]
    lp.xValueAxis.valueMin, lp.xValueAxis.valueMax, lp.xValueAxis.valueStep = 0, 25, 5
    lp.yValueAxis.valueMin, lp.yValueAxis.valueMax, lp.yValueAxis.valueStep = 0, 100, 25
    for ax in (lp.xValueAxis, lp.yValueAxis):
        ax.labels.fontName = "Body"
        ax.labels.fontSize = 7
        ax.labels.fillColor = INK2
        ax.strokeColor = RULE
        pass
    lp.yValueAxis.visibleGrid = True
    lp.yValueAxis.gridStrokeColor = colors.HexColor("#eceef1")
    lp.yValueAxis.gridStrokeWidth = 0.5
    lp.xValueAxis.labelTextFormat = "%d"
    # learning shading
    learn_end = 0.17 * 60
    x_of = lambda t: lp.x + t / 25 * lp.width  # noqa: E731
    y_of = lambda v: lp.y + v / 100 * lp.height  # noqa: E731
    d.add(Rect(lp.x, lp.y, x_of(learn_end) - lp.x, lp.height, fillColor=colors.HexColor("#f2f3f5"),
               strokeColor=None))
    d.add(String(lp.x + 4, lp.y + lp.height - 10, "learning period (demo profile: 10 min)", fontName="Body-Italic",
                 fontSize=6.8, fillColor=MUTED))
    d.add(lp)
    for v, name in ((25, "Low"), (50, "Medium"), (75, "High")):
        ln = Line(lp.x, y_of(v), lp.x + lp.width, y_of(v), strokeColor=MUTED, strokeWidth=0.6)
        ln.strokeDashArray = [4, 3]
        d.add(ln)
        d.add(String(lp.x + lp.width + 3, y_of(v) + 2, name, fontName="Body", fontSize=6.6, fillColor=MUTED))
    d.add(String(lp.x + lp.width / 2, 14, "minutes since NetSentry started", fontName="Body", fontSize=7.4,
                 fillColor=INK2, textAnchor="middle"))
    d.add(String(10, lp.y + lp.height / 2, "score", fontName="Body", fontSize=7.4, fillColor=INK2,
                 textAnchor="middle"))
    # legend (right): swatch + text in ink
    lx, ly = lp.x + lp.width + 40, lp.y + lp.height - 6
    for i, (name, desc) in enumerate(order):
        y = ly - i * 30
        d.add(Line(lx, y + 3, lx + 14, y + 3, strokeColor=SERIES[i], strokeWidth=2))
        d.add(String(lx + 18, y, name, fontName="Body-Bold", fontSize=7.2, fillColor=INK))
        d.add(String(lx + 18, y - 9, desc, fontName="Body", fontSize=6.4, fillColor=INK2))
    y = ly - 4 * 30
    ln = Line(lx, y + 3, lx + 14, y + 3, strokeColor=REF_GRAY, strokeWidth=1)
    ln.strokeDashArray = [2, 2]
    d.add(ln)
    d.add(String(lx + 18, y, "ms-teams.exe", fontName="Body-Bold", fontSize=7.2, fillColor=INK))
    d.add(String(lx + 18, y - 9, "normal 60 s heartbeat", fontName="Body", fontSize=6.4, fillColor=INK2))
    # direct labels at peaks (text in ink, numbers only)
    for i, (name, _) in enumerate(order):
        t, s = max(DATA["series"][name], key=lambda p: p[1])
        d.add(Rect(x_of(t) - 2.2, y_of(s) - 2.2, 4.4, 4.4, fillColor=SERIES[i], strokeColor=colors.white,
                   strokeWidth=1))
        d.add(String(x_of(t) + 4, y_of(s) + 3, str(s), fontName="Body-Bold", fontSize=7, fillColor=INK))
    return d


def tui_screenshot(name: str = "tui.svg"):
    try:
        from svglib.svglib import svg2rlg

        drw = svg2rlg(str(SP / name))
        if drw is None:
            return None
        scale = CW / drw.width
        drw.width, drw.height = drw.width * scale, drw.height * scale
        drw.scale(scale, scale)
        return drw
    except Exception as e:  # pragma: no cover
        print("svg failed:", e, file=sys.stderr)
        return None


# ---------------------------------------------------------------- page templates


def on_cover(c, doc) -> None:  # noqa: ANN001
    c.saveState()
    c.setFillColor(ACCENT)
    c.rect(0, H - 118 * mm, W, 118 * mm, stroke=0, fill=1)
    c.setFillColor(colors.HexColor("#2a5fa3"))
    for i in range(14):  # quiet network motif
        x = 30 * mm + i * 12 * mm
        c.circle(x, H - 104 * mm + (i % 3) * 5 * mm, 1.3 * mm, stroke=0, fill=1)
    c.setFillColor(colors.white)
    c.setFont("Body", 10)
    c.drawString(MARGIN, H - 32 * mm, "COMPUTER NETWORKS  ·  DIGITAL ASSIGNMENT 2")
    c.setFont("Body-Bold", 44)
    c.drawString(MARGIN, H - 58 * mm, "NetSentry")
    c.setFont("Body", 15)
    c.drawString(MARGIN, H - 70 * mm, "On-Device Network Behaviour Monitor for Applications")
    c.setFont("Body", 10.5)
    c.setFillColor(colors.HexColor("#d6e3f5"))
    c.drawString(MARGIN, H - 82 * mm, "Project documentation: architecture, pipeline, detection engine,")
    c.drawString(MARGIN, H - 88 * mm, "implementation, testing and validation")
    facts = [("8", "explainable heuristics"), ("2 s", "end-to-end tick"), ("54", "automated tests"),
             ("0", "infrastructure needed")]
    fw = (W - 2 * MARGIN) / 4
    for i, (big, small) in enumerate(facts):
        x = MARGIN + i * fw
        c.setFillColor(ACCENT)
        c.setFont("Body-Bold", 26)
        c.drawString(x, H - 150 * mm, big)
        c.setFillColor(INK2)
        c.setFont("Body", 9)
        c.drawString(x, H - 157 * mm, small)
    c.setStrokeColor(RULE)
    c.line(MARGIN, H - 135 * mm, W - MARGIN, H - 135 * mm)
    c.line(MARGIN, H - 166 * mm, W - MARGIN, H - 166 * mm)
    c.setFillColor(INK)
    c.setFont("Body-Bold", 11)
    c.drawString(MARGIN, 72 * mm, "Nainika Pathak")
    c.setFont("Body", 10)
    c.setFillColor(INK2)
    c.drawString(MARGIN, 66 * mm, "Registration no. 24BCE0230")
    c.drawString(MARGIN, 52 * mm, "Version 0.1.0  ·  October 2026")
    c.drawString(MARGIN, 46 * mm, "Source: github.com/Nainikap/mycafee")
    c.setStrokeColor(RULE)
    c.line(MARGIN, 38 * mm, W - MARGIN, 38 * mm)
    c.setFont("Body-Italic", 8.5)
    c.setFillColor(MUTED)
    c.drawString(MARGIN, 32 * mm, "A behaviour monitor, deliberately not an antivirus: metadata only, no payload "
                                  "decryption, every rule open and tunable.")
    c.restoreState()


def on_page(c, doc) -> None:  # noqa: ANN001
    c.saveState()
    c.setFont("Body", 7.5)
    c.setFillColor(MUTED)
    c.drawString(MARGIN, H - 12 * mm, "NetSentry — Project Documentation")
    c.drawRightString(W - MARGIN, H - 12 * mm, "Nainika Pathak · 24BCE0230")
    c.setStrokeColor(RULE)
    c.setLineWidth(0.5)
    c.line(MARGIN, H - 13.5 * mm, W - MARGIN, H - 13.5 * mm)
    c.drawCentredString(W / 2, 11 * mm, str(doc.page))
    c.restoreState()


class Doc(BaseDocTemplate):
    def __init__(self, path: str) -> None:
        super().__init__(path, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=20 * mm,
                         bottomMargin=18 * mm, title="NetSentry — Project Documentation",
                         author="Nainika Pathak", subject="Computer Networks DA2: NetSentry",
                         keywords="network monitoring, anomaly detection, JA3, psutil, heuristics")
        frame = Frame(MARGIN, 18 * mm, CW, H - 38 * mm, id="f", leftPadding=0, rightPadding=0, topPadding=0,
                      bottomPadding=0)
        self.addPageTemplates([PageTemplate("cover", [frame], onPage=on_cover),
                               PageTemplate("body", [frame], onPage=on_page)])

    def afterFlowable(self, flowable) -> None:  # noqa: ANN001
        toc = getattr(flowable, "_toc", None)
        if toc:
            level, text = toc
            key = f"s{self.seq.nextf('toc')}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
            self.notify("TOCEntry", (level, text, self.page, key))


# ================================================================ CONTENT

story.append(NextPageTemplate("body"))
story.append(PageBreak())
story.append(P("Contents", "h1"))
story.append(Rule())
toc = TableOfContents()
toc.levelStyles = [S["toc1"], S["toc2"]]
toc.dotsMinLevel = 0
story.append(toc)

# ---------------------------------------------------------------- 1
H1("Introduction")
story.append(P(
    "Every consumer machine runs a mix of applications that quietly open network connections: sync clients, "
    "telemetry, update checkers, and occasionally something less benign, such as spyware or a compromised binary "
    "beaconing to a command-and-control (C2) server. An ordinary user cannot tell <b>which process</b> is talking "
    "to <b>which host</b>, <b>how often</b> or <b>how much</b>. That gap is usually filled by heavyweight, "
    "closed-source security suites that rely on signature databases, cloud reputation and kernel drivers."))
story.append(P(
    "<b>NetSentry</b> is a lightweight, host-based network behaviour monitor that gives the user this "
    "visibility. It attributes every connection on the machine to the process that owns it, learns what is "
    "normal for each application, and scores deviations with <b>eight transparent, explainable heuristics</b>. "
    "The result is a live per-application severity, with plain-language evidence for every alert."))
NOTE("<b>Design principle.</b> Every alert has to answer three questions: <i>which app</i>, <i>what did it do</i>, "
     "and <i>why is that unusual for this app</i>. A rule that cannot explain itself in one sentence with numbers "
     "does not belong in NetSentry.")

H2("What NetSentry is, and is not")
T([["NetSentry is…", "NetSentry is not…"],
   ["A behaviour monitor that sees <b>who</b> an app talks to, <b>how much</b> and <b>how often</b>",
    "An antivirus: it has no malware signature database and does not scan files"],
   ["Metadata-based: IPs, ports, timing, byte counts, DNS names, TLS fingerprints",
    "A content inspector: it never decrypts TLS or reads payloads"],
   ["Transparent: every weight and threshold is a line in a YAML file",
    "A black-box ML model (an Isolation Forest is listed as future work)"],
   ["A single-host daemon with zero infrastructure", "A network sensor on a SPAN port, like Zeek or Suricata"],
   ["Advisory: it scores and alerts; the user decides", "A firewall: it does not block traffic"]],
  [1, 1])

H2("Objectives")
story.append(P("The DA2 report set five objectives. The table shows where each one is met in the implementation."))
T([["#", "Objective (from DA2)", "Delivered by"],
   ["1", "Capture inbound/outbound connections and attribute each to its process (PID + executable)",
    "<font name=Mono>capture/socket_poller.py</font>, <font name=Mono>process_resolver.py</font>, "
    "<font name=Mono>pipeline/attributor.py</font>"],
   ["2", "Log metadata: destination IP/domain, port, protocol, volume and frequency over time",
    "Flow table, enricher, SQLite <font name=Mono>flows</font> and <font name=Mono>app_minutes</font> tables"],
   ["3", "Rule-based heuristic engine that flags suspicious connections",
    "Eight heuristics, noisy-OR scorer, alert manager (Section 8)"],
   ["4", "Dashboard/CLI with severity levels and per-app history",
    "Textual TUI, <font name=Mono>netsentry</font> CLI, per-minute history sparklines"],
   ["5", "Whitelist/blacklist of applications or destinations",
    "Policy engine: allow / deny / mute / “this is normal”, from the TUI or CLI"]],
  [0.3, 3, 3])

H2("How this document is organised")
B(["<b>Sections 2–3</b>: background, the gap NetSentry fills, and its scope.",
   "<b>Sections 4–5</b>: system architecture and the end-to-end pipeline that runs every two seconds.",
   "<b>Sections 6–8</b>: each layer in depth: capture, correlation, and the detection engine (features, "
   "baselines, the eight heuristics, scoring, alerts and the feedback loop).",
   "<b>Sections 9–10</b>: data model, storage and the technical implementation (stack, modules, CLI, dashboard, "
   "configuration).",
   "<b>Section 11</b>: testing and validation, including real measurements and the bugs that live testing found.",
   "<b>Sections 12–14</b>: limitations, future work, and how to run the project.",
   "<b>Appendices</b>: the full default rule file, a glossary and references."])

# ---------------------------------------------------------------- 2
H1("Background and Existing Systems")
story.append(P(
    "Five representative tools were reviewed, covering commercial per-app visibility, packet analysis and "
    "network intrusion detection. They split into two camps, and NetSentry is positioned in the gap between "
    "them."))
T([["System", "Approach", "Process attribution", "Deployment", "Limitation for an individual endpoint"],
   ["GlassWire", "Visual traffic history + firewall", "Yes (Windows/Android)", "Single host, closed source",
    "Anomaly logic undocumented and not tunable"],
   ["Little Snitch", "Connection-time interception", "Yes (macOS/Linux)", "Single host, closed source",
    "Allow/deny prompts, no behavioural risk ranking"],
   ["Zeek", "Scriptable behavioural analysis", "No", "Network chokepoint / sensor",
    "Needs a SPAN port; no notion of a local process"],
   ["Wireshark", "Manual packet inspection", "No (by default)", "Single host, manual",
    "Not a monitor: someone has to be watching"],
   ["Suricata", "Signature-based IDS/IPS", "No", "Network chokepoint / sensor",
    "Catches known-bad patterns, not novel behaviour"]],
  [1.1, 1.6, 1.3, 1.4, 2.2])

H2("The gap")
story.append(P(
    "The tools with per-process attribution (GlassWire, Little Snitch) are closed-source, tied to one platform, "
    "and offer no inspectable scoring logic. The tools with open, explainable, rule-based detection (Zeek, "
    "Suricata) are built to watch a network segment and have no concept of “which local process opened this”. "
    "Wireshark is a manual tool and belongs to neither camp."))

H2("Novelty")
T([["", "What NetSentry combines", "Compared with"],
   ["1", "<b>Open, per-process attribution.</b> Process-level mapping, with the parent chain, where every "
         "heuristic and weight is a line in a config file that a grader can read and change.",
    "GlassWire / Little Snitch (closed)"],
   ["2", "<b>Zero-infrastructure behavioural scoring.</b> A Zeek-style transparent rule engine running as a "
         "single-host daemon. A Suricata-style blocklist check is one heuristic among eight, not the whole "
         "strategy.", "Zeek / Suricata (need a sensor)"],
   ["3", "<b>A feedback loop that learns the user's baseline.</b> Per-app baselines plus allow/deny/“this is "
         "normal” decisions correct the engine for each machine, instead of one fixed threshold for everyone.",
    "All five (static rules or prompts)"]],
  [0.25, 4.2, 1.6])

# ---------------------------------------------------------------- 3
H1("Scope")
story.append(P(
    "NetSentry is deliberately scoped as a <b>network-behaviour monitor, not an antivirus</b>. This is what keeps "
    "it buildable and honest within a semester."))
T([["Component", "Status", "Notes"],
   ["Connection capture (OS socket table)", "In scope", "psutil → GetExtendedTcpTable / GetExtendedUdpTable"],
   ["Process attribution + lineage", "In scope", "PID, executable, user, command line, up to 4 parents"],
   ["Packet capture for bytes, DNS, SNI", "In scope", "Optional; needs administrator rights + Npcap"],
   ["JA3 / JA3N TLS fingerprinting", "In scope", "From the cleartext ClientHello; no decryption"],
   ["Metadata heuristics + scoring", "In scope", "Eight heuristics, noisy-OR, per-app baselines"],
   ["Payload / TLS decryption", "Out of scope", "Would need MITM certificate injection: invasive"],
   ["Malware signature database", "Out of scope", "Not maintainable in a semester"],
   ["Kernel driver / rootkit detection", "Out of scope", "Needs kernel-mode development and code signing"],
   ["Blocking traffic", "Out of scope (stretch)", "Optional Windows Firewall rule, never automatic"],
   ["IP reputation (AbuseIPDB)", "Stretch (P8)", "Config hooks exist; not implemented yet"]],
  [2.3, 1.2, 3])
NOTE("Metadata alone is genuinely useful. An unfamiliar background process uploading 200 MB to a new, unnamed "
     "IP at 3 AM while the user is away is a strong signal, without reading a single byte of payload. Section "
     "8.5 shows that exact case scoring <b>77 (High)</b>.")

H2("Operating modes")
story.append(P("Packet capture needs administrator rights, so NetSentry runs in one of two modes and "
               "degrades gracefully. Missing data is never treated as evidence of safety: the heuristics that "
               "need it report <i>n/a</i>."))
T([["Capability", "Standard mode (no admin)", "Full mode (admin + Npcap)"],
   ["Socket table, PIDs, parent chain", "Yes", "Yes"],
   ["Per-flow byte counts", "—", "Yes"],
   ["Domain names", "Reverse DNS only", "DNS answers + TLS SNI + reverse DNS"],
   ["TLS fingerprints (JA3/JA3N)", "—", "Yes"],
   ["UDP flows (QUIC, DNS, VoIP)", "—", "Yes (attributed by local port)"],
   ["Exact connection start times (SYN)", "2 s poll resolution", "Yes"],
   ["Heuristics available", "6 of 8 (H4 volume, H8 TLS are n/a)", "All 8"]],
  [2, 2, 2])

# ---------------------------------------------------------------- 4
H1("System Architecture")
story.append(P(
    "NetSentry is a single Python process with four layers. Each layer can be tested in isolation, and data "
    "flows strictly left to right. The only arrow going backwards is the user's feedback."))
story.append(KeepTogether([diagram_architecture(),
                           P("Figure 1. Layered architecture. Arrows show data flow; the dashed arrow is the "
                             "feedback loop.", "caption")]))

H2("Layers")
T([["Layer", "Responsibility", "Input → Output", "Tested in isolation by"],
   ["1 · Capture", "Read raw OS state and packets", "OS → sockets, processes, packet stats, DNS answers, "
                                                    "TLS hellos, idle time",
    "<font name=Mono>netsentry capture</font> vs <font name=Mono>netstat -ano</font>"],
   ["2 · Correlation", "Turn samples into attributed, named flows", "samples → Flow (PID, app, domain, bytes)",
    "Hand-built ticks in <font name=Mono>test_flows.py</font>"],
   ["3 · Analysis", "Features, baselines, heuristics, score, alerts", "flows → Verdict per app, Alert",
    "Synthetic windows in <font name=Mono>test_heuristics.py</font>"],
   ["4 · Presentation", "Show state, take user decisions", "events → UI; key presses → policy rules",
    "Headless Textual pilot + synthetic scenario"]],
  [1.1, 1.8, 2.2, 1.9])
story.append(P(
    "The DA2 proposal described three layers. The middle <b>correlation</b> stage is now a layer of its own, "
    "because joining packets to sockets to processes is the trickiest part of the system and needs its own "
    "tests."))

H2("Components")
T([["Component", "Module", "What it does"],
   ["SocketPoller", "capture/socket_poller.py", "Reads the connection table every 2 s; drops TIME_WAIT, PID-0 and "
                                                "loopback entries; separates listening sockets"],
   ["ProcessResolver", "capture/process_resolver.py", "PID → name, exe, user, cmdline and parent chain; cached, "
                                                      "evicted when the process exits"],
   ["PacketSniffer", "capture/sniffer.py", "Scapy on Npcap: bytes/packets per 5-tuple, SYN times, DNS answers, "
                                           "TLS ClientHello"],
   ["TLS parser", "capture/tls.py", "Hand-written ClientHello parser: SNI, JA3, JA3N"],
   ["IdleMonitor", "capture/idle.py", "Seconds since last keyboard/mouse input (Win32 GetLastInputInfo)"],
   ["Capture sources", "capture/source.py", "LiveSource, ReplaySource (JSONL), ListSource (tests), Recorder"],
   ["Attributor", "pipeline/attributor.py", "Joins packet counters to sockets → PID; pending buffer → “unknown”"],
   ["FlowTable", "pipeline/flow_table.py", "Flow lifecycle, direction (inbound/outbound), byte deltas"],
   ["Enricher", "pipeline/enricher.py", "Domain for each IP: DNS cache → SNI → async reverse DNS; eTLD+1"],
   ["Engine", "pipeline/engine.py", "Orchestrates one tick; reloads config; applies user actions"],
   ["FeatureExtractor", "detection/features.py", "Per-app 1-minute buckets and the 5-minute window"],
   ["Baseline", "detection/baseline.py", "EWMA statistics, known destinations/ports/JA3N, hour histogram"],
   ["Heuristics", "detection/heuristics/*.py", "Eight pure functions → score 0–1 plus evidence"],
   ["Scorer / Policy", "detection/scorer.py, policy.py", "Noisy-OR combination; allow/deny/mute overrides"],
   ["AlertManager", "detection/alerts.py", "One alert per app per incident; resolve, reopen, false positive"],
   ["Store", "storage/db.py, schema.sql", "SQLite in WAL mode; one transaction per tick"],
   ["EventBus / UI", "bus.py, ui/tui/app.py, cli.py", "Async pub/sub; Textual dashboard; command line"]],
  [1.3, 2, 3.7], mono_cols=(1,))

H2("Runtime and threading model")
story.append(P(
    "One asyncio event loop owns all engine state, so the engine needs no locks. Blocking OS calls run in a "
    "thread pool. The packet sniffer runs in Scapy's own thread and only writes to its private counter "
    "dictionary, which the engine swaps out atomically once per tick."))
CODE("""
main thread ── asyncio event loop
   ├─ Engine.tick() every 2 s ............... orchestrates the pipeline (Section 5)
   │     ├─ run_in_executor(SocketPoller.poll)        blocking psutil call → thread
   │     ├─ run_in_executor(ProcessResolver.resolve_many)
   │     ├─ sniffer.drain()  → swap counters under a lock (microseconds)
   │     └─ attribute → flows → enrich → features → score → alerts → SQLite → EventBus
   ├─ Enricher reverse-DNS lookups ......... async, max 4 concurrent, 3 s timeout, cached 1 h
   └─ UI: Textual app (same loop) or headless console printer

sniffer thread ── Scapy AsyncSniffer callback
   └─ counters[5-tuple] += packet length; DNS answers / TLS hellos → lists (under a lock)
""")
story.append(P(
    "Every time-dependent component takes a <font name=Mono>Clock</font>. Live runs use the system clock. "
    "Replays and tests inject a <font name=Mono>FakeClock</font> driven by the recorded timestamps, which makes "
    "every run deterministic. The engine never imports a UI module; the TUI, the headless printer and a future "
    "web dashboard all subscribe to the same EventBus."))

H2("Key design decisions")
T([["#", "Decision", "Alternatives", "Why"],
   ["D1", "Python 3.13 for the whole core", "Node.js", "psutil, Scapy and Textual cover all three layers in one "
                                                      "language"],
   ["D2", "Poll the socket table + optional sniffer", "ETW kernel provider; per-connection EStats",
    "Works without admin; Npcap was already installed; ETW is complex to consume from Python"],
   ["D3", "1-minute buckets + EWMA baselines", "Raw event windows; full recompute",
    "Constant memory per app, easy to explain and persist"],
   ["D4", "Noisy-OR score combination", "Weighted average", "A weighted average dilutes one strong signal "
                                                            "among quiet ones; noisy-OR lets signals reinforce"],
   ["D5", "SQLite in WAL mode", "JSON files", "No server, queryable history, readers never block the writer"],
   ["D6", "Textual TUI first, web later", "Web first", "Fastest path to an end-to-end demo; same EventBus"],
   ["D7", "Record / replay of raw ticks", "Live-only testing", "Deterministic tests, safe offline demo, offline "
                                                              "tuning"],
   ["D8", "Normalised JA3 (JA3N) alongside JA3", "JA4", "Chrome randomises extension order; sorting keeps JA3 "
                                                       "stable"],
   ["D9", "App identity = lower-cased exe path", "Process name", "Any binary can be called chrome.exe; the "
                                                                 "path is the real identity"]],
  [0.35, 1.6, 1.4, 2.6])

# ---------------------------------------------------------------- 5
H1("End-to-End Pipeline")
story.append(P(
    "The engine runs one <b>tick</b> every two seconds. A tick is the unit of work for the whole system: it "
    "takes a snapshot of the machine and carries it all the way to the screen and the database."))
story.append(KeepTogether([diagram_pipeline(),
                           P("Figure 2. The 13 steps of a tick, coloured by layer (blue capture, green "
                             "correlation, orange analysis, violet presentation).", "caption")]))

H2("Step by step")
T([["#", "Stage", "What happens"],
   ["1", "Poll", "psutil.net_connections(\"inet\") in a worker thread. TIME_WAIT/PID-0 entries and loopback "
                 "remotes are dropped; LISTEN and UDP sockets are kept separately."],
   ["2", "Drain sniffer", "Swap the sniffer's counter dict for an empty one; collect DNS answers and TLS hellos "
                          "(full mode only)."],
   ["3", "Resolve processes", "New PIDs get name, exe, user, cmdline and parent chain, using one parent-PID "
                              "snapshot for the whole batch."],
   ["4", "Attribute", "TCP: exact 5-tuple match to a socket. UDP: match on local port. Unmatched packets wait "
                      "two ticks, then go to the app “unknown”."],
   ["5", "Flow table", "New key → open a flow; seen again → update; missing two polls → close. Flows accepted "
                       "on a listening port are marked inbound."],
   ["6", "Enrich", "Find a name for the remote IP (DNS cache → SNI → reverse DNS) and its destination key."],
   ["7", "Features", "Add each flow's activity to its app's current 1-minute bucket; mark the app dirty."],
   ["8", "Heuristics", "Run all eight heuristics on every dirty app's 5-minute window against its baseline."],
   ["9", "Policy", "Apply the user's allow/deny/mute rules for this app and its destinations."],
   ["10", "Score", "Noisy-OR combination → 0–100 → severity (None/Low/Medium/High)."],
   ["11", "Alerts", "Open, update, escalate or resolve this app's alert."],
   ["12", "Persist", "One SQLite transaction: new and closed flows, byte updates every 30 s, alerts."],
   ["13", "Publish", "Publish a TickResult (app rows, alert events, stats) on the EventBus for the UI."]],
  [0.3, 1.1, 5])

H2("Slower loops")
T([["Loop", "Period", "Job"],
   ["Bucket close", "60 s", "Freeze every app's current minute; write it to app_minutes; fold clean minutes "
                            "into the baseline"],
   ["Baseline flush", "5 min", "Write changed baselines to SQLite"],
   ["Config reload", "10 s", "Re-read rules.yaml and the static lists if their modification time changed; "
                             "reload policy rules if the table changed"],
   ["Retention", "1 h", "Delete closed flows older than 7 days and minute history older than 30 days"]],
  [1.2, 0.8, 4])

H2("Flow lifecycle", need=85)
story.append(KeepTogether([diagram_flow_lifecycle(),
                           P("Figure 3. Flow states. A flow survives one missed poll, so a connection that "
                             "briefly drops out of the table is not counted twice.", "caption")]))

H2("Naming destinations")
story.append(P("A remote IP is turned into a <b>destination key</b>, which is what baselines remember:"))
B(["<b>1. DNS answer cache</b> (full mode): the sniffer parses DNS responses and maps each IP to the name that "
   "was originally asked for, following CNAME chains. Kept for max(TTL, 5 min).",
   "<b>2. TLS SNI</b> (full mode): the server name in that flow's ClientHello.",
   "<b>3. Reverse DNS</b> (both modes): async lookup, max 4 concurrent, 3 s timeout, cached for 1 hour.",
   "<b>Destination key</b>: the registrable domain (eTLD+1, e.g. <font name=Mono>a1.cdn.example.co.uk → "
   "example.co.uk</font>) using an offline Public Suffix List. A bare IP falls back to its /24 (IPv4) or /48 "
   "(IPv6) prefix.",
   "A flow's destination is settled when a name is found, the lookup fails, or 4 s have passed. This "
   "stops one connection from being counted as two “new destinations” (once as an IP, then as a name)."])

H2("Record and replay")
story.append(P(
    "<font name=Mono>netsentry record</font> writes one JSON line per tick containing the <b>raw capture "
    "inputs</b>: sockets, processes, packet counters, DNS and TLS events, and idle time. "
    "<font name=Mono>netsentry replay</font> feeds a recording through the identical pipeline with a fake "
    "clock. The same mechanism powers <font name=Mono>netsentry demo</font>, a synthetic 25-minute scenario "
    "used for testing and presentations (Section 11.2)."))

# ---------------------------------------------------------------- 6
H1("Capture Layer")
H2("Socket table polling")
story.append(P(
    "On Windows, <font name=Mono>psutil.net_connections(kind=\"inet\")</font> wraps the IP Helper API calls "
    "<font name=Mono>GetExtendedTcpTable</font> and <font name=Mono>GetExtendedUdpTable</font>. These return "
    "every TCP/UDP endpoint with its owning PID, and need no administrator rights. A poll takes 3–30 ms on the "
    "test laptop."))
B(["Entries in <b>TIME_WAIT</b> or <b>CLOSE</b>, or with PID 0, are skipped: Windows reports TIME_WAIT sockets "
   "under the idle process, so they have no attributable owner.",
   "<b>IPv4-mapped IPv6</b> addresses (<font name=Mono>::ffff:1.2.3.4</font>) are unwrapped and IPv6 zone IDs "
   "stripped, so one host always has one spelling.",
   "Remote addresses classed as <b>loopback</b> are ignored by default. <b>LAN</b> means RFC 1918, CGNAT, "
   "link-local and ULA ranges, defined explicitly; Python's <font name=Mono>is_private</font> also counts "
   "documentation ranges as private, which mislabelled test IPs as LAN during development.",
   "Sockets without a remote end (TCP LISTEN, all UDP) are kept as <b>listeners</b>. They are used to "
   "attribute UDP packets and to tell inbound connections from outbound ones."])

H2("Process resolution and lineage")
story.append(P(
    "For each PID the resolver records name, executable path, user, command line and the <b>parent chain</b> "
    "(up to four levels). The app identity is the lower-cased executable path, so a "
    "<font name=Mono>svchost.exe</font> in <font name=Mono>%TEMP%</font> is a different app from the real one "
    "in System32, and that difference is itself a signal (H7)."))
H3("Performance work (measured on the development laptop, about 40 networked processes)")
T([["Version", "Cold start", "Steady state", "Problem"],
   ["First draft", "3.6 s", "~750 ms per tick", "Re-validated every cached PID's create time on every call"],
   ["Throttled re-check", "3.5 s", "spikes to 700 ms", "Each Process.ppid() call on Windows snapshots all "
                                                         "processes (~33 ms), once per parent hop"],
   ["One ppid snapshot per batch", "0.9 s", "0–1 ms", "—"],
   ["Evict on exit instead of re-checking", "0.9 s", "0–1 ms, no spikes", "—"]],
  [1.8, 0.9, 1.2, 3])
story.append(P(
    "A PID cannot be reused while its process still exists, so it is enough to evict cached PIDs that "
    "disappear from <font name=Mono>psutil.pids()</font> (one cheap EnumProcesses call per poll). "
    "Parent-chain walks check that each parent is older than its child, which detects a parent PID that was "
    "reused by a younger process. Protected system processes that deny access appear as "
    "<font name=Mono>pid:N</font> rather than crashing the poll."))

H2("Packet sniffer (full mode)")
story.append(P(
    "When NetSentry runs as administrator, a Scapy <font name=Mono>AsyncSniffer</font> on Npcap captures with "
    "the BPF filter <font name=Mono>ip or ip6</font> and <font name=Mono>store=False</font>. The callback is "
    "kept short:"))
B(["Packet direction is decided by checking the source or destination against this machine's interface "
   "addresses (refreshed every 30 s). The key is always oriented from the local side "
   "(<font name=Mono>proto, local ip, local port, remote ip, remote port</font>), which matches the socket "
   "table exactly.",
   "Bytes and packets are added per direction. An outgoing SYN without ACK records a precise "
   "<b>connection start time</b> (up to 20 per flow) for beacon detection.",
   "Payload is parsed only for <b>UDP source port 53</b> (DNS answers) and the <b>first three outgoing data "
   "packets</b> of a TCP flow (looking for a TLS ClientHello).",
   "If Scapy cannot open Npcap, NetSentry logs one clear reason and continues in standard mode."])

H2("TLS ClientHello, JA3 and JA3N")
story.append(P(
    "The ClientHello is the first message of a TLS handshake, and it is sent in clear text even in TLS 1.3. "
    "NetSentry parses it by hand (<font name=Mono>capture/tls.py</font>) to extract the <b>SNI</b> (the server "
    "name) and a <b>JA3 fingerprint</b> of the client's TLS stack:"))
story.append(P("JA3 = MD5( version , ciphers , extensions , elliptic_curves , point_formats )", "formula"))
story.append(P(
    "Each field is a dash-separated list of decimal values, for example "
    "<font name=Mono>771,4865-4866-49195,0-23-65281-10-11,29-23-24,0</font>. GREASE values (0x0A0A, 0x1A1A, …), "
    "which browsers insert at random, are removed. Since 2023 Chrome also <b>shuffles its extension order</b> "
    "on every connection, which makes raw JA3 change every time. NetSentry therefore also computes <b>JA3N</b>, "
    "the same hash with the extension list sorted. JA3N stays stable for a given TLS library, so it is the "
    "value baselines remember. Modern ClientHellos with post-quantum key shares can exceed one TCP segment, so "
    "the sniffer reassembles up to three segments (16 KB maximum) before parsing."))

H2("DNS answers and user idle time")
story.append(P(
    "DNS responses are parsed with Scapy's DNS layer. Every A/AAAA record is mapped back to the <i>question</i> "
    "name, so <font name=Mono>www.example.com → CNAME edge.cdn.net → 93.184.215.14</font> records the IP "
    "under <font name=Mono>www.example.com</font>. User idle time comes from the Win32 call "
    "<font name=Mono>GetLastInputInfo</font>, computed in 32-bit arithmetic so it stays correct when the tick "
    "counter wraps every 49.7 days."))

# ---------------------------------------------------------------- 7
H1("Correlation Layer")
H2("Attribution rules")
T([["Case", "Rule"],
   ["TCP packet counters", "Exact 5-tuple match against the socket table, or against an already-known flow"],
   ["UDP packet counters", "Match on local port against UDP listeners. Windows UDP sockets have no remote end, "
                           "so this is the only way to attribute UDP"],
   ["No match yet", "Held in a <i>pending</i> buffer for 2 ticks; the socket often appears one poll after the "
                    "first packet"],
   ["Still no match", "Attributed to the app <font name=Mono>unknown</font>, so the traffic is counted and "
                      "visible rather than silently dropped"]],
  [1.5, 5])

H2("Flow direction")
story.append(P(
    "A TCP flow whose local port is one of this machine's <b>LISTEN</b> ports was accepted from outside: this "
    "machine is the server, and the remote port is the client's random ephemeral port. Such flows are marked "
    "<b>inbound</b>. They still count towards destinations, but are excluded from the port rule (H1) and from "
    "beacon timing (H2). This rule was added after live testing showed a local test server being flagged for "
    "“connecting to non-standard port 5xxxx” (Section 11.5)."))

H2("Destination keys")
story.append(P(
    "Grouping by registrable domain means content-delivery sub-domains do not each count as “new”, and a bare "
    "IP is grouped with its /24 neighbours (one cloud host often rotates within a block). The display keeps the "
    "full name. The key used for baselines is the coarser one."))

# ---------------------------------------------------------------- 8
H1("Detection Engine")
story.append(P(
    "Every rule is a function of <b>features</b> (what the app is doing now) and its <b>baseline</b> (what it "
    "normally does). All numbers below are defaults from <font name=Mono>config/rules.yaml</font> and can be "
    "changed while NetSentry is running."))

H2("Features: buckets and windows")
story.append(P(
    "Activity is rolled into a <b>per-app bucket for each minute</b>. The <b>window</b> a heuristic sees is the "
    "last five closed buckets plus the current partial one, so every decision is based on recent behaviour, "
    "not on a single poll."))
T([["Feature", "Per bucket", "Used by"],
   ["new_flows", "Outbound connections opened in the minute (pre-existing ones at startup are not counted)",
    "H2 rate"],
   ["starts[ip:port]", "Last 20 connection start times per remote endpoint, kept across buckets",
    "H2 beacon"],
   ["dests / new dests", "Destination keys contacted, and those not in the baseline", "H3"],
   ["rports, listen ports", "Remote (protocol, port) pairs used; local LISTEN ports", "H1"],
   ["bytes_out / bytes_in", "Summed per remote IP (full mode). Only outbound is scored, so downloads and "
                            "game patches do not trigger it", "H4"],
   ["ja3 / ja3n", "TLS fingerprints seen (full mode)", "H8"],
   ["idle_max, hour", "User idle seconds; local hour of day", "H6"],
   ["process", "Name, exe path, parent chain", "H7"]],
  [1.2, 4, 0.8], mono_cols=(0,))

H2("Baselines")
story.append(P(
    "Each app (keyed by exe path) has one baseline. It keeps an <b>exponentially weighted moving average "
    "(EWMA)</b> of the log of three per-minute features: <font name=Mono>new_flows</font>, "
    "<font name=Mono>unique_dests</font> and <font name=Mono>bytes_out</font>. The log keeps heavy-tailed "
    "traffic manageable. The baseline also stores known destinations, ports and JA3N hashes, plus a 24-hour "
    "activity histogram."))
story.append(P("v = log(1 + x)      mean ← mean + α·(v − mean)      var ← (1 − α)·(var + α·(v − mean_old)²)",
               "formula"))
story.append(P(
    "With α = 0.02, the half-life is about 35 <i>active</i> minutes. The baseline is only updated on minutes "
    "in which the app actually did something, so an app that runs once an hour is compared with its own active "
    "minutes, not diluted by zeros. Deviation is measured as a z-score and mapped linearly to 0–1:"))
story.append(P("z = (v − mean) / max(√var, 0.5)          dev = clamp((z − 3) / (6 − 3), 0, 1)", "formula"))
T([["Concept", "Rule"],
   ["App maturity", "≥ 30 active minutes <b>and</b> ≥ 24 h since first seen (demo profile: 5 minutes and 10 "
                    "minutes). Statistical rules only judge mature apps."],
   ["System maturity", "NetSentry itself has run for the learning period. The start time is stored in the "
                       "database, so it survives restarts."],
   ["New app", "An app first seen <i>after</i> the system matured. Brand-new software appearing on an "
               "established machine is suspicious in itself, which closes the “new malware has no baseline” "
               "gap."],
   ["Poisoning guard", "A minute only teaches the baseline if the app's verdict stayed below Medium during it, "
                       "or the user later said “this is normal”. An attacker cannot slowly train the engine to "
                       "accept an exfiltration."]],
  [1.3, 5])

H2("The eight heuristics")
story.append(P(
    "Each heuristic is a pure function <font name=Mono>(window, baseline, context) → (score 0–1 or n/a, "
    "evidence)</font>. Its score is the maximum over its sub-rules. Its <b>weight</b> is the most it can "
    "contribute on its own."))


def heuristic(code: str, name: str, weight: str, rows: list[list[str]], note: str = "", example: str = "") -> None:
    parts = [P(f"<b>{code} · {name}</b>  <font color='#7a808c'>weight {weight}</font>", "h3")]
    story.extend(parts)
    T([["Sub-rule", "Score"]] + rows, [5.2, 1])
    if note:
        story.append(P(note, "small"))
    if example:
        story.append(P(f"Evidence example: <font name=Mono>{example}</font>", "small"))
    story.append(Spacer(1, 4))


heuristic("H1", "Unusual port usage", "0.45", [
    ["Remote port on the suspicious list: 4444 (Metasploit), 1337, 31337, 6666–6669 (IRC), 5555, 9001/9030 (Tor), "
     "12345, 23", "1.0"],
    ["Mature app uses a <b>TCP</b> port outside the common list that it has never used before", "0.5 (0.6 if ≥ 49152)"],
    ["Mature app starts listening on a new local port", "0.5"]],
    "UDP is skipped for the “new port” rule because WebRTC, games and VoIP legitimately use random high UDP "
    "ports. Inbound flows are skipped entirely.",
    "connected to 198.51.100.23:4444 (suspicious port: Metasploit default)")
heuristic("H2", "Connection frequency spike / beaconing", "0.55", [
    ["<b>Rate:</b> dev(new_flows) for a mature app, only if ≥ 10 new connections in the minute", "0–1"],
    ["<b>Beacon:</b> ≥ 6 connection starts to one ip:port in the last 5 min; coefficient of variation cv = "
     "std/mean of the gaps. cv ≤ 0.10 → 1.0, cv ≥ 0.35 → 0, linear between", "0–1"],
    ["Beacon to a destination the mature app already knows, or while NetSentry is still learning", "× 0.3"]],
    "Malware C2 implants “check in” at machine-regular intervals; humans do not. Legitimate heartbeats (Teams, "
    "Slack) are also regular, but go to known destinations, which is why they are damped. In standard mode only "
    "gaps ≥ 10 s are trusted, because start times are quantised to the 2 s poll.",
    "20 connections to 198.51.100.23:4444 every 30.1 s ± 1.0 s (cv 0.03)")
heuristic("H3", "New / unrecognised destination", "0.35", [
    ["Mature app contacts destinations not in its baseline: 0.5 + 0.1 × (n − 1), capped at 0.8", "0.5–0.8"],
    ["New app (first seen after the system matured) uses the network", "0.5"],
    ["Bonus if any new destination has no name at all (direct-to-IP)", "+ 0.2"],
    ["All new destinations are on the LAN", "× 0.5"],
    ["System or app still learning", "n/a"]],
    example="first contact with 185.199.110.153:443; direct-to-IP, no DNS name")
heuristic("H4", "Outbound data volume anomaly (full mode)", "0.60", [
    ["Mature app: dev(bytes_out per minute), only if ≥ 5 MB in the minute", "0–1"],
    ["New app: ≥ 50 MB in one minute", "0.7"]],
    "The floor stops a tiny app jumping from 1 KB to 50 KB from triggering it. Destinations the user allowed "
    "for this app are subtracted first.",
    "uploaded 74.5 MB in 1 min to 185.199.110.153; usually about 353.8 KB/min (z = 10.6)")
heuristic("H5", "Known-bad IP / domain", "0.95 + override", [
    ["Remote IP in blocklists/ips.txt (single IPs or CIDR ranges)", "1.0"],
    ["Domain, or any parent domain, in blocklists/domains.txt", "1.0"]],
    "Any hit raises the final score to at least 80 (High). A user “allow” cannot hide it; it is capped at 60 "
    "and labelled allowed-but-blocklisted.")
heuristic("H6", "Off-hours activity", "0.25 (amplifier)", [
    ["User idle ≥ 10 min while the app is significantly active (≥ 3 new connections or ≥ 1 MB out)", "0.6"],
    ["Hour inside quiet hours (01:00–06:00), or a mature app is active in an hour holding < 2 % of its history",
     "0.6"],
    ["Both", "1.0"]],
    "Its weight is low on purpose. On its own it reaches Low at most, but it lifts a real anomaly a severity "
    "level.")
heuristic("H7", "Suspicious process lineage", "0.60", [
    ["<b>Masquerading:</b> name of a Windows system binary (svchost.exe, lsass.exe, …) running from outside the "
     "system folders", "1.0"],
    ["Office document / PDF reader / browser → script host (PowerShell, cmd, wscript, mshta, rundll32, "
     "certutil, …) that goes online", "1.0"],
    ["Any script host / LOLBin making a network connection", "0.5"],
    ["Executable runs from a staging folder (%TEMP%, Downloads, Users\\Public)", "0.6"]],
    example="explorer.exe → WINWORD.EXE → powershell.exe: a document/browser process spawned a script host that "
            "went online")
heuristic("H8", "TLS fingerprint (full mode)", "0.35", [
    ["JA3 or JA3N on the known-bad list (e.g. abuse.ch SSLBL)", "1.0"],
    ["Mature app presents a JA3N it has never used: its TLS client stack changed", "0.5"]],
    "This catches a process that normally uses Windows SChannel suddenly speaking with an embedded Go or "
    "Python TLS client. Known false positive: an app update that changes its TLS library, which is why the "
    "weight is low.")

H2("Scoring: noisy-OR")
story.append(P("The available heuristic scores are combined as:"))
story.append(P("S = 1 − Π (1 − w_i · s_i)          score = round(100 · S)", "formula"))
story.append(P(
    "This is the probability that at least one of several independent signals is “real”, if signal i is real "
    "with probability w<sub>i</sub>·s<sub>i</sub>. It has three properties that make it a good fit:"))
B(["<b>A strong single signal is not diluted.</b> With a plain weighted average across eight heuristics, a "
   "blocklist hit (1.0) next to seven zeros would score about 12. With noisy-OR it scores 95.",
   "<b>Independent weak signals reinforce each other.</b> A new destination (18) plus a volume spike (60) plus "
   "off-hours activity combine to 77.",
   "<b>It never exceeds 100 and never decreases when a signal is added.</b> Both properties are checked "
   "automatically with Hypothesis property-based tests.",
   "Heuristics that are unavailable (n/a) are simply left out of the product."])
T([["Score", "Severity", "Behaviour"],
   ["0–24", "None", "Shown in the table, no colour"],
   ["25–49", "Low", "Highlighted yellow, no alert"],
   ["50–74", "Medium", "Alert opened, toast in the dashboard"],
   ["75–100", "High", "Alert opened, red toast in the dashboard"]],
  [1, 1, 4])
H3("Overrides, applied in this order")
B(["1. <b>Deny rule</b> for the app or one of its destinations → score at least 90.",
   "2. <b>Blocklist hit</b> → score at least 80; if the app is allowed, capped at 60 instead.",
   "3. <b>Allow rule</b> for the whole app → 0, shown as “allowed”. Destination-level allows remove only that "
   "destination's traffic from H1–H4.",
   "4. <b>Mute</b> → the score is computed and shown, but no alert is opened."])

H2("Worked examples")
story.append(P("These rows are unit tests in <font name=Mono>tests/unit/test_scorer.py</font>; the arithmetic "
               "is checked on every run."))
T([["Scenario", "Signals (w · s)", "Computation", "Result"],
   ["Background app uploads 200 MB to a new bare IP at 3 AM while the user sleeps",
    "H4 0.60·1.0, H3 0.35·0.7, H6 0.25·1.0", "1 − 0.40 · 0.755 · 0.75 = 0.77", "<b>77 High</b>"],
   ["C2 beacon every 30 s to a bare IP on port 4444", "H2 0.55·1.0, H1 0.45·1.0, H3 0.35·0.7",
    "1 − 0.45 · 0.55 · 0.755 = 0.81", "<b>81 High</b>"],
   ["Word spawns PowerShell, which downloads from a new domain", "H7 0.60·1.0, H3 0.35·0.5",
    "1 − 0.40 · 0.825 = 0.67", "<b>67 Medium</b>"],
   ["Chrome opens a site never visited before", "H3 0.35·0.5", "0.175", "18 None"],
   ["OneDrive uploads a large folder in the afternoon", "H4 0.60·1.0", "0.60",
    "60 Medium (false positive → “this is normal”)"],
   ["Any app contacts a blocklisted IP", "H5 0.95·1.0", "0.95 (override ≥ 80)", "<b>95 High</b>"]],
  [2.4, 1.8, 1.8, 1.3])

H2("Alert lifecycle", need=95)
story.append(KeepTogether([diagram_alert_lifecycle(),
                           P("Figure 4. Alert states. There is one active alert per app per incident.",
                             "caption")]))
story.append(P(
    "An alert opens when an app's verdict reaches Medium (configurable). While the app stays at that level, "
    "the same alert is updated in place: its peak score, top heuristic and evidence always describe the "
    "strongest moment, refreshed with the latest numbers at an equal score. The alert resolves after the app "
    "has stayed below the threshold for 5 minutes. If the same app flares up again within 15 minutes of "
    "resolving, the old alert is reopened rather than a new one created. An alert's summary is its top two "
    "evidence strings."))

H2("The feedback loop")
T([["User action", "TUI key / CLI", "Effect (applied on the next tick, ≤ 2 s)"],
   ["Allow app", "a / netsentry allow --app X", "Policy rule; the app's score becomes 0 (blocklist still shows, "
                                                "capped at 60)"],
   ["Allow destination for app", "netsentry allow --app X --dest D", "Destination excluded from H1–H4 for that app "
                                                                     "and added to its baseline"],
   ["Deny app / destination", "d / netsentry deny …", "Score forced to at least 90 (High)"],
   ["Mute", "m / netsentry mute … --minutes N", "Scored and shown, but no alerts (1 h by default)"],
   ["This is normal", "n", "Alert closed as false positive; the alerted minutes are folded into the "
                           "baseline. The only way flagged behaviour becomes “normal”."],
   ["Acknowledge", "k", "Alert marked as seen; it stays open until it resolves"]],
  [1.4, 1.8, 3.3])
story.append(P(
    "Every decision is written to <font name=Mono>user_actions</font> with a timestamp, so the alert history "
    "shows who changed what, and the validation can measure how quickly the false-positive rate falls."))

# ---------------------------------------------------------------- 9
H1("Data Model and Storage")
story.append(P(
    "All state lives in one SQLite database at <font name=Mono>%LOCALAPPDATA%\\NetSentry\\netsentry.db</font> "
    "(override with <font name=Mono>--db</font>), in WAL mode with <font name=Mono>synchronous=NORMAL</font>. "
    "The schema is idempotent and created on first start."))
T([["Table", "Key columns", "Purpose"],
   ["meta", "key, value", "system_first_seen (start of learning)"],
   ["apps", "app_id, name, first_seen, last_seen", "Every application ever seen on the network"],
   ["flows", "app_id, pid, proto, laddr:lport, raddr:rport, domain, ip_class, opened_at, closed_at, bytes_out, "
             "bytes_in, ja3n", "One row per connection; indexed by (app_id, opened_at) and raddr"],
   ["app_minutes", "app_id, minute_ts, new_flows, unique_dests, new_dests, bytes_out, bytes_in, score, severity",
    "Per-app per-minute history: feeds charts and sparklines"],
   ["baselines (+ _dests, _ports, _ja3)", "ewma_json, hour_hist, n_buckets; known sets",
    "Learned behaviour per app; survives restarts"],
   ["alerts", "app_id, status, severity, peak_score, top_heuristic, summary, evidence_json",
    "Alert history including all heuristic results at peak"],
   ["policy_rules", "scope (app | dest | app+dest), action (allow | deny | mute), expires_at",
    "User decisions"],
   ["user_actions", "ts, alert_id, action, detail", "Audit trail for false-positive statistics"]],
  [1.4, 3, 2.2])
H2("Write strategy and retention")
B(["The engine writes everything for a tick in <b>one transaction</b>. Typical cost: a few milliseconds.",
   "Flows are inserted when they open, byte counts are updated every 30 s, and the closing time is written when "
   "they close. A crash loses at most 30 s of byte counts.",
   "History views read only <font name=Mono>app_minutes</font>, never the raw flows, so they stay fast.",
   "Readers (CLI commands) use their own connections; WAL means they never block the engine.",
   "Retention: closed flows 7 days (configurable), minute history 30 days; alerts, rules and baselines are "
   "kept."])

# ---------------------------------------------------------------- 10
H1("Technical Implementation")
H2("Technology stack")
T([["Concern", "Choice", "Why"],
   ["Language", "Python 3.13", "One language for capture, analysis and UI"],
   ["Socket table, processes", "psutil 7", "Cross-platform, no admin needed for the socket table"],
   ["Packet capture", "Scapy 2.8 on Npcap", "Mature dissectors for IP, TCP, UDP and DNS; BPF filtering"],
   ["Configuration", "pydantic 2 + PyYAML", "Validated config; errors name the bad field"],
   ["Domain parsing", "tldextract (offline snapshot)", "Correct eTLD+1 without network access"],
   ["Command line", "Typer + Rich", "Typed options, readable tables"],
   ["Dashboard", "Textual 8", "Full-screen terminal UI running on the same asyncio loop"],
   ["Storage", "SQLite (stdlib)", "Zero setup; WAL for concurrent readers"],
   ["Tests", "pytest, pytest-asyncio, Hypothesis", "Unit, integration and property-based tests"],
   ["Lint", "ruff", "Fast lint and import sorting"]],
  [1.5, 1.7, 3.2])

H2("Repository layout")
CODE("""
mycafee/                         github.com/Nainikap/mycafee  (Python package: netsentry)
├─ README.md · pyproject.toml
├─ config/
│  ├─ rules.yaml                 weights, thresholds, profiles (Appendix A)
│  ├─ ports.yaml                 common and suspicious ports
│  ├─ lolbins.yaml               script hosts, suspicious parents, system binaries, staging paths
│  └─ blocklists/ ips.txt · domains.txt · ja3.txt
├─ src/netsentry/
│  ├─ cli.py · demo.py · config.py · models.py · clock.py · bus.py
│  ├─ capture/    socket_poller · process_resolver · sniffer · tls · idle · source
│  ├─ pipeline/   attributor · flow_table · enricher · engine
│  ├─ detection/  features · baseline · policy · scorer · alerts · heuristics/ (8 files)
│  ├─ storage/    schema.sql · db.py
│  └─ ui/tui/     app.py (Textual dashboard)
├─ tests/        unit/ (49 tests) · integration/ (5 tests) · factories.py
├─ tools/simulate/sim.py         harmless attack simulators
└─ docs/         01–07 design documents and this PDF
""")
story.append(P(f"The source is about 3,800 lines of Python: capture 629, pipeline 674, detection 941, storage "
               f"187, UI 237, plus the CLI, models and configuration."))

H2("Core interfaces")
CODE("""
class CaptureSource(Protocol):              # LiveSource · ReplaySource · ListSource
    full_mode: bool
    async def start(self) -> None
    async def sample(self) -> RawTick | None   # None = end of a replay
    async def stop(self) -> None

class Heuristic(Protocol):
    name: str; code: str                    # e.g. "frequency", "H2"
    def evaluate(self, win: AppWindow, base: Baseline | None,
                 ctx: HeuristicContext) -> HeuristicResult   # score 0..1 | None, evidence

def score(app_id, ts, results, policy: AppPolicy, cfg, dest_denied=None) -> Verdict

class Engine:
    async def run(self, max_ticks=None) -> None
    async def tick(self) -> TickResult | None      # one deterministic step (used by tests)
    def user_action(self, action, app_id, dest=None, minutes=None) -> str
""")

H2("Command-line interface")
T([["Command", "Purpose"],
   ["netsentry run [--profile demo] [--ui tui|none] [--no-sniff] [--record F]", "Monitor this machine live"],
   ["netsentry demo [--speed 10] [--ui tui|none]", "Play the synthetic attack scenario through the real engine"],
   ["netsentry record --out F --minutes N", "Record raw capture ticks to JSONL"],
   ["netsentry replay F [--speed N]", "Replay a recording deterministically"],
   ["netsentry capture", "One snapshot of attributed connections (compare with netstat -ano)"],
   ["netsentry status / alerts [--json]", "Per-app summary and alert list from the database"],
   ["netsentry allow | deny | mute --app X [--dest D] [--minutes N]", "Add a policy rule"],
   ["netsentry rules [--delete ID]", "List or delete rules"],
   ["netsentry export --what alerts|flows --format csv|json", "Export data for the report"],
   ["netsentry doctor", "Check admin rights, Npcap, socket access, config and database"]],
  [3.4, 2.6], mono_cols=(0,))

H2("The dashboard")
shot = tui_screenshot()
if shot is not None:
    story.append(KeepTogether([shot, P("Figure 5. The Textual dashboard during <font name=Mono>netsentry "
                                       "demo</font>: the live per-app table (severity, score, PID, connections, "
                                       "top destination, per-minute traffic, firing heuristics) above the "
                                       "alert list, with the key bar at the bottom.", "caption")]))
story.append(P(
    "The status line shows the capture mode, app and flow counts, tick time and the learning countdown. "
    "Selecting an app and pressing <b>Enter</b> opens a detail screen: parent chain, command line, baseline "
    "maturity, every heuristic with score × weight and evidence (n/a ones greyed out), open flows with bytes and "
    "JA3N, and one-hour sparklines of connections and score."))
T([["Key", "Action"], ["Enter", "Details for the selected app"], ["a / d / m", "Allow / deny / mute 1 h"],
   ["n", "“This is normal”: close the alert as a false positive and teach the baseline"], ["k", "Acknowledge"],
   ["f", "Show only flagged apps"], ["q", "Quit (flushes baselines and flows to the database)"]], [1, 5])

H2("Configuration")
story.append(P(
    "All tuning lives in plain text that is reloaded while NetSentry runs. An invalid edit to "
    "<font name=Mono>rules.yaml</font> is logged and the previous configuration kept, so a typo cannot stop "
    "monitoring. Profiles override parts of the file; <font name=Mono>--profile demo</font> shortens the "
    "learning period to 10 minutes. The full default file is in Appendix A."))

H2("Engineering conventions")
B(["Detection code is pure: no I/O and no wall-clock calls. Time and data are passed in, which makes every "
   "heuristic unit-testable.",
   "Every evidence string is readable by a non-expert and contains the actual numbers.",
   "Config errors fail fast at startup with the field name (pydantic).",
   "Logs go to <font name=Mono>%LOCALAPPDATA%\\NetSentry\\netsentry.log</font> with rotation; ticks over 250 ms are "
   "logged as warnings.",
   "Secrets, such as a future AbuseIPDB key, only ever come from environment variables."])

# ---------------------------------------------------------------- 11
H1("Testing and Validation")
H2("Automated test suite")
T([["File", "Tests", "Covers"],
   ["tests/unit/test_heuristics.py", "24", "Every sub-rule of H1–H8 at and around its boundary; allow-rule "
                                           "filtering; learning and n/a behaviour"],
   ["tests/unit/test_scorer.py", "12", "All worked examples from Section 8.5; overrides; Hypothesis properties "
                                       "(score in 0–100, adding a signal never lowers it)"],
   ["tests/unit/test_flows.py", "7", "Flow lifecycle, one-miss tolerance, byte attribution, UDP by port, "
                                     "pending → unknown, inbound detection, loopback"],
   ["tests/unit/test_capture_parsing.py", "6", "ClientHello → SNI/JA3/JA3N, GREASE removal, JA3N stability "
                                               "under shuffling, truncation, DNS CNAME chains, IP helpers"],
   ["tests/integration/test_engine.py", "5", "Synthetic scenario end to end in full and standard mode; quiet "
                                             "learning period; persistence; “this is normal”"],
   ["Total", "<b>54</b>", "All passing (≈ 12 s)"]],
  [2.6, 0.6, 4], mono_cols=(0,))

H2("Synthetic scenario results", need=130)
story.append(P(
    "<font name=Mono>netsentry demo</font> generates 25 minutes of traffic (750 ticks) in the same format as a "
    "live recording. The first 12 minutes are normal Chrome browsing, a Microsoft Teams heartbeat every 60 s "
    "and light OneDrive sync. Four attacks follow. The chart shows the real scores the engine produced."))
story.append(KeepTogether([chart_scores(),
                           P("Figure 6. Per-app score over time in the synthetic scenario (demo profile). The dashed "
                             "lines are the severity thresholds; the grey line is Teams' legitimate heartbeat, which "
                             "stays below Low.", "caption")]))
rows = [["App", "Attack", "Severity", "Peak", "Top", "Opened (min)"]]
desc = {"updater.exe": ("updater.exe", "Beacon every 30 s from %TEMP% to :4444"),
        "onedrive.exe": ("OneDrive.exe", "200 MB upload to a new bare IP"),
        "chrome.exe": ("chrome.exe", "Contact with a blocklisted IP"),
        "powershell.exe": ("powershell.exe", "Word → PowerShell → new host")}
for a in sorted(DATA["alerts"], key=lambda a: a["opened"]):
    name, what = desc.get(a["app"].lower(), (a["app"], ""))
    rows.append([name, what, a["sev"], str(a["peak"]), a["top"], f"{a['opened']:.1f}"])
T(rows, [1.3, 2.6, 0.8, 0.6, 0.5, 0.9])
story.append(P(
    "All four attacks raised alerts, and nothing else did. Teams' perfectly regular 60-second heartbeat scored at "
    "most 17, because it goes to a destination the app already knows (beacon score × 0.3). In <b>standard mode</b> "
    "the same scenario still catches the beacon, the blocklist hit and the Word → PowerShell chain, but not the "
    "upload, because there are no byte counts. Both outcomes are asserted in the integration tests. The p95 "
    f"engine tick on this scenario was {DATA['tick_ms_p95']:.1f} ms."))

H2("Attack simulators")
story.append(P(
    "<font name=Mono>tools/simulate/sim.py</font> provides harmless simulators for live validation. They open "
    "ordinary TCP connections to hosts the tester chooses, and hold each one for a few seconds so the 2 s poll "
    "sees it. Nothing is installed or exfiltrated."))
T([["ID", "Command", "Simulates", "Expected"],
   ["S1", "sim.py beacon --host H --port 4444", "C2 beacon every 30 s ± 1 s", "High (Medium while learning)"],
   ["S2", "sim.py exfil --host H --mb 200", "Bulk upload", "Medium/High (full mode)"],
   ["S3", "sim.py oddport --port 31337", "Backdoor port", "Low (45)"],
   ["S4", "sim.py office", "WINWORD.EXE (renamed cmd) → PowerShell → internet", "Medium"],
   ["S5", "sim.py masquerade", "svchost.exe in %TEMP% (renamed curl)", "Medium (60–67)"],
   ["S6", "sim.py blocklist", "Adds a host to ips.txt, then connects", "High (≥ 80)"],
   ["—", "sim.py sink --ports 4444 9000", "Receiving end for S1/S2", ""]],
  [0.35, 2.3, 2.3, 1.4], mono_cols=(1,))

H2("Live measurements")
T([["Check", "Result (development laptop, standard mode)"],
   ["Capture vs netstat", "Every established TCP connection attributed to the correct process, with parent "
                          "chains (e.g. msedgewebview2.exe ← ms-teams.exe ← explorer.exe)"],
   ["Normal use, 75 s", "13 apps and up to 80 flows tracked; no alerts"],
   ["Tick cost", "5–15 ms steady state; ~0.9 s once at startup (first process scan)"],
   ["S1 beacon (12 s interval, local sink, learning period)", "One Medium (53) alert: “connected to …:4444 "
    "(suspicious port: Metasploit default); 7 connections … every 11.7 s ± 1.4 s (cv 0.12) (damped while "
    "learning)”"],
   ["Dashboard (headless Textual pilot)", "Table and alerts render; Enter opens details; n applies “this is "
                                         "normal”"]],
  [2, 4.5])

H2("Bugs found by live testing")
story.append(P("Running against a real machine found problems that synthetic tests had not. Each fix is now "
               "covered by a test."))
T([["Problem", "Symptom", "Fix"],
   ["PID re-validation cost", "Ticks of 700 ms–1.9 s", "One parent-PID snapshot per batch; evict PIDs when the "
                                                     "process exits instead of re-checking"],
   ["Inbound connections looked outbound", "A local server was flagged for “non-standard port 5xxxx” (the "
                                           "client's ephemeral port)", "Flows accepted on a LISTEN port are "
                                                                       "marked inbound and skipped by H1/H2"],
   ["Beacon timing mixed endpoints", "A real beacon was missed because unrelated connections to the same IP "
                                     "broke the regularity", "Start times keyed by remote ip:port"],
   ["Documentation IPs treated as LAN", "Test IPs (203.0.113.x) got the LAN discount",
    "Explicit list of LAN ranges"],
   ["Two alerts per incident", "The beacon opened one alert for H1, then another for H2",
    "One active alert per app, updated in place"],
   ["Stale evidence", "Upload alert said 14.7 MB while 200 MB was being sent", "Evidence refreshed at equal "
                                                                              "peak score"],
   ["Windows console encoding", "Crash printing → ± ≈ on cp1252 consoles", "UTF-8 reconfigured at startup"],
   ["Enter in the dashboard", "Detail screen did not open (the table consumed the key)",
    "Handle the table's row-selected event"]],
  [1.6, 2.4, 2.6])

H2("Remaining validation work")
B(["Run full mode from an administrator terminal: byte accuracy (V2: ±10 % on a known 100 MB transfer) and "
   "domain coverage (V3: ≥ 90 % of browser flows named).",
   "Run S2–S6 live and record true and false positives.",
   "Normal-day false-positive study: at least 6 hours after the 24 h learning period; alerts per hour, share "
   "marked “this is normal”, top causes, and the false-positive rate in hours 1–3 vs 4–6.",
   "Performance at load: replay a busy hour at 50× and confirm p95 tick under 250 ms."])

# ---------------------------------------------------------------- 12
H1("Limitations")
story.append(P("These are stated plainly because they affect how results should be read."))
T([["Limitation", "Impact", "Mitigation"],
   ["Connections shorter than one poll (2 s)", "Invisible in standard mode", "Full mode sees their packets; "
                                                                             "unattributable ones go to “unknown”"],
   ["QUIC / HTTP3 (UDP 443)", "ClientHello is encrypted: no SNI or JA3", "DNS answers still name the "
                                                                         "destination"],
   ["DNS-over-HTTPS in browsers", "DNS answers not visible", "SNI and reverse DNS fill the gap"],
   ["Scapy throughput", "May drop packets above ~50 Mbit/s; byte counts approximate", "Packet counter shown in "
                                                                                       "the status line"],
   ["Heuristic false positives", "Backups, cloud sync, game launchers, app updates", "Learning period, "
                                                                                     "poisoning guard, feedback loop"],
   ["Learning period", "No “new destination” alerts for the first 24 h", "Blocklist, lineage and port rules work "
                                                                          "from the first second"],
   ["Single machine, Windows-focused", "Idle detection and some lists are Windows-specific", "Core is "
                                                                                             "cross-platform via "
                                                                                             "psutil"],
   ["Metadata only", "Cannot see what is being sent", "By design: no decryption"]],
  [2, 2.3, 2.3])

# ---------------------------------------------------------------- 13
H1("Future Work")
B(["<b>Web dashboard (P8):</b> FastAPI with REST + WebSocket on 127.0.0.1 with a startup token, plus a React "
   "front end with per-app history charts. It would subscribe to the existing EventBus.",
   "<b>Reputation lookups:</b> AbuseIPDB or VirusTotal free tier, cached, within the daily budget; confidence ≥ "
   "75 → 0.9 inside H5.",
   "<b>Learned scorer:</b> an Isolation Forest trained on <font name=Mono>app_minutes</font> behind the same "
   "Scorer interface, with the rule results kept as the explanation layer.",
   "<b>DNS-level monitoring:</b> detecting domain-generation-algorithm (DGA) patterns from query names.",
   "<b>JA4 fingerprints</b> and a JA3S server-side fingerprint.",
   "<b>Windows ETW</b> (Kernel-Network provider) for exact per-process byte counts without packet capture.",
   "<b>Optional enforcement:</b> “block with Windows Firewall” from an alert, with explicit confirmation.",
   "<b>System-tray service</b> and native desktop notifications for High alerts."])

# ---------------------------------------------------------------- 14
H1("Running the Project")
CODE("""
git clone https://github.com/Nainikap/mycafee && cd mycafee
python -m venv .venv
.venv\\Scripts\\pip install -e ".[dev]"

.venv\\Scripts\\netsentry doctor                 # admin? Npcap? config valid?
.venv\\Scripts\\netsentry demo                   # synthetic attack scenario, no network needed
.venv\\Scripts\\netsentry run --profile demo     # live, 10-minute learning period
.venv\\Scripts\\python -m pytest                 # 54 tests
""")
story.append(P(
    "For <b>full mode</b>, start the terminal with “Run as administrator” (Npcap must be installed). Without it, "
    "NetSentry runs in standard mode and says so in the status line. A presentation can use "
    "<font name=Mono>netsentry demo</font> as a fallback if the venue network is unreliable."))
H2("Suggested demonstration (≈ 10 minutes)")
B(["1. <font name=Mono>netsentry doctor</font>: show the capture mode and checks.",
   "2. <font name=Mono>netsentry run --profile demo</font>: the live table fills; open Chrome's detail screen "
   "(parent chain, destinations).",
   "3. Run the beacon simulator: a Medium/High alert appears; read its evidence.",
   "4. Run the exfiltration simulator (full mode), press <b>n</b>, and show the next run scoring lower.",
   "5. Run the blocklist simulator: an immediate High.",
   "6. Change a weight in <font name=Mono>rules.yaml</font> and watch scores change within 10 s."])

# ---------------------------------------------------------------- appendices
HA("Appendix A: Default rules.yaml")
CODE((ROOT / "config" / "rules.yaml").read_text(encoding="utf-8"))

HA("Appendix B: Glossary")
T([["Term", "Meaning"],
   ["Beacon", "Regular, machine-timed connections from malware to its controller (C2) to ask for commands"],
   ["C2", "Command-and-control server used by an attacker to steer compromised machines"],
   ["Coefficient of variation (cv)", "Standard deviation divided by mean; near 0 means very regular timing"],
   ["eTLD+1", "Registrable domain: the public suffix plus one label (example.co.uk)"],
   ["EWMA", "Exponentially weighted moving average: a running mean that favours recent values"],
   ["Exfiltration", "Unauthorised transfer of data off a machine"],
   ["5-tuple", "Protocol, local IP, local port, remote IP, remote port: identifies one connection"],
   ["GREASE", "Random placeholder values browsers put in TLS handshakes to keep servers tolerant"],
   ["JA3 / JA3N", "MD5 fingerprint of a TLS ClientHello; JA3N sorts extensions so it stays stable"],
   ["LOLBin", "“Living off the land” binary: a built-in Windows tool (PowerShell, certutil…) abused by "
              "attackers"],
   ["Noisy-OR", "S = 1 − Π(1 − p<sub>i</sub>): the probability that at least one independent cause is active"],
   ["Npcap", "Windows packet capture driver used by Scapy and Wireshark"],
   ["SNI", "Server Name Indication: the host name a TLS client asks for, sent in clear text"],
   ["TIME_WAIT", "TCP state after a connection closes; on Windows it is reported under PID 0"],
   ["z-score", "How many standard deviations a value is from the mean"]],
  [1.6, 5])

HA("Appendix C: References")
B(["GlassWire: Network Security Monitor &amp; Firewall Tool, glasswire.com/features",
   "Objective Development: Little Snitch, obdev.at/littlesnitch",
   "The Zeek Project: About Zeek (Book of Zeek), docs.zeek.org/en/lts/about.html",
   "EC-Council: What is Wireshark?, eccouncil.org",
   "Open Information Security Foundation: Suricata, github.com/OISF/suricata",
   "Salesforce: JA3, a method for profiling SSL/TLS clients, github.com/salesforce/ja3",
   "abuse.ch: SSL Blacklist (JA3 fingerprints), sslbl.abuse.ch",
   "psutil documentation, psutil.readthedocs.io; Scapy documentation, scapy.readthedocs.io",
   "Microsoft: GetExtendedTcpTable and GetLastInputInfo (Win32 API documentation), learn.microsoft.com",
   "RFC 8446: TLS 1.3; RFC 8701: GREASE for TLS; RFC 1918: Private address space; RFC 5737: IPv4 documentation "
   "ranges",
   "Project source and design documents: github.com/Nainikap/mycafee (docs/01–07)"])

# ---------------------------------------------------------------- build
doc = Doc(str(OUT))
doc.multiBuild(story)
print("wrote", OUT)
