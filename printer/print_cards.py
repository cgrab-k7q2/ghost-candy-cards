#!/usr/bin/env python3
"""Print Ghost Candy Cards as an SVG sheet (one QR per card) plus the list of card points for `new`.

usage: candy-cli new 8 > cards.txt && python3 print_cards.py cards.txt sheet.svg points.json
Each line of cards.txt is "<secret_hex> <point_hex>". The QR holds "ghostcandy:<secret_hex>".
Keep cards.txt offline: whoever holds a card's secret can redeem it.
"""
import json, sys
import qrcode, qrcode.image.svg

src, out_svg, out_points = sys.argv[1:4]
cards = [l.split() for l in open(src) if l.strip()]
W, H, cols = 260, 360, 4
rows = (len(cards) + cols - 1) // cols
parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{cols*W}" height="{rows*H}" font-family="Georgia,serif">',
         f'<rect width="100%" height="100%" fill="#120d1f"/>']
for i, (secret, point) in enumerate(cards):
    x, y = (i % cols) * W, (i // cols) * H
    qr = qrcode.QRCode(border=1, box_size=1); qr.add_data("ghostcandy:" + secret); qr.make()
    m = qr.get_matrix(); n = len(m); s = 200 / n
    cells = "".join(f'<rect x="{x+30+c*s:.2f}" y="{y+95+r*s:.2f}" width="{s+0.05:.2f}" height="{s+0.05:.2f}"/>'
                    for r, row in enumerate(m) for c, v in enumerate(row) if v)
    parts.append(f'<g><rect x="{x+10}" y="{y+10}" width="{W-20}" height="{H-20}" rx="18" fill="#ff7a18" stroke="#2b1b47" stroke-width="4"/>'
                 f'<text x="{x+W/2}" y="{y+48}" text-anchor="middle" font-size="21" font-weight="bold" fill="#2b1b47">Ghost Candy Card</text>'
                 f'<path d="M{x+28} {y+342} q0 -26 16 -26 q16 0 16 26 l-5 -5 -5 5 -6 -5 -5 5 -6 -5 z" fill="#fff" stroke="#2b1b47" stroke-width="2"/><circle cx="{x+38}" cy="{y+328}" r="2.5" fill="#2b1b47"/><circle cx="{x+50}" cy="{y+328}" r="2.5" fill="#2b1b47"/>'
                 f'<text x="{x+W/2}" y="{y+76}" text-anchor="middle" font-size="13" fill="#2b1b47">scan to trick-or-treat on Tari</text>'
                 f'<rect x="{x+25}" y="{y+90}" width="210" height="210" fill="#fff"/><g fill="#000">{cells}</g>'
                 f'<text x="{x+W/2}" y="{y+328}" text-anchor="middle" font-size="11" fill="#2b1b47">card {i+1} · {point[:10]}…</text></g>')
parts.append("</svg>")
open(out_svg, "w").write("".join(parts))
json.dump([p for _, p in cards], open(out_points, "w"), indent=1)
print(f"{len(cards)} cards -> {out_svg}, points -> {out_points}")
