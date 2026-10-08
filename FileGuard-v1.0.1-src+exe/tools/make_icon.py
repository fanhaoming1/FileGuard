# -*- coding: utf-8 -*-
"""生成应用图标 assets/fileguard.ico（深蓝盾牌 + FG），只需运行一次。"""
import os

from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "assets", "fileguard.ico")


def shield(size, pad=2):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size - pad * 2
    x0, y0 = pad, pad
    x1, y1 = pad + s, pad + s
    r = int(s * 0.16)
    # 盾牌轮廓：上宽下尖
    top_h = int(s * 0.62)
    pts = [
        (x0 + r, y0),
        (x1 - r, y0),
        (x1, y0 + r),
        (x1, y0 + top_h * 0.55),
        ((x0 + x1) / 2, y1),
        (x0, y0 + top_h * 0.55),
        (x0, y0 + r),
    ]
    d.polygon(pts, fill=(37, 99, 235, 255))
    # 内高光
    inset = max(2, int(s * 0.09))
    pts2 = [(x0 + inset + (px - x0) * (s - inset * 2) / s,
             y0 + inset + (py - y0) * (s - inset * 2) / s) for px, py in pts]
    d.polygon(pts2, fill=(56, 130, 246, 255))
    # 文字 FG
    txt = "FG"
    fs = int(s * 0.42)
    try:
        font = ImageFont.truetype("segoeuib.ttf", fs)
    except OSError:
        try:
            font = ImageFont.truetype("arialbd.ttf", fs)
        except OSError:
            font = ImageFont.load_default()
    box = d.textbbox((0, 0), txt, font=font)
    tw, th = box[2] - box[0], box[3] - box[1]
    d.text(((size - tw) / 2 - box[0], (size - th) / 2 - box[1] + s * 0.04),
           txt, font=font, fill=(255, 255, 255, 255))
    return img


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    # Pillow 的 ICO 保存会对同一张基准图按 sizes 重新采样，多尺寸必须用 256 基准
    shield(256).save(OUT, format="ICO", sizes=[(s, s) for s in sizes])
    from PIL import Image
    im = Image.open(OUT)
    print("已生成:", OUT, os.path.getsize(OUT), "bytes",
          "sizes=", sorted(im.info.get("sizes", [])))


if __name__ == "__main__":
    main()
