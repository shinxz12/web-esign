"""Sinh PDF hợp đồng mẫu (tiếng Việt có dấu) để thử luồng ký."""

import pathlib
import sys

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


def pick_font() -> str:
    for path in FONT_CANDIDATES:
        if pathlib.Path(path).is_file():
            pdfmetrics.registerFont(TTFont("Body", path))
            return "Body"
    return "Helvetica"


def main(out_path: str) -> None:
    font = pick_font()
    c = canvas.Canvas(out_path, pagesize=A4)
    width, height = A4

    for page_no, (title, lines) in enumerate(PAGES, start=1):
        c.setFont(font, 16)
        c.drawCentredString(width / 2, height - 35 * mm, title)
        c.setFont(font, 11)
        y = height - 50 * mm
        for line in lines:
            c.drawString(25 * mm, y, line)
            y -= 7 * mm
        c.setFont(font, 9)
        c.drawCentredString(width / 2, 15 * mm, f"Trang {page_no}/{len(PAGES)}")
        c.showPage()

    c.save()
    print(f"Đã tạo {out_path}")


PAGES = [
    (
        "HỢP ĐỒNG DỊCH VỤ SỐ 2026/HĐDV-01",
        [
            "Hôm nay, ngày ... tháng ... năm 2026, tại Hà Nội, chúng tôi gồm:",
            "",
            "BÊN A: CÔNG TY TNHH DEMO",
            "    Mã số thuế: 0101234567",
            "    Đại diện: Ông NGUYỄN VĂN A — Chức vụ: Giám đốc",
            "",
            "BÊN B: CÔNG TY CỔ PHẦN THỬ NGHIỆM",
            "    Mã số thuế: 0107654321",
            "    Đại diện: Bà TRẦN THỊ BÍCH — Chức vụ: Tổng giám đốc",
            "",
            "Hai bên thống nhất ký kết hợp đồng với các điều khoản sau:",
            "",
            "Điều 1. Nội dung công việc",
            "    Bên B cung cấp cho Bên A dịch vụ ký số tài liệu điện tử,",
            "    bao gồm hạ tầng phần mềm và hỗ trợ kỹ thuật trong 12 tháng.",
            "",
            "Điều 2. Giá trị hợp đồng",
            "    Tổng giá trị: 120.000.000 VNĐ (đã bao gồm thuế GTGT).",
        ],
    ),
    (
        "ĐIỀU KHOẢN CHUNG VÀ CHỮ KÝ",
        [
            "Điều 3. Phương thức thanh toán",
            "    Chuyển khoản, thanh toán thành 02 đợt.",
            "",
            "Điều 4. Hiệu lực hợp đồng",
            "    Hợp đồng có hiệu lực kể từ ngày hai bên ký số.",
            "    Hợp đồng được lập dưới dạng thông điệp dữ liệu, có giá trị",
            "    pháp lý như bản giấy theo Luật Giao dịch điện tử 2023.",
            "",
            "",
            "        ĐẠI DIỆN BÊN A                    ĐẠI DIỆN BÊN B",
            "",
            "",
            "",
            "",
            "",
            "",
            "        (Ký số)                           (Ký số)",
        ],
    ),
]


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/documents/hop-dong-mau.pdf")
