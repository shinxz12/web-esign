"""Chữ ký tay: người nhận vẽ (hoặc tải ảnh) chữ ký, server đóng ảnh vào PDF.

Không có token nên không có chữ ký số của người này — đây là chữ ký điện tử
đơn giản. Bằng chứng nằm ở nhật ký kiểm toán chuỗi băm: ai, lúc nào, IP nào,
SHA-256 của ảnh và của PDF sau khi đóng.

Ảnh được đặt vào **một trường chữ ký trống, chỉ đọc** trong một incremental
update. Thêm trường biểu mẫu là thay đổi chuẩn PDF cho phép sau chữ ký số,
nên chữ ký số đã có vẫn hợp lệ. (Chú thích kiểu Stamp thì không: pyHanko và
nhiều trình xác thực coi đó là sửa đổi không giải thích được.)
"""

from __future__ import annotations

import io

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name, pdf_string
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.sign import fields

from .errors import ApiError
from .signing import free_field_name, incremental_writer

MAX_IMAGE_BYTES = 1024 * 1024
MAX_PIXELS = 2000 * 2000
READ_ONLY = 1  # /Ff bit 1: trình đọc PDF không mời ký đè vào ô này


def load_signature_image(data: bytes):
    """Ảnh PNG/JPEG/WEBP thật, cắt bỏ phần nền trong suốt/trắng thừa quanh nét ký."""
    from PIL import Image, ImageOps

    if len(data) > MAX_IMAGE_BYTES:
        raise ApiError(400, "image_too_large", "Ảnh chữ ký tối đa 1 MB")
    try:
        probe = Image.open(io.BytesIO(data))
        probe.verify()
        image = Image.open(io.BytesIO(data))
        if image.format not in ("PNG", "JPEG", "WEBP"):
            raise ValueError("chỉ nhận PNG, JPEG hoặc WEBP")
        if image.width * image.height > MAX_PIXELS:
            raise ValueError("ảnh quá lớn")
        image = image.convert("RGBA")
    except Exception as exc:
        raise ApiError(400, "invalid_image", f"Không đọc được ảnh chữ ký: {exc}") from exc

    # Vùng có nét: không trong suốt và không gần trắng.
    opaque = image.getchannel("A").point(lambda v: 255 if v > 16 else 0)
    dark = ImageOps.invert(image.convert("L")).point(lambda v: 255 if v > 24 else 0)
    bbox = Image.composite(dark, Image.new("L", image.size, 0), opaque).getbbox()
    if bbox is None:
        raise ApiError(400, "empty_signature", "Chữ ký đang trống")
    return image.crop(bbox)


def stamp(
    pdf_bytes: bytes,
    page: int,
    box: tuple[float, float, float, float],
    image,
    signer_name: str,
) -> tuple[bytes, str]:
    """-> (PDF có thêm một revision chứa ảnh chữ ký trong ``box``, tên trường)."""
    field_name = free_field_name(pdf_bytes, prefix="KyTay")
    writer = incremental_writer(pdf_bytes)
    fields.append_signature_field(writer, fields.SigFieldSpec(field_name, on_page=page, box=box))

    # Giữ tỉ lệ ảnh, căn giữa trong ô ký.
    box_w, box_h = box[2] - box[0], box[3] - box[1]
    scale = min(box_w / image.width, box_h / image.height)
    width, height = image.width * scale, image.height * scale
    picture = PdfImage(image, writer=writer, box=BoxConstraints(width=width, height=height))
    picture_ref = writer.add_object(picture.as_form_xobject())
    content = b"q 1 0 0 1 %g %g cm /Sig Do Q" % ((box_w - width) / 2, (box_h - height) / 2)
    appearance = generic.StreamObject(
        {
            pdf_name("/Type"): pdf_name("/XObject"),
            pdf_name("/Subtype"): pdf_name("/Form"),
            pdf_name("/BBox"): generic.ArrayObject(generic.FloatObject(v) for v in (0, 0, box_w, box_h)),
            pdf_name("/Resources"): generic.DictionaryObject(
                {pdf_name("/XObject"): generic.DictionaryObject({pdf_name("/Sig"): picture_ref})}
            ),
        },
        stream_data=content,
    )
    appearance_ref = writer.add_object(appearance)

    for ref in writer.root["/AcroForm"]["/Fields"]:
        field = ref.get_object()
        if field.get("/T") == field_name:
            field[pdf_name("/AP")] = generic.DictionaryObject({pdf_name("/N"): appearance_ref})
            field[pdf_name("/Ff")] = generic.NumberObject(READ_ONLY)
            field[pdf_name("/TU")] = pdf_string(f"Chữ ký tay của {signer_name}")
            writer.mark_update(ref)
            break

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue(), field_name
