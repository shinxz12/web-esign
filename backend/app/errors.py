"""Lỗi nghiệp vụ trả về client: ``{"detail": <thông điệp>, "code": <mã máy đọc>}``.

``detail`` giữ đúng tên trường FastAPI vẫn dùng, nên giao diện cũ đọc được;
``code`` ổn định để hệ thống tích hợp rẽ nhánh mà không phải so chuỗi tiếng Việt.
"""

from __future__ import annotations


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers


def not_found(what: str = "Không tìm thấy") -> ApiError:
    return ApiError(404, "not_found", what)


def conflict(code: str, message: str) -> ApiError:
    return ApiError(409, code, message)


def bad_request(code: str, message: str) -> ApiError:
    return ApiError(400, code, message)
