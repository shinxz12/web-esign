"""Nguồn khoá chứng thư số từ Windows Certificate Store (CNG / CryptoAPI).

Vì sao dùng Windows Certificate Store thay vì PKCS#11 trên Windows:
- Tại Việt Nam, hầu hết các nhà cung cấp dịch vụ chứng thực chữ ký số công cộng
  (Viettel-CA, VNPT-CA, FPT-CA, BKAV, Nacencomm/CA2, EasyCA, FastCA, v.v.)
  khi cài đặt bộ phần mềm quản trị USB token (PKI Token Client) đều tự động
  đăng ký CSP (Cryptographic Service Provider) hoặc KSP (Key Storage Provider)
  tương ứng vào hệ thống Windows.
- Khi người dùng cắm USB token vào cổng USB, Windows Certificate Store (kho "MY")
  sẽ tự động phát hiện thiết bị và nạp chứng thư số của người dùng kèm liên kết
  tới khoá riêng trên phần cứng.
- Nhờ cơ chế này, agent có thể đọc chứng thư và thực hiện ký số trực tiếp qua
  Windows CryptoAPI / CNG mà không cần phải cấu hình hoặc dò tìm đường dẫn tệp
  thư viện PKCS#11 (.dll) cho từng loại token của từng CA (như Feitian ePass2003,
  SafeNet eToken, v.v.), mang lại trải nghiệm cắm-là-chạy (plug-and-play).

Giới hạn của đường CSP cũ (CryptoAPI 1.0):
- Một số USB token hoặc driver đời cũ chưa nâng cấp lên CNG KSP hiện đại sẽ hoạt
  động ở chế độ CSP cũ (trả về handle HCRYPTPROV thay vì NCRYPT_KEY_HANDLE).
- Đường CSP cũ chỉ hỗ trợ thuật toán ký RSA PKCS#1 v1.5 với SHA-256 (RSA_PKCS1_SHA256)
  thông qua CALG_SHA_256 và CryptSignHashW. Nó KHÔNG hỗ trợ thuật toán RSA-PSS
  (RSA_PSS_SHA256) cũng như ECDSA (ECDSA_SHA256). Nếu gặp các thuật toán này,
  nguồn khoá sẽ báo lỗi KeySourceError để thông báo token không hỗ trợ.
- Chữ ký RSA do CryptoAPI trả về theo thứ tự byte little-endian, do đó bắt buộc
  phải đảo ngược mảng byte ([::-1]) để đưa về thứ tự big-endian chuẩn cho cấu trúc
  CMS/PKCS#7.
"""

from __future__ import annotations

import ctypes
import hashlib
import sys
from contextlib import contextmanager

from keysource import (
    CertEntry,
    KeySource,
    KeySourceError,
    SigAlgo,
    cert_id_for,
    ecdsa_raw_to_der,
    pss_salt_length,
)

__all__ = [
    "WindowsCertStoreKeySource",
    "is_available",
]


def is_available() -> bool:
    """Kiểm tra nguồn khoá Windows Certificate Store có khả dụng hay không.

    Chỉ trả về True khi chạy trên nền tảng Windows (win32).
    """
    return sys.platform == "win32"


# --------------------------------------------------------------------------
# Định nghĩa kiểu dữ liệu và hằng số Win32 / CryptoAPI / CNG
# --------------------------------------------------------------------------

# Kiểu dữ liệu tương thích ABI Win32 (cả x86 và x64)
_DWORD = ctypes.c_uint32
_ULONG = ctypes.c_uint32
_LONG = ctypes.c_int32
_BOOL = ctypes.c_int32
_HANDLE = ctypes.c_void_p
_LPCWSTR = ctypes.c_wchar_p
_LPSTR = ctypes.c_char_p

# Cờ mở store và tìm kiếm
CERT_STORE_PROV_SYSTEM = 10

# Cờ CryptAcquireCertificatePrivateKey
CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001
CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00010000
CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000

# Kiểu khoá (Key Spec)
CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
AT_KEYEXCHANGE = 1
AT_SIGNATURE = 2

# Thuộc tính và cờ CNG (NCrypt)
NCRYPT_IMPL_TYPE_PROPERTY = "ImplType"
NCRYPT_IMPL_HARDWARE_FLAG = 0x00000001
NCRYPT_IMPL_SOFTWARE_FLAG = 0x00000002
NCRYPT_IMPL_REMOVABLE_FLAG = 0x00000008

# Cờ padding cho NCryptSignHash
BCRYPT_PAD_PKCS1 = 0x00000002
BCRYPT_PAD_PSS = 0x00000008

# Thuộc tính và cờ CSP cũ (CryptoAPI)
PP_IMPTYPE = 3
CRYPT_IMPL_HARDWARE = 0x00000001
CRYPT_IMPL_REMOVABLE = 0x00000008

# Thuật toán và tham số băm CryptoAPI
CALG_SHA_256 = 0x0000800C
HP_HASHVAL = 0x0002


# --------------------------------------------------------------------------
# Cấu trúc dữ liệu Win32 CryptoAPI / CNG
# --------------------------------------------------------------------------


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", _DWORD),
        ("pbCertEncoded", ctypes.c_void_p),
        ("cbCertEncoded", _DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", _HANDLE),
    ]


class CERT_TRUST_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwErrorStatus", _DWORD),
        ("dwInfoStatus", _DWORD),
    ]


class CERT_CHAIN_ELEMENT(ctypes.Structure):
    _fields_ = [
        ("cbSize", _DWORD),
        ("pCertContext", ctypes.POINTER(CERT_CONTEXT)),
        ("TrustStatus", CERT_TRUST_STATUS),
        ("pRevocationInfo", ctypes.c_void_p),
        ("pIssuanceUsage", ctypes.c_void_p),
        ("pApplicationUsage", ctypes.c_void_p),
        ("pwszExtendedErrorInfo", _LPCWSTR),
    ]


class CERT_SIMPLE_CHAIN(ctypes.Structure):
    _fields_ = [
        ("cbSize", _DWORD),
        ("TrustStatus", CERT_TRUST_STATUS),
        ("cElement", _DWORD),
        ("rgpElement", ctypes.POINTER(ctypes.POINTER(CERT_CHAIN_ELEMENT))),
        ("pTrustListInfo", ctypes.c_void_p),
        ("fHasRevocationFreshnessTime", _BOOL),
        ("dwRevocationFreshnessTime", _DWORD),
    ]


class CERT_CHAIN_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("cbSize", _DWORD),
        ("TrustStatus", CERT_TRUST_STATUS),
        ("cChain", _DWORD),
        ("rgpChain", ctypes.POINTER(ctypes.POINTER(CERT_SIMPLE_CHAIN))),
        ("cLowerQualityChainContext", _DWORD),
        ("rgpLowerQualityChainContext", ctypes.c_void_p),
        ("fHasRevocationFreshnessTime", _BOOL),
        ("dwRevocationFreshnessTime", _DWORD),
    ]


class CERT_ENHKEY_USAGE(ctypes.Structure):
    _fields_ = [
        ("cUsageIdentifier", _DWORD),
        ("rgpszUsageIdentifier", ctypes.POINTER(_LPSTR)),
    ]


class CERT_USAGE_MATCH(ctypes.Structure):
    _fields_ = [
        ("dwType", _DWORD),
        ("Usage", CERT_ENHKEY_USAGE),
    ]


class CERT_CHAIN_PARA(ctypes.Structure):
    _fields_ = [
        ("cbSize", _DWORD),
        ("RequestedUsage", CERT_USAGE_MATCH),
    ]


class BCRYPT_PKCS1_PADDING_INFO(ctypes.Structure):
    _fields_ = [
        ("pszAlgId", _LPCWSTR),
    ]


class BCRYPT_PSS_PADDING_INFO(ctypes.Structure):
    _fields_ = [
        ("pszAlgId", _LPCWSTR),
        ("cbSalt", _ULONG),
    ]


# --------------------------------------------------------------------------
# Nạp thư viện Win32 và cấu hình argtypes/restype (chỉ trên Windows)
# --------------------------------------------------------------------------

_crypt32 = None
_ncrypt = None
_advapi32 = None
_kernel32 = None

if sys.platform == "win32":
    _crypt32 = ctypes.windll.crypt32
    _ncrypt = ctypes.windll.ncrypt
    _advapi32 = ctypes.windll.advapi32
    _kernel32 = ctypes.windll.kernel32

    # crypt32.dll
    _crypt32.CertOpenSystemStoreW.argtypes = [_HANDLE, _LPCWSTR]
    _crypt32.CertOpenSystemStoreW.restype = _HANDLE

    _crypt32.CertCloseStore.argtypes = [_HANDLE, _DWORD]
    _crypt32.CertCloseStore.restype = _BOOL

    _crypt32.CertEnumCertificatesInStore.argtypes = [_HANDLE, ctypes.c_void_p]
    _crypt32.CertEnumCertificatesInStore.restype = ctypes.POINTER(CERT_CONTEXT)

    _crypt32.CertDuplicateCertificateContext.argtypes = [ctypes.POINTER(CERT_CONTEXT)]
    _crypt32.CertDuplicateCertificateContext.restype = ctypes.POINTER(CERT_CONTEXT)

    _crypt32.CertFreeCertificateContext.argtypes = [ctypes.POINTER(CERT_CONTEXT)]
    _crypt32.CertFreeCertificateContext.restype = _BOOL

    _crypt32.CryptAcquireCertificatePrivateKey.argtypes = [
        ctypes.POINTER(CERT_CONTEXT),
        _DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(_DWORD),
        ctypes.POINTER(_BOOL),
    ]
    _crypt32.CryptAcquireCertificatePrivateKey.restype = _BOOL

    _crypt32.CertGetCertificateChain.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(CERT_CONTEXT),
        ctypes.c_void_p,
        _HANDLE,
        ctypes.POINTER(CERT_CHAIN_PARA),
        _DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(CERT_CHAIN_CONTEXT)),
    ]
    _crypt32.CertGetCertificateChain.restype = _BOOL

    _crypt32.CertFreeCertificateChain.argtypes = [ctypes.POINTER(CERT_CHAIN_CONTEXT)]
    _crypt32.CertFreeCertificateChain.restype = None

    # ncrypt.dll
    _ncrypt.NCryptFreeObject.argtypes = [ctypes.c_size_t]
    _ncrypt.NCryptFreeObject.restype = _LONG

    _ncrypt.NCryptGetProperty.argtypes = [
        ctypes.c_size_t,
        _LPCWSTR,
        ctypes.c_void_p,
        _DWORD,
        ctypes.POINTER(_DWORD),
        _DWORD,
    ]
    _ncrypt.NCryptGetProperty.restype = _LONG

    _ncrypt.NCryptSignHash.argtypes = [
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        _DWORD,
        ctypes.c_void_p,
        _DWORD,
        ctypes.POINTER(_DWORD),
        _DWORD,
    ]
    _ncrypt.NCryptSignHash.restype = _LONG

    # advapi32.dll
    _advapi32.CryptReleaseContext.argtypes = [ctypes.c_size_t, _DWORD]
    _advapi32.CryptReleaseContext.restype = _BOOL

    _advapi32.CryptGetProvParam.argtypes = [
        ctypes.c_size_t,
        _DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(_DWORD),
        _DWORD,
    ]
    _advapi32.CryptGetProvParam.restype = _BOOL

    _advapi32.CryptCreateHash.argtypes = [
        ctypes.c_size_t,
        _DWORD,
        ctypes.c_size_t,
        _DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _advapi32.CryptCreateHash.restype = _BOOL

    _advapi32.CryptSetHashParam.argtypes = [
        ctypes.c_size_t,
        _DWORD,
        ctypes.c_void_p,
        _DWORD,
    ]
    _advapi32.CryptSetHashParam.restype = _BOOL

    _advapi32.CryptSignHashW.argtypes = [
        ctypes.c_size_t,
        _DWORD,
        _LPCWSTR,
        _DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(_DWORD),
    ]
    _advapi32.CryptSignHashW.restype = _BOOL

    _advapi32.CryptDestroyHash.argtypes = [ctypes.c_size_t]
    _advapi32.CryptDestroyHash.restype = _BOOL

    # kernel32.dll
    _kernel32.GetLastError.argtypes = []
    _kernel32.GetLastError.restype = _DWORD


def _get_last_error() -> int:
    """Lấy mã lỗi Win32 gần nhất."""
    if hasattr(ctypes, "GetLastError"):
        return ctypes.GetLastError()
    if _kernel32 is not None and hasattr(_kernel32, "GetLastError"):
        return _kernel32.GetLastError()
    return 0


def _format_win_error(code: int) -> str:
    """Định dạng mã lỗi Win32/NTSTATUS kèm thông điệp hệ thống nếu có."""
    code_u32 = code & 0xFFFFFFFF
    hex_str = f"0x{code_u32:08X}"
    msg = ""
    if hasattr(ctypes, "FormatError"):
        try:
            msg = ctypes.FormatError(code).strip()
        except Exception:
            try:
                msg = ctypes.FormatError(code_u32).strip()
            except Exception:
                pass
    if msg:
        return f"{msg} ({hex_str})"
    return hex_str


# --------------------------------------------------------------------------
# Lớp WindowsCertStoreKeySource
# --------------------------------------------------------------------------


class WindowsCertStoreKeySource:
    """Nguồn khoá đọc từ Windows Certificate Store qua CNG và CryptoAPI.

    Tuân thủ Protocol KeySource trong agent/keysource.py.
    """

    label: str = "Windows Certificate Store (MY)"

    def __init__(self, store_name: str = "MY", hardware_only: bool = True) -> None:
        """Khởi tạo nguồn khoá từ Windows Certificate Store.

        :param store_name: Tên store hệ thống (mặc định "MY" - Personal store).
        :param hardware_only: Nếu True, chỉ giữ chứng thư mà khoá riêng nằm
            trên thiết bị phần cứng (USB token, smartcard). Bỏ qua khoá phần mềm.
        :raises KeySourceError: Khi không chạy trên Windows hoặc không mở được store.
        """
        if not is_available():
            raise KeySourceError(
                "Windows Certificate Store (CNG/CryptoAPI) chỉ khả dụng trên hệ điều hành Windows."
            )

        self.store_name = store_name
        self.hardware_only = hardware_only
        self.label = f"Windows Certificate Store ({store_name})"

        # Xác thực mở store thành công ngay tại bước khởi tạo
        with self._open_store():
            pass

    @contextmanager
    def _open_store(self):
        """Mở store chứng thư hệ thống bằng CertOpenSystemStoreW với đảm bảo giải phóng."""
        if not is_available() or _crypt32 is None:
            raise KeySourceError(
                "Windows Certificate Store chỉ hoạt động trên hệ điều hành Windows."
            )

        h_store = _crypt32.CertOpenSystemStoreW(None, self.store_name)
        if not h_store:
            err = _get_last_error()
            raise KeySourceError(
                f"Không thể mở Windows Certificate Store '{self.store_name}': {_format_win_error(err)}"
            )

        try:
            yield h_store
        finally:
            _crypt32.CertCloseStore(h_store, 0)

    def _is_hardware_key(self, h_key_or_prov: int, dw_key_spec: int) -> bool:
        """Kiểm tra khoá riêng có nằm trên thiết bị phần cứng (token/smartcard) hay không."""
        if (dw_key_spec & 0xFFFFFFFF) == CERT_NCRYPT_KEY_SPEC:
            # Đường CNG (NCRYPT_KEY_HANDLE)
            impl_type = _DWORD(0)
            cb_result = _DWORD(0)
            status = _ncrypt.NCryptGetProperty(
                h_key_or_prov,
                NCRYPT_IMPL_TYPE_PROPERTY,
                ctypes.byref(impl_type),
                ctypes.sizeof(impl_type),
                ctypes.byref(cb_result),
                0,
            )
            if status != 0:
                # Nếu không lấy được thuộc tính thì coi như không phải phần cứng
                return False
            return bool(
                impl_type.value
                & (NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_REMOVABLE_FLAG)
            )
        else:
            # Đường CSP cũ (HCRYPTPROV)
            impl_type = _DWORD(0)
            cb_data = _DWORD(ctypes.sizeof(impl_type))
            ok = _advapi32.CryptGetProvParam(
                h_key_or_prov,
                PP_IMPTYPE,
                ctypes.byref(impl_type),
                ctypes.byref(cb_data),
                0,
            )
            if not ok:
                return False
            return bool(
                impl_type.value & (CRYPT_IMPL_HARDWARE | CRYPT_IMPL_REMOVABLE)
            )

    @staticmethod
    def _free_key_handle(
        h_key_or_prov: int, dw_key_spec: int, caller_free: bool
    ) -> None:
        """Giải phóng handle khoá riêng đã acquire nếu cờ caller_free là True."""
        if not caller_free or not h_key_or_prov:
            return
        if (dw_key_spec & 0xFFFFFFFF) == CERT_NCRYPT_KEY_SPEC:
            _ncrypt.NCryptFreeObject(h_key_or_prov)
        else:
            _advapi32.CryptReleaseContext(h_key_or_prov, 0)

    def _build_chain(
        self,
        h_store: ctypes.c_void_p,
        p_cert: ctypes.POINTER(CERT_CONTEXT),
        cert_der: bytes,
    ) -> list[bytes]:
        """Dựng chuỗi chứng thư (intermediate CAs + root) bằng CertGetCertificateChain."""
        chain_der: list[bytes] = []
        p_chain_ctx = ctypes.POINTER(CERT_CHAIN_CONTEXT)()
        chain_para = CERT_CHAIN_PARA()
        chain_para.cbSize = ctypes.sizeof(CERT_CHAIN_PARA)

        try:
            ok = _crypt32.CertGetCertificateChain(
                None,  # default chain engine
                p_cert,
                None,  # current system time
                h_store,  # additional store
                ctypes.byref(chain_para),
                0,
                None,
                ctypes.byref(p_chain_ctx),
            )
            if ok and p_chain_ctx:
                try:
                    chain_context = p_chain_ctx.contents
                    if chain_context.cChain > 0 and chain_context.rgpChain:
                        simple_chain = chain_context.rgpChain[0].contents
                        for i in range(simple_chain.cElement):
                            elem_ptr = simple_chain.rgpElement[i]
                            if elem_ptr and elem_ptr.contents.pCertContext:
                                ctx = elem_ptr.contents.pCertContext.contents
                                if ctx.pbCertEncoded and ctx.cbCertEncoded > 0:
                                    der = bytes(
                                        ctypes.string_at(
                                            ctx.pbCertEncoded, ctx.cbCertEncoded
                                        )
                                    )
                                    chain_der.append(der)
                finally:
                    _crypt32.CertFreeCertificateChain(p_chain_ctx)
        except Exception:
            # Nếu dựng chuỗi thất bại thì fallback về danh sách chỉ chứa chứng thư đó
            pass

        if not chain_der:
            chain_der = [cert_der]
        return chain_der

    def certificates(self) -> list[CertEntry]:
        """Duyệt store và trả về danh sách chứng thư có khoá riêng dùng được.

        Nếu hardware_only=True, chỉ giữ lại chứng thư nằm trên phần cứng (USB token, smartcard).
        Giải phóng triệt để mọi handle được cấp phát trong quá trình duyệt.
        """
        if not is_available():
            raise KeySourceError(
                "Windows Certificate Store chỉ hoạt động trên hệ điều hành Windows."
            )

        entries: list[CertEntry] = []

        with self._open_store() as h_store:
            p_cert = None
            try:
                while True:
                    p_cert = _crypt32.CertEnumCertificatesInStore(h_store, p_cert)
                    if not p_cert:
                        break

                    cert_ctx = p_cert.contents
                    if not cert_ctx.pbCertEncoded or cert_ctx.cbCertEncoded == 0:
                        continue

                    cert_der = bytes(
                        ctypes.string_at(
                            cert_ctx.pbCertEncoded, cert_ctx.cbCertEncoded
                        )
                    )

                    # Kiểm tra chứng thư có khoá riêng hay không
                    h_key_or_prov = ctypes.c_size_t(0)
                    dw_key_spec = _DWORD(0)
                    f_caller_free = _BOOL(0)

                    ok = _crypt32.CryptAcquireCertificatePrivateKey(
                        p_cert,
                        CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                        None,
                        ctypes.byref(h_key_or_prov),
                        ctypes.byref(dw_key_spec),
                        ctypes.byref(f_caller_free),
                    )
                    if not ok:
                        # Chứng thư không có khoá riêng hoặc không thể acquire
                        continue

                    try:
                        # Kiểm tra khoá phần cứng nếu hardware_only=True
                        if self.hardware_only and not self._is_hardware_key(
                            h_key_or_prov.value, dw_key_spec.value
                        ):
                            continue
                    finally:
                        self._free_key_handle(
                            h_key_or_prov.value,
                            dw_key_spec.value,
                            bool(f_caller_free.value),
                        )

                    # Dựng chuỗi chứng thư
                    chain_der = self._build_chain(h_store, p_cert, cert_der)

                    # Dựng CertEntry
                    try:
                        entry = CertEntry.build(cert_der, chain_der)
                        entries.append(entry)
                    except Exception:
                        continue
            finally:
                if p_cert:
                    _crypt32.CertFreeCertificateContext(p_cert)

        return entries

    def _sign_cng(
        self, h_key: int, digest: bytes, algo: SigAlgo, params: dict
    ) -> bytes:
        """Ký bản băm bằng NCryptSignHash qua đường CNG (NCRYPT_KEY_HANDLE)."""
        p_pad_info = None
        pad_info_holder = None  # giữ tham chiếu Python để tránh GC giải phóng con trỏ
        flags = 0

        if algo == SigAlgo.RSA_PKCS1_SHA256:
            pad_info_holder = BCRYPT_PKCS1_PADDING_INFO(pszAlgId="SHA256")
            p_pad_info = ctypes.cast(
                ctypes.byref(pad_info_holder), ctypes.c_void_p
            )
            flags = BCRYPT_PAD_PKCS1
        elif algo == SigAlgo.RSA_PSS_SHA256:
            # Salt do server chỉ định, KHÔNG mặc định 32: pyHanko khai salt
            # dài tối đa nên đoán sai là chữ ký không verify được.
            pad_info_holder = BCRYPT_PSS_PADDING_INFO(
                pszAlgId="SHA256", cbSalt=pss_salt_length(params)
            )
            p_pad_info = ctypes.cast(
                ctypes.byref(pad_info_holder), ctypes.c_void_p
            )
            flags = BCRYPT_PAD_PSS
        elif algo == SigAlgo.ECDSA_SHA256:
            p_pad_info = None
            flags = 0
        else:
            raise KeySourceError(
                f"Thuật toán ký không được hỗ trợ qua CNG: {algo}"
            )

        hash_buf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        cb_result = _DWORD(0)

        # Lần gọi 1: lấy kích thước bộ đệm chữ ký (pbSignature = NULL)
        status = _ncrypt.NCryptSignHash(
            h_key,
            p_pad_info,
            hash_buf,
            len(digest),
            None,
            0,
            ctypes.byref(cb_result),
            flags,
        )
        if status != 0:
            raise KeySourceError(
                f"NCryptSignHash (lấy kích thước chữ ký) thất bại: {_format_win_error(status)}"
            )
        if cb_result.value == 0:
            raise KeySourceError("NCryptSignHash trả về kích thước chữ ký bằng 0.")

        # Lần gọi 2: thực hiện ký
        sig_buf = (ctypes.c_ubyte * cb_result.value)()
        status = _ncrypt.NCryptSignHash(
            h_key,
            p_pad_info,
            hash_buf,
            len(digest),
            sig_buf,
            cb_result.value,
            ctypes.byref(cb_result),
            flags,
        )
        if status != 0:
            raise KeySourceError(
                f"NCryptSignHash (ký bản băm) thất bại: {_format_win_error(status)}"
            )

        raw_sig = bytes(sig_buf[: cb_result.value])

        if algo == SigAlgo.ECDSA_SHA256:
            # CNG trả về r||s, CMS yêu cầu DER SEQUENCE { r INTEGER, s INTEGER }
            return ecdsa_raw_to_der(raw_sig)

        return raw_sig

    def _sign_csp(
        self, h_prov: int, dw_key_spec: int, digest: bytes, algo: SigAlgo
    ) -> bytes:
        """Ký bản băm bằng CryptSignHashW qua đường CSP cũ (HCRYPTPROV)."""
        if algo != SigAlgo.RSA_PKCS1_SHA256:
            raise KeySourceError(
                f"Token chỉ có CSP cũ (CryptoAPI), không hỗ trợ thuật toán {algo.value}. "
                "Chỉ hỗ trợ RSA_PKCS1_SHA256."
            )

        h_hash = ctypes.c_size_t(0)
        if not _advapi32.CryptCreateHash(
            h_prov, CALG_SHA_256, 0, 0, ctypes.byref(h_hash)
        ):
            err = _get_last_error()
            raise KeySourceError(
                f"CryptCreateHash thất bại: {_format_win_error(err)}"
            )

        try:
            hash_buf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
            if not _advapi32.CryptSetHashParam(
                h_hash.value, HP_HASHVAL, hash_buf, 0
            ):
                err = _get_last_error()
                raise KeySourceError(
                    f"CryptSetHashParam thất bại: {_format_win_error(err)}"
                )

            sig_len = _DWORD(0)
            # Lần gọi 1: lấy kích thước chữ ký (pbSignature = NULL)
            if not _advapi32.CryptSignHashW(
                h_hash.value, dw_key_spec, None, 0, None, ctypes.byref(sig_len)
            ):
                err = _get_last_error()
                raise KeySourceError(
                    f"CryptSignHashW (lấy kích thước chữ ký) thất bại: {_format_win_error(err)}"
                )

            if sig_len.value == 0:
                raise KeySourceError(
                    "CryptSignHashW trả về kích thước chữ ký bằng 0."
                )

            # Lần gọi 2: thực hiện ký
            sig_buf = (ctypes.c_ubyte * sig_len.value)()
            if not _advapi32.CryptSignHashW(
                h_hash.value, dw_key_spec, None, 0, sig_buf, ctypes.byref(sig_len)
            ):
                err = _get_last_error()
                raise KeySourceError(
                    f"CryptSignHashW (ký bản băm) thất bại: {_format_win_error(err)}"
                )

            raw_sig = bytes(sig_buf[: sig_len.value])
            # CryptoAPI trả chữ ký RSA theo thứ tự byte little-endian,
            # phải đảo ngược mảng byte để đưa về định dạng big-endian chuẩn.
            return raw_sig[::-1]
        finally:
            if h_hash.value:
                _advapi32.CryptDestroyHash(h_hash.value)

    def sign(
        self, cert_id: str, data: bytes, algo: SigAlgo, params: dict
    ) -> bytes:
        """Ký dữ liệu ``data`` bằng chứng thư có định danh ``cert_id``.

        Dữ liệu được băm SHA-256 phía agent trước khi chuyển tới thiết bị ký.
        Người dùng có thể thấy hộp thoại yêu cầu nhập mã PIN do Windows hoặc
        driver của USB token hiển thị.
        """
        if not is_available():
            raise KeySourceError(
                "Windows Certificate Store chỉ hoạt động trên hệ điều hành Windows."
            )

        if isinstance(algo, str) and not isinstance(algo, SigAlgo):
            algo = SigAlgo(algo)

        # Mở store để tìm chứng thư và thực hiện ký
        with self._open_store() as h_store:
            p_target_cert = None
            p_cert = None
            try:
                while True:
                    p_cert = _crypt32.CertEnumCertificatesInStore(h_store, p_cert)
                    if not p_cert:
                        break

                    ctx = p_cert.contents
                    if not ctx.pbCertEncoded or ctx.cbCertEncoded == 0:
                        continue

                    der = bytes(
                        ctypes.string_at(ctx.pbCertEncoded, ctx.cbCertEncoded)
                    )
                    if cert_id_for(der) == cert_id:
                        p_target_cert = _crypt32.CertDuplicateCertificateContext(
                            p_cert
                        )
                        break
            finally:
                if p_cert:
                    _crypt32.CertFreeCertificateContext(p_cert)

            if not p_target_cert:
                raise KeySourceError(
                    f"Không tìm thấy chứng thư với mã '{cert_id}' trong Windows Certificate Store '{self.store_name}'."
                )

            try:
                h_key_or_prov = ctypes.c_size_t(0)
                dw_key_spec = _DWORD(0)
                f_caller_free = _BOOL(0)

                ok = _crypt32.CryptAcquireCertificatePrivateKey(
                    p_target_cert,
                    CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                    None,
                    ctypes.byref(h_key_or_prov),
                    ctypes.byref(dw_key_spec),
                    ctypes.byref(f_caller_free),
                )
                if not ok:
                    err = _get_last_error()
                    raise KeySourceError(
                        f"Không thể lấy khoá riêng cho chứng thư '{cert_id}': {_format_win_error(err)}"
                    )

                try:
                    if self.hardware_only and not self._is_hardware_key(
                        h_key_or_prov.value, dw_key_spec.value
                    ):
                        raise KeySourceError(
                            f"Khoá riêng của chứng thư '{cert_id}' không nằm trên thiết bị phần cứng (hardware_only=True)."
                        )

                    # Băm dữ liệu bằng SHA-256 phía agent
                    digest = hashlib.sha256(data).digest()

                    if (dw_key_spec.value & 0xFFFFFFFF) == CERT_NCRYPT_KEY_SPEC:
                        # Đường CNG
                        return self._sign_cng(
                            h_key_or_prov.value, digest, algo, params
                        )
                    else:
                        # Đường CSP cũ
                        return self._sign_csp(
                            h_key_or_prov.value, dw_key_spec.value, digest, algo
                        )
                finally:
                    self._free_key_handle(
                        h_key_or_prov.value,
                        dw_key_spec.value,
                        bool(f_caller_free.value),
                    )
            finally:
                _crypt32.CertFreeCertificateContext(p_target_cert)
