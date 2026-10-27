/**
 * API client, CSRF token handling, state, DOM helpers, và constants.
 */

export const state = {
  me: null,
  config: null,
  csrfToken: "",
  currentRoute: "",
  routeParams: {},
  routeQuery: {},
};

export const STATUS_LABELS = {
  draft: "Nháp",
  in_progress: "Đang ký",
  completed: "Hoàn tất",
  declined: "Bị từ chối",
  voided: "Đã huỷ",
  expired: "Hết hạn",
};

export const ROLE_LABELS = {
  owner: "Chủ sở hữu",
  admin: "Quản trị viên",
  member: "Thành viên",
  signer: "Người ký",
  approver: "Người duyệt",
};

// Đúng các loại sự kiện backend ghi vào nhật ký (backend/app/documents.py).
export const AUDIT_EVENT_LABELS = {
  "document.created": "Tạo tài liệu",
  "document.updated": "Sửa thông tin tài liệu",
  "document.recipients_set": "Khai báo người nhận",
  "document.sent": "Gửi tài liệu",
  "document.voided": "Huỷ tài liệu",
  "document.declined": "Tài liệu bị từ chối",
  "document.completed": "Hoàn tất tài liệu",
  "document.expired": "Hết hạn",
  "document.downloaded": "Tải tệp PDF",
  "document.imported": "Nhập từ bản cũ",
  "recipient.notified": "Gửi email mời",
  "recipient.viewed": "Người nhận mở tài liệu",
  "recipient.approved": "Đã duyệt",
  "recipient.signed": "Đã ký số",
  "recipient.declined": "Người nhận từ chối",
  "recipient.link_rotated": "Cấp lại liên kết ký",
};

export const BOX_SIZES = {
  nho: [140, 76],
  chuan: [165, 90],
  lon: [190, 104],
  rat_lon: [220, 120],
};

export const RECIPIENT_COLORS = [
  { border: "#3b82f6", bg: "rgba(59, 130, 246, 0.15)", text: "#93c5fd", label: "Xanh dương" },
  { border: "#10b981", bg: "rgba(16, 185, 129, 0.15)", text: "#6ee7b7", label: "Xanh lá" },
  { border: "#a855f7", bg: "rgba(168, 85, 247, 0.15)", text: "#d8b4fe", label: "Tím" },
  { border: "#f59e0b", bg: "rgba(245, 158, 11, 0.15)", text: "#fcd34d", label: "Cam" },
  { border: "#ec4899", bg: "rgba(236, 72, 153, 0.15)", text: "#f472b6", label: "Hồng" },
  { border: "#06b6d4", bg: "rgba(6, 182, 212, 0.15)", text: "#67e8f9", label: "Xanh ngọc" },
];

/**
 * Tạo DOM element an toàn với thuộc tính, sự kiện và con.
 */
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null) continue;
      if (key.startsWith("on") && typeof value === "function") {
        node.addEventListener(key.slice(2).toLowerCase(), value);
      } else if (key === "className" || key === "class") {
        node.className = value;
      } else if (key === "style" && typeof value === "object") {
        Object.assign(node.style, value);
      } else if (key === "dataset" && typeof value === "object") {
        Object.assign(node.dataset, value);
      } else if (key === "htmlFor") {
        node.htmlFor = value;
      } else if (typeof value === "boolean") {
        if (value) node.setAttribute(key, "");
      } else {
        node.setAttribute(key, value);
      }
    }
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    if (typeof child === "string" || typeof child === "number") {
      node.appendChild(document.createTextNode(String(child)));
    } else if (child instanceof Node) {
      node.appendChild(child);
    }
  }
  return node;
}

/**
 * Hiển thị thông báo Toast góc dưới màn hình.
 */
export function toast(message, type = "info", duration = 4000) {
  let container = document.getElementById("toasts");
  if (!container) {
    container = el("div", { id: "toasts", className: "toasts" });
    document.body.appendChild(container);
  }
  const item = el(
    "div",
    { className: `toast ${type === "err" ? "err" : type === "ok" ? "ok" : ""}` },
    message
  );
  container.appendChild(item);
  setTimeout(() => {
    item.classList.add("out");
    setTimeout(() => item.remove(), 400);
  }, duration);
}

/**
 * Gọi API backend với X-CSRF-Token và xử lý lỗi tập trung.
 */
export async function api(path, options = {}) {
  const opts = { ...options };
  opts.headers = { ...(opts.headers || {}) };
  opts.credentials = "same-origin";

  const method = (opts.method || "GET").toUpperCase();

  if (opts.body && !(opts.body instanceof FormData) && typeof opts.body === "object") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }

  // Luôn gửi X-CSRF-Token cho các request thay đổi trạng thái
  if (method !== "GET" && method !== "HEAD") {
    if (state.csrfToken) {
      opts.headers["X-CSRF-Token"] = state.csrfToken;
    }
  }

  const res = await fetch(path, opts);

  if (res.status === 204) {
    return null;
  }

  const contentType = res.headers.get("content-type") || "";
  let data = null;
  if (contentType.includes("application/json")) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    let msg = "Đã xảy ra lỗi không xác định";
    const code = data?.code || "unknown_error";

    if (data?.detail) {
      if (Array.isArray(data.detail)) {
        msg = data.detail
          .map((err) => {
            const field = err.loc ? err.loc.filter((p) => p !== "body").join(".") : "";
            return field ? `${field}: ${err.msg}` : err.msg;
          })
          .join("; ");
      } else if (typeof data.detail === "string") {
        msg = data.detail;
      }
    } else if (res.statusText) {
      msg = `${res.status} ${res.statusText}`;
    }

    // Xử lý các mã lỗi đặc biệt
    if (res.status === 401) {
      const isAuthRoute =
        location.hash.startsWith("#/login") ||
        location.hash.startsWith("#/register") ||
        location.hash.startsWith("#/forgot") ||
        location.hash.startsWith("#/reset") ||
        location.hash.startsWith("#/invite");
      if (!isAuthRoute) {
        state.me = null;
        location.hash = "#/login";
      }
    } else if (res.status === 402 || code === "quota_exceeded") {
      toast(`${msg} — Xem chi tiết tại mục Gói & sử dụng`, "err", 6000);
    } else if (res.status === 429 || code === "rate_limited") {
      toast("Quá nhiều yêu cầu. Vui lòng thử lại sau giây lát.", "err", 5000);
    }

    const error = new Error(msg);
    error.status = res.status;
    error.code = code;
    error.data = data;
    throw error;
  }

  return data !== null ? data : res;
}

/**
 * Định dạng ngày giờ chuẩn tiếng Việt theo múi giờ địa phương.
 */
export function formatDate(isoString, includeTime = true) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return new Intl.DateTimeFormat("vi-VN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      ...(includeTime
        ? {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
          }
        : {}),
    }).format(d);
  } catch {
    return isoString;
  }
}

/**
 * Hiển thị Modal Dialog
 */
export function showModal({ title, content, actions = [], onClose }) {
  const overlay = el("div", { className: "modal-overlay" });
  const closeBtn = el(
    "button",
    {
      className: "modal-close",
      title: "Đóng",
      onClick: () => {
        overlay.remove();
        if (onClose) onClose();
      },
    },
    "✕"
  );

  const header = el(
    "div",
    { className: "modal-header" },
    el("h3", { className: "modal-title" }, title),
    closeBtn
  );

  const body = el("div", { className: "modal-body" }, content);

  const footer = el(
    "div",
    { className: "modal-footer" },
    ...actions.map((act) => {
      const btn = el(
        "button",
        {
          className: act.className || (act.primary ? "primary" : act.danger ? "danger" : ""),
          onClick: async () => {
            if (act.onClick) {
              const keep = await act.onClick(overlay);
              if (keep === false) return;
            }
            overlay.remove();
            if (onClose) onClose();
          },
        },
        act.label
      );
      return btn;
    })
  );

  const modalBox = el("div", { className: "modal-card" }, header, body, footer);
  overlay.appendChild(modalBox);

  // Nhấn ra ngoài để đóng nếu không phải modal khẩn cấp
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) {
      overlay.remove();
      if (onClose) onClose();
    }
  });

  document.body.appendChild(overlay);
  return overlay;
}

/**
 * Hộp thoại xác nhận (Confirm Dialog)
 */
export function confirmModal({ title = "Xác nhận", message, confirmText = "Đồng ý", danger = false, onConfirm }) {
  showModal({
    title,
    content: el("p", { style: { margin: "8px 0" } }, message),
    actions: [
      { label: "Huỷ" },
      {
        label: confirmText,
        danger,
        primary: !danger,
        onClick: async () => {
          if (onConfirm) await onConfirm();
        },
      },
    ],
  });
}

/**
 * Hộp thoại nhập giá trị (Prompt Dialog)
 */
export function promptModal({
  title = "Nhập thông tin",
  message,
  placeholder = "",
  defaultValue = "",
  confirmText = "Xác nhận",
  onConfirm,
}) {
  const input = el("input", {
    type: "text",
    placeholder,
    value: defaultValue,
    style: { width: "100%", marginTop: "8px" },
  });

  showModal({
    title,
    content: el("div", {}, el("p", { style: { margin: "0 0 8px 0" } }, message), input),
    actions: [
      { label: "Huỷ" },
      {
        label: confirmText,
        primary: true,
        onClick: async () => {
          const val = input.value.trim();
          if (onConfirm) await onConfirm(val);
        },
      },
    ],
  });
  setTimeout(() => input.focus(), 50);
}
