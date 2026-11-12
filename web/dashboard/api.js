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
  navigationGuard: null,
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
  { border: "#23408e", bg: "rgba(35, 64, 142, 0.10)", text: "#1b3370", label: "Xanh dương" },
  { border: "#15803d", bg: "rgba(21, 128, 61, 0.10)", text: "#14532d", label: "Xanh lá" },
  { border: "#7e22ce", bg: "rgba(126, 34, 206, 0.10)", text: "#581c87", label: "Tím" },
  { border: "#b45309", bg: "rgba(180, 83, 9, 0.10)", text: "#78350f", label: "Cam" },
  { border: "#be123c", bg: "rgba(190, 18, 60, 0.10)", text: "#881337", label: "Đỏ hồng" },
  { border: "#0e7490", bg: "rgba(14, 116, 144, 0.10)", text: "#155e75", label: "Xanh ngọc" },
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
  const container = document.getElementById("toasts");
  const text = String(message);

  const activeToasts = Array.from(container.querySelectorAll(".toast:not(.out)"));
  if (activeToasts.some((t) => t.textContent === text)) return;
  // Giữ tối đa 3 thông báo: bỏ cái cũ nhất trước khi thêm cái mới
  for (const old of activeToasts.slice(0, Math.max(0, activeToasts.length - 2))) {
    old.remove();
  }

  const item = el(
    "div",
    { className: `toast ${type === "err" ? "err" : type === "ok" ? "ok" : ""}` },
    text
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
    const parts = new Intl.DateTimeFormat("vi-VN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).formatToParts(d);
    const map = {};
    for (const p of parts) map[p.type] = p.value;
    const dateStr = `${map.day}/${map.month}/${map.year}`;
    if (!includeTime) return dateStr;
    return `${dateStr} ${map.hour}:${map.minute}`;
  } catch {
    return isoString;
  }
}

let modalIdCounter = 0;

/**
 * Hiển thị Modal Dialog
 */
export function showModal({ title, content, actions = [], onClose }) {
  const modalId = `modal-${++modalIdCounter}`;
  const titleId = `${modalId}-title`;
  const prevFocused = document.activeElement;

  const overlay = el("div", {
    className: "modal-overlay",
    role: "dialog",
    "aria-modal": "true",
    "aria-labelledby": title ? titleId : undefined,
  });

  const closeBtn = el("button", {
    type: "button",
    className: "modal-close",
    "aria-label": "Đóng",
    title: "Đóng",
    onClick: () => close(),
  });
  closeBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 1l12 12M13 1L1 13"/></svg>`;

  const header = el(
    "div",
    { className: "modal-header" },
    el("h3", { id: titleId, className: "modal-title" }, title),
    closeBtn
  );

  const body = el("div", { className: "modal-body" }, content);

  const footer = el(
    "div",
    { className: "modal-footer" },
    ...actions.map((act) => {
      let btnClass = act.className;
      if (!btnClass) {
        if (act.danger) {
          btnClass = act.solid ? "button danger solid" : "button danger";
        } else if (act.primary) {
          btnClass = "button primary";
        } else {
          btnClass = "button";
        }
      }
      const btn = el(
        "button",
        {
          type: "button",
          className: btnClass,
          onClick: async () => {
            if (act.onClick) {
              const keep = await act.onClick(overlay);
              if (keep === false) return;
            }
            close();
          },
        },
        act.label
      );
      return btn;
    })
  );

  const modalBox = el("div", { className: "modal-card" }, header, body, footer);
  overlay.appendChild(modalBox);

  function close() {
    overlay.remove();
    document.removeEventListener("keydown", onKeyDown);
    if (onClose) onClose();
    if (prevFocused && typeof prevFocused.focus === "function") {
      try {
        prevFocused.focus();
      } catch {}
    }
  }

  function onKeyDown(e) {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
    }
  }
  document.addEventListener("keydown", onKeyDown);

  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) {
      close();
    }
  });

  document.body.appendChild(overlay);

  requestAnimationFrame(() => {
    const focusable = modalBox.querySelector(
      "input:not([disabled]), textarea:not([disabled]), select:not([disabled]), button.primary:not([disabled]), button.danger.solid:not([disabled]), button:not([disabled])"
    );
    if (focusable) {
      focusable.focus();
    } else {
      closeBtn.focus();
    }
  });

  return overlay;
}

/**
 * Hộp thoại xác nhận (Confirm Dialog)
 */
export function confirmModal({
  title = "Xác nhận",
  message,
  confirmText = "Đồng ý",
  danger = false,
  onConfirm,
}) {
  showModal({
    title,
    content: el("p", { style: { margin: "8px 0" } }, message),
    actions: [
      { label: "Huỷ" },
      {
        label: confirmText,
        danger,
        solid: danger,
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
    "aria-label": title,
    style: { width: "100%", marginTop: "8px" },
  });

  input.addEventListener("keydown", async (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      const val = input.value.trim();
      const overlay = input.closest(".modal-overlay");
      if (overlay) overlay.remove();
      if (onConfirm) await onConfirm(val);
    }
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
