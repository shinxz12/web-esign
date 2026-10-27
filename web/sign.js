/**
 * Web Signer — Giao diện người nhận (liên kết ký /s/<token>).
 *
 * Người nhận (người ký hoặc người duyệt) chỉ tương tác với tài liệu của họ.
 * pdf.js nạp từ /vendor/pdfjs cục bộ (không dùng CDN, không eval).
 */
import * as pdfjs from "/vendor/pdfjs/pdf.min.mjs";

pdfjs.GlobalWorkerOptions.workerSrc = "/vendor/pdfjs/pdf.worker.min.mjs";

const TOKEN = location.pathname.startsWith("/s/")
  ? decodeURIComponent(location.pathname.slice(3))
  : null;

const $ = (id) => document.getElementById(id);
const ui = {
  // Topbar
  docName: $("doc-name"),
  docStatus: $("doc-status"),
  btnVerify: $("btn-verify"),
  btnDownload: $("btn-download"),

  // Viewer
  viewer: $("viewer"),
  pages: $("pages"),
  pageInfo: $("page-info"),
  emptyState: $("empty-state"),
  emptyText: $("empty-text"),
  placeHint: $("place-hint"),
  btnPlace: $("btn-place"),
  btnClearBox: $("btn-clear-box"),
  zoomLevel: $("zoom-level"),
  zoomIn: $("zoom-in"),
  zoomOut: $("zoom-out"),
  zoomFit: $("zoom-fit"),

  // Doc Info Card
  docInfoCard: $("doc-info-card"),
  docCardTitle: $("doc-card-title"),
  docOrgRow: $("doc-org-row"),
  docOrgName: $("doc-org-name"),
  docMsgBox: $("doc-msg-box"),
  docMsgText: $("doc-msg-text"),
  recipientsList: $("recipients-list"),

  // Turn Card
  turnCard: $("turn-card"),
  turnInfo: $("turn-info"),

  // Approver
  approverCard: $("approver-card"),
  btnApprove: $("btn-approve"),
  btnDeclineApprover: $("btn-decline-approver"),
  approverStatus: $("approver-status"),

  // Signer: Step 1 Agent
  stepAgent: $("step-agent"),
  agentStatus: $("agent-status"),
  deviceInfo: $("device-info"),
  forgetDevice: $("btn-forget-device"),
  manualPair: $("manual-pair"),
  agentCode: $("agent-code"),
  btnConnect: $("btn-connect"),

  // Signer: Step 2 Cert
  stepCert: $("step-cert"),
  certList: $("cert-list"),

  // Signer: Step 3 Place & Style
  stepPlace: $("step-place"),
  fieldFixedNotice: $("field-fixed-notice"),
  sizeControlGroup: $("size-control-group"),
  size: $("sign-size"),
  color: $("sign-color"),
  border: $("sign-border"),
  check: $("sign-check"),
  logoInput: $("logo-input"),
  btnLogoClear: $("btn-logo-clear"),
  logoStatus: $("logo-status"),
  previewStage: $("preview-stage"),
  boxInfo: $("box-info"),

  // Signer: Action
  signerActionCard: $("signer-action-card"),
  btnSign: $("btn-sign"),
  btnDeclineSigner: $("btn-decline-signer"),
  signStatus: $("sign-status"),
  profileHint: $("profile-hint"),

  // Verify
  verifyCard: $("verify-card"),
  verifyResult: $("verify-result"),

  // Decline Dialog
  declineDialog: $("decline-dialog"),
  declineForm: $("decline-form"),
  declineReason: $("decline-reason"),
  declineError: $("decline-error"),
  btnDeclineCancel: $("btn-decline-cancel"),
  btnDeclineConfirm: $("btn-decline-confirm"),

  // Toasts
  toasts: $("toasts"),
};

const BOX_SIZES = {
  nho: [140, 76],
  chuan: [165, 90],
  lon: [190, 104],
  rong: [220, 120],
};

const COLOR_HEX = {
  "xanh-duong": "#143a7a",
  "xanh-la": "#1c7a3d",
  do: "#a11c1c",
  den: "#111111",
};

const MIN_SCALE = 0.4;
const MAX_SCALE = 3;

const DOC_STATUS_MAP = {
  draft: { text: "Bản nháp", class: "draft" },
  in_progress: { text: "Đang ký", class: "in_progress" },
  completed: { text: "Hoàn tất", class: "completed" },
  declined: { text: "Bị từ chối", class: "declined" },
  voided: { text: "Đã huỷ", class: "voided" },
  expired: { text: "Hết hạn", class: "expired" },
};

const state = {
  token: TOKEN,
  doc: null,
  recipient: null,
  turn: null,
  profile: null,
  timestamping: false,
  pdf: null,
  pages: [],
  scale: 1.3,
  placing: false,
  box: null, // { page: 0-based, rect: [x1, y1, x2, y2] điểm PDF }
  fixedField: false,
  certId: null,
  cert: null,
  hasLogo: false,
  logoVersion: 0,
  pairingCode: null,
  certSignature: null,
};

let ghost = null;

// --------------------------------------------------------------------------
// Tiện ích
// --------------------------------------------------------------------------

function setStatus(el, text, kind = "muted") {
  if (!el) return;
  el.className = `status ${kind}`;
  el.textContent = text;
}

function toast(text, kind = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = text;
  ui.toasts.appendChild(el);
  setTimeout(() => el.classList.add("out"), 3200);
  setTimeout(() => el.remove(), 3600);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    let code = null;
    try {
      const err = await response.json();
      detail = err.detail || detail;
      code = err.code || null;
    } catch {}
    if (Array.isArray(detail)) {
      detail = detail.map((e) => e.msg || JSON.stringify(e)).join(", ");
    } else if (typeof detail !== "string") {
      detail = JSON.stringify(detail);
    }
    const error = new Error(detail);
    error.status = response.status;
    error.code = code;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function handleError(error, statusEl) {
  let msg = error.message;
  if (error.code === "wrong_signer") {
    const expected = state.recipient?.tax_code
      ? `MST ${state.recipient.tax_code}`
      : state.recipient?.name || "";
    msg = error.message || `Chứng thư số không khớp với người được mời (${expected}).`;
  }
  if (statusEl) setStatus(statusEl, msg, "err");
  toast(msg, "err");
}

function formatDate(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    const p = (v) => String(v).padStart(2, "0");
    return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
  } catch {
    return isoStr.replace("T", " ").slice(0, 16);
  }
}

function nowStamp() {
  const now = new Date();
  const p = (v) => String(v).padStart(2, "0");
  const offset = -now.getTimezoneOffset();
  const sign = offset < 0 ? "-" : "+";
  const abs = Math.abs(offset);
  return (
    `${p(now.getDate())}/${p(now.getMonth() + 1)}/${now.getFullYear()} ` +
    `${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())} ` +
    `${sign}${p(Math.floor(abs / 60))}${p(abs % 60)}`
  );
}

// --------------------------------------------------------------------------
// Hiển thị thông tin tài liệu & danh sách người nhận
// --------------------------------------------------------------------------

function renderDocumentInfo() {
  if (!state.doc) return;

  const title = state.doc.title || state.doc.filename || "Tài liệu";
  ui.docName.textContent = title;
  ui.docCardTitle.textContent = title;

  const sInfo = DOC_STATUS_MAP[state.doc.status] || {
    text: state.doc.status,
    class: "draft",
  };
  ui.docStatus.hidden = false;
  ui.docStatus.textContent = sInfo.text;
  ui.docStatus.className = `badge ${sInfo.class}`;

  const canDownload = state.doc.status === "completed" || (state.doc.revision || 0) > 0;
  ui.btnDownload.hidden = !canDownload;
  if (canDownload) {
    ui.btnDownload.href = `/api/sign/${state.token}/file?download=true`;
  }

  if (state.doc.organization) {
    ui.docOrgRow.hidden = false;
    ui.docOrgName.textContent = state.doc.organization;
  } else {
    ui.docOrgRow.hidden = true;
  }

  if (state.doc.message) {
    ui.docMsgBox.hidden = false;
    ui.docMsgText.textContent = state.doc.message;
  } else {
    ui.docMsgBox.hidden = true;
  }

  renderRecipientsList();
}

function renderRecipientsList() {
  if (!state.doc?.recipients) {
    ui.recipientsList.replaceChildren();
    return;
  }

  ui.recipientsList.replaceChildren(
    ...state.doc.recipients.map((r) => {
      const isYou = r.id === state.recipient?.id;
      const item = document.createElement("div");
      item.className = `recipient-item${isYou ? " current-user" : ""}`;

      const top = document.createElement("div");
      top.className = "recipient-top";

      const nameWrap = document.createElement("div");
      nameWrap.className = "recipient-name-wrap";

      const order = document.createElement("span");
      order.className = "recipient-order";
      order.textContent = `#${r.order}`;
      nameWrap.appendChild(order);

      const name = document.createElement("span");
      name.className = "recipient-name";
      name.textContent = r.name;
      nameWrap.appendChild(name);

      if (isYou) {
        const you = document.createElement("span");
        you.className = "badge you";
        you.textContent = "Bạn";
        nameWrap.appendChild(you);
      }
      top.appendChild(nameWrap);

      const roleBadge = document.createElement("span");
      roleBadge.className = "badge role-badge";
      roleBadge.textContent = r.role === "approver" ? "Duyệt" : "Ký";
      top.appendChild(roleBadge);
      item.appendChild(top);

      const detail = document.createElement("div");
      detail.className = "recipient-detail";

      if (r.tax_code) {
        const mst = document.createElement("span");
        mst.textContent = `MST: ${r.tax_code}`;
        detail.appendChild(mst);
      }

      const statusRow = document.createElement("span");
      let statusText = "";
      let statusTone = "muted";
      if (r.status === "signed") {
        statusText = `✓ Đã ký${r.acted_at ? " lúc " + formatDate(r.acted_at) : ""}`;
        statusTone = "ok";
      } else if (r.status === "approved") {
        statusText = `✓ Đã duyệt${r.acted_at ? " lúc " + formatDate(r.acted_at) : ""}`;
        statusTone = "ok";
      } else if (r.status === "declined") {
        statusText = `✕ Đã từ chối${r.acted_at ? " lúc " + formatDate(r.acted_at) : ""}`;
        statusTone = "err";
      } else {
        statusText = r.role === "approver" ? "Chờ duyệt" : "Chờ ký";
      }
      statusRow.className = `status ${statusTone}`;
      statusRow.style.margin = "0";
      statusRow.textContent = statusText;
      detail.appendChild(statusRow);

      if (r.status === "declined" && r.decline_reason) {
        const reasonEl = document.createElement("span");
        reasonEl.className = "decline-msg";
        reasonEl.textContent = `Lý do: ${r.decline_reason}`;
        detail.appendChild(reasonEl);
      }

      item.appendChild(detail);
      return item;
    }),
  );
}

// --------------------------------------------------------------------------
// Lượt xử lý & vai trò (Approver / Signer)
// --------------------------------------------------------------------------

function applyTurn() {
  const turn = state.turn;
  const r = state.recipient;
  if (!turn || !r) return;

  ui.turnCard.hidden = false;

  if (turn.can_act) {
    if (r.role === "approver") {
      setStatus(ui.turnInfo, "Đến lượt bạn duyệt tài liệu này.", "ok");
      ui.approverCard.hidden = false;
      ui.btnApprove.disabled = false;
      ui.btnDeclineApprover.disabled = false;

      // Ẩn toàn bộ UI ký số
      ui.stepAgent.hidden = true;
      ui.stepCert.hidden = true;
      ui.stepPlace.hidden = true;
      ui.signerActionCard.hidden = true;
      ui.btnPlace.hidden = true;
      ui.btnClearBox.hidden = true;
    } else {
      // Role signer
      setStatus(ui.turnInfo, "Đến lượt bạn ký tài liệu.", "ok");
      ui.approverCard.hidden = true;

      // Hiện UI ký số
      ui.stepAgent.hidden = false;
      ui.stepCert.hidden = false;
      ui.stepPlace.hidden = false;
      ui.signerActionCard.hidden = false;
      ui.btnDeclineSigner.disabled = false;

      if (r.field) {
        state.fixedField = true;
        state.box = { page: r.field.page, rect: r.field.box };
        ui.fieldFixedNotice.hidden = false;
        ui.sizeControlGroup.hidden = true;
        ui.btnPlace.hidden = true;
        ui.btnClearBox.hidden = true;
      } else {
        state.fixedField = false;
        ui.fieldFixedNotice.hidden = true;
        ui.sizeControlGroup.hidden = false;
        ui.btnPlace.hidden = false;
        ui.btnPlace.disabled = false;
      }
    }
  } else {
    // Không thể thao tác
    ui.approverCard.hidden = true;
    ui.stepAgent.hidden = true;
    ui.stepCert.hidden = true;
    ui.stepPlace.hidden = true;
    ui.signerActionCard.hidden = true;
    ui.btnPlace.hidden = true;
    ui.btnClearBox.hidden = true;

    if (r.role === "signer" && r.field && r.status === "pending") {
      // Nếu là người ký có ô ký đặt sẵn nhưng chưa đến lượt, vẫn giữ toạ độ để hiển thị vị trí
      state.fixedField = true;
      state.box = { page: r.field.page, rect: r.field.box };
    }

    const waiting = turn.waiting_for?.length
      ? turn.waiting_for.join(", ")
      : "người trước";

    const reasonMessages = {
      not_your_turn: `Chưa tới lượt bạn — đang chờ ${waiting}.`,
      already_acted:
        r.status === "approved"
          ? "Bạn đã duyệt tài liệu này."
          : r.status === "signed"
            ? "Bạn đã ký tài liệu này."
            : r.status === "declined"
              ? "Bạn đã từ chối tài liệu này."
              : "Bạn đã xử lý tài liệu này rồi.",
      document_completed: "Tài liệu đã hoàn tất.",
      document_declined: "Tài liệu đã bị từ chối.",
      document_voided: `Tài liệu đã bị huỷ${state.doc.void_reason ? `: ${state.doc.void_reason}` : ""}.`,
      document_expired: "Tài liệu đã hết hạn ký.",
    };

    const tone =
      turn.reason === "not_your_turn"
        ? "busy"
        : turn.reason === "already_acted" || turn.reason === "document_completed"
          ? "ok"
          : "err";

    setStatus(
      ui.turnInfo,
      reasonMessages[turn.reason] || turn.reason || "Tài liệu ở chế độ chỉ đọc.",
      tone,
    );
  }
}

// --------------------------------------------------------------------------
// Mở tài liệu & Nạp PDF
// --------------------------------------------------------------------------

async function openDocument() {
  if (!state.token) {
    ui.emptyState.hidden = false;
    ui.emptyText.textContent = "Không tìm thấy mã liên kết ký (/s/<token>).";
    return;
  }

  try {
    const data = await api(`/api/sign/${state.token}`);
    state.doc = data.document;
    state.recipient = data.recipient;
    state.turn = data.turn;
    state.profile = data.profile;

    renderDocumentInfo();
    applyTurn();
    ui.btnVerify.disabled = false;
    ui.emptyState.hidden = true;

    await loadPdf();
    await refreshLogo();
  } catch (error) {
    ui.emptyState.hidden = false;
    ui.emptyText.textContent = error.message;
    toast(error.message, "err");
  }
}

async function loadPdf() {
  const url = `/api/sign/${state.token}/file?r=${state.doc?.revision || 0}`;
  state.pdf = await pdfjs.getDocument({
    url,
    withCredentials: true,
    isEvalSupported: false,
  }).promise;
  await layoutPages();
  drawBox();
  updateBoxInfo();

  if (state.fixedField && state.box) {
    setTimeout(scrollToBox, 150);
  }
}

async function handleActionResult(payload) {
  const oldRevision = state.doc?.revision;
  state.doc = payload.document;
  state.recipient = payload.recipient;
  state.turn = payload.turn;
  if (payload.profile) state.profile = payload.profile;

  renderDocumentInfo();
  applyTurn();

  if (payload.document.revision !== oldRevision) {
    await loadPdf();
  } else {
    drawBox();
    updateBoxInfo();
  }
}

// --------------------------------------------------------------------------
// Viewer cuộn liên tục (Continuous-scroll lazy viewer)
// --------------------------------------------------------------------------

const visibility = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      const item = state.pages[Number(entry.target.dataset.index)];
      if (entry.isIntersecting && item) renderPage(item);
    }
  },
  { root: ui.pages, rootMargin: "400px 0px" },
);

async function layoutPages() {
  visibility.disconnect();
  ui.pages.replaceChildren();
  state.pages = [];

  for (let num = 1; num <= state.pdf.numPages; num++) {
    const page = await state.pdf.getPage(num);
    const holder = document.createElement("div");
    holder.className = "page";
    holder.dataset.index = String(num - 1);

    const label = document.createElement("div");
    label.className = "page-label";
    label.textContent = String(num);

    const canvas = document.createElement("canvas");
    const overlay = document.createElement("div");
    overlay.className = "overlay";

    holder.append(canvas, overlay, label);
    ui.pages.appendChild(holder);

    const item = { num, page, holder, canvas, overlay, viewport: null };
    state.pages.push(item);
    sizePage(item);
    visibility.observe(holder);
  }
  updatePageInfo();
  updateZoomLabel();
}

function sizePage(item) {
  const viewport = item.page.getViewport({ scale: state.scale });
  item.viewport = viewport;
  item.rendered = false;
  item.holder.style.width = `${Math.floor(viewport.width)}px`;
  item.holder.style.height = `${Math.floor(viewport.height)}px`;
  item.canvas.style.width = `${Math.floor(viewport.width)}px`;
  item.canvas.style.height = `${Math.floor(viewport.height)}px`;
}

async function renderPage(item) {
  if (item.rendered) return;
  item.rendered = true;
  const viewport = item.viewport;
  const dpr = window.devicePixelRatio || 1;
  item.canvas.width = Math.floor(viewport.width * dpr);
  item.canvas.height = Math.floor(viewport.height * dpr);

  const task = item.page.render({
    canvasContext: item.canvas.getContext("2d"),
    viewport,
    transform: dpr === 1 ? null : [dpr, 0, 0, dpr, 0, 0],
  });
  item.task = task;
  try {
    await task.promise;
  } catch {
    if (item.task === task) item.rendered = false;
  }
}

function setScale(scale) {
  state.scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale));
  for (const item of state.pages) {
    item.task?.cancel?.();
    sizePage(item);
  }
  for (const item of visiblePages()) renderPage(item);
  drawBox();
  updateZoomLabel();
}

function visiblePages() {
  const top = ui.pages.scrollTop - 400;
  const bottom = top + ui.pages.clientHeight + 800;
  return state.pages.filter(
    (item) =>
      item.holder.offsetTop + item.holder.offsetHeight >= top &&
      item.holder.offsetTop <= bottom,
  );
}

function fitWidth() {
  const first = state.pages[0];
  if (!first) return;
  const natural = first.page.getViewport({ scale: 1 }).width;
  setScale((ui.pages.clientWidth - 56) / natural);
}

function updateZoomLabel() {
  ui.zoomLevel.textContent = `${Math.round(state.scale * 100)}%`;
}

function currentPageNumber() {
  const middle = ui.pages.scrollTop + ui.pages.clientHeight / 2;
  let current = 1;
  for (const item of state.pages) {
    if (item.holder.offsetTop <= middle) current = item.num;
  }
  return current;
}

function updatePageInfo() {
  if (!state.pdf) return;
  ui.pageInfo.textContent = `Trang ${currentPageNumber()} / ${state.pdf.numPages}`;
}

ui.pages.addEventListener("scroll", updatePageInfo, { passive: true });

// --------------------------------------------------------------------------
// Ô ký & Vị trí
// --------------------------------------------------------------------------

function boxSize() {
  return BOX_SIZES[ui.size.value] || BOX_SIZES.chuan;
}

function clampRect(item, x1, y1, width, height) {
  const [vx1, vy1, vx2, vy2] = item.page.view;
  const x = Math.min(Math.max(x1, vx1), Math.max(vx1, vx2 - width));
  const y = Math.min(Math.max(y1, vy1), Math.max(vy1, vy2 - height));
  return [x, y, x + width, y + height].map((v) => Math.round(v));
}

function placeBoxAt(item, clientX, clientY) {
  if (state.fixedField) return;
  const rect = item.overlay.getBoundingClientRect();
  const [px, py] = item.viewport.convertToPdfPoint(
    clientX - rect.left,
    clientY - rect.top,
  );
  const [w, h] = boxSize();
  state.box = {
    page: item.num - 1,
    rect: clampRect(item, px - w / 2, py - h / 2, w, h),
  };
  drawBox();
  updateBoxInfo();
}

function enablePlacing(on) {
  if (state.fixedField) return;
  state.placing = on && Boolean(state.turn?.can_act);
  ui.placeHint.hidden = !state.placing;
  ui.btnPlace.classList.toggle("active", state.placing);
  ui.btnPlace.textContent = state.placing ? "✕ Huỷ đặt" : "✎ Đặt chữ ký";
  for (const item of state.pages) {
    item.overlay.classList.toggle("placing", state.placing);
  }
  if (!state.placing) removeGhost();
}

function removeGhost() {
  ghost?.remove();
  ghost = null;
}

function moveGhost(item, clientX, clientY) {
  if (!ghost) {
    ghost = document.createElement("div");
    ghost.className = "sig-box ghost";
    ghost.appendChild(previewNode());
  }
  if (ghost.parentElement !== item.overlay) item.overlay.appendChild(ghost);
  const rect = item.overlay.getBoundingClientRect();
  const [w, h] = boxSize();
  const pw = w * state.scale;
  const ph = h * state.scale;
  ghost.style.width = `${pw}px`;
  ghost.style.height = `${ph}px`;
  ghost.style.left = `${clientX - rect.left - pw / 2}px`;
  ghost.style.top = `${clientY - rect.top - ph / 2}px`;
  applyPreviewScale(ghost, state.scale);
}

ui.pages.addEventListener("pointermove", (event) => {
  if (!state.placing) return;
  const item = pageOfEvent(event);
  if (item) moveGhost(item, event.clientX, event.clientY);
});

ui.pages.addEventListener("pointerdown", (event) => {
  if (!state.placing) return;
  const item = pageOfEvent(event);
  if (!item) return;
  event.preventDefault();
  placeBoxAt(item, event.clientX, event.clientY);
  enablePlacing(false);
  toast("Đã đặt ô ký — kéo để chỉnh lại vị trí.");
});

function pageOfEvent(event) {
  const holder = event.target.closest?.(".page");
  return holder ? state.pages[Number(holder.dataset.index)] : null;
}

function scrollToBox() {
  if (!state.box) return;
  const item = state.pages[state.box.page];
  if (!item || !item.holder) return;
  item.holder.scrollIntoView({ behavior: "smooth", block: "center" });
}

function drawBox() {
  for (const item of state.pages) {
    for (const node of item.overlay.querySelectorAll(".sig-box:not(.ghost)")) {
      node.remove();
    }
  }
  ui.btnClearBox.hidden = state.fixedField || !state.box;
  if (!state.box) return;

  const item = state.pages[state.box.page];
  if (!item) return;
  const [x1, y1, x2, y2] = state.box.rect;
  const [sx1, sy1] = item.viewport.convertToViewportPoint(x1, y2);
  const [sx2, sy2] = item.viewport.convertToViewportPoint(x2, y1);

  const div = document.createElement("div");
  div.className = `sig-box${state.fixedField ? " fixed" : ""}`;
  const width = Math.abs(sx2 - sx1);
  const height = Math.abs(sy2 - sy1);
  div.style.left = `${Math.min(sx1, sx2)}px`;
  div.style.top = `${Math.min(sy1, sy2)}px`;
  div.style.width = `${width}px`;
  div.style.height = `${height}px`;
  div.appendChild(previewNode());

  if (!state.fixedField) {
    div.appendChild(handleNode());
    attachDrag(div, item);
  }

  applyPreviewScale(div, state.scale);
  item.overlay.appendChild(div);
}

function handleNode() {
  const grip = document.createElement("div");
  grip.className = "sig-grip";
  grip.textContent = "⠿ kéo";
  return grip;
}

function attachDrag(div, item) {
  div.addEventListener("pointerdown", (event) => {
    if (state.placing || state.fixedField) return;
    event.preventDefault();
    event.stopPropagation();
    div.setPointerCapture(event.pointerId);
    div.classList.add("dragging");

    const rect = item.overlay.getBoundingClientRect();
    const start = item.viewport.convertToPdfPoint(
      event.clientX - rect.left,
      event.clientY - rect.top,
    );
    const origin = state.box.rect.slice();
    const [w, h] = [origin[2] - origin[0], origin[3] - origin[1]];

    const move = (e) => {
      const now = item.viewport.convertToPdfPoint(
        e.clientX - rect.left,
        e.clientY - rect.top,
      );
      state.box.rect = clampRect(
        item,
        origin[0] + (now[0] - start[0]),
        origin[1] + (now[1] - start[1]),
        w,
        h,
      );
      const [sx1, sy1] = item.viewport.convertToViewportPoint(
        state.box.rect[0],
        state.box.rect[3],
      );
      div.style.left = `${sx1}px`;
      div.style.top = `${sy1}px`;
      updateBoxInfo();
    };

    const up = () => {
      div.classList.remove("dragging");
      div.removeEventListener("pointermove", move);
      div.removeEventListener("pointerup", up);
    };
    div.addEventListener("pointermove", move);
    div.addEventListener("pointerup", up);
  });
}

function previewNode() {
  const wrap = document.createElement("div");
  wrap.className = "sig-preview";
  wrap.style.color = COLOR_HEX[ui.color.value] || COLOR_HEX["xanh-duong"];
  wrap.classList.toggle("bordered", ui.border.checked);

  if (ui.check.checked) {
    const check = document.createElement("div");
    check.className = "sig-check";
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M3 13 L9 19 L21 5");
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", "#22b32a");
    path.setAttribute("stroke-width", "4");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("stroke-linejoin", "round");
    svg.appendChild(path);
    check.appendChild(svg);
    wrap.appendChild(check);
  }

  if (state.hasLogo) {
    const logo = document.createElement("img");
    logo.className = "sig-logo";
    logo.src = `/api/sign/${state.token}/logo/image?t=${state.logoVersion || 0}`;
    logo.alt = "";
    wrap.appendChild(logo);
  }

  const text = document.createElement("div");
  text.className = "sig-text";
  if (state.hasLogo) text.classList.add("with-logo");

  const lines = state.cert
    ? [
        `Digitally signed by/Ký bởi: ${state.cert.subject}`,
        state.cert.tax_code ? `Tax code/MST: ${state.cert.tax_code}` : null,
        `Signing date/Ngày ký: ${nowStamp()}`,
      ].filter(Boolean)
    : ["Chọn chứng thư ở bước 2 để xem trước nội dung chữ ký."];

  for (const line of lines) {
    const row = document.createElement("div");
    row.textContent = line;
    text.appendChild(row);
  }
  wrap.appendChild(text);
  return wrap;
}

function applyPreviewScale(node, scale) {
  const preview = node.classList.contains("sig-preview")
    ? node
    : node.querySelector(".sig-preview");
  if (preview) preview.style.fontSize = `${Math.max(5, 7 * scale)}px`;
}

function renderPreviewStage() {
  const [w, h] = state.box
    ? [
        state.box.rect[2] - state.box.rect[0],
        state.box.rect[3] - state.box.rect[1],
      ]
    : boxSize();

  const stage = ui.previewStage;
  const scale = (stage.clientWidth || 290) / w;
  stage.style.height = `${Math.round(h * scale)}px`;
  const node = previewNode();
  stage.replaceChildren(node);
  applyPreviewScale(node, scale);
}

function refreshPreview() {
  renderPreviewStage();
  drawBox();
  if (ghost) {
    ghost.replaceChildren(previewNode());
    applyPreviewScale(ghost, state.scale);
  }
}

function updateBoxInfo() {
  if (!state.doc) {
    setStatus(ui.boxInfo, "Chưa mở tài liệu.", "muted");
  } else if (!state.turn?.can_act) {
    setStatus(ui.boxInfo, "Tài liệu này hiện không nhận chữ ký của bạn.", "muted");
  } else if (!state.box) {
    setStatus(
      ui.boxInfo,
      "Chưa chọn vị trí — bấm “Đặt chữ ký” rồi bấm vào chỗ muốn ký.",
      "muted",
    );
  } else {
    const [x1, y1, x2, y2] = state.box.rect;
    const fixedMsg = state.fixedField ? " (ô ký cố định)" : "";
    setStatus(
      ui.boxInfo,
      `Trang ${state.box.page + 1} · ${x2 - x1}×${y2 - y1} pt tại (${x1}, ${y1})${fixedMsg}`,
      "ok",
    );
  }

  const canSign = Boolean(
    state.box &&
      state.certId &&
      state.doc &&
      state.turn?.can_act &&
      state.recipient?.role === "signer",
  );
  ui.btnSign.disabled = !canSign;
}

// --------------------------------------------------------------------------
// Agent & Chứng thư số
// --------------------------------------------------------------------------

async function connectAgent() {
  const code = ui.agentCode.value.trim();
  if (!code) return setStatus(ui.agentStatus, "Nhập mã ghép cặp.", "err");

  setStatus(ui.agentStatus, "Đang kết nối agent…", "busy");
  try {
    const data = await api(`/api/agents/${code}/certificates`);
    state.pairingCode = code;
    setStatus(ui.agentStatus, `Đã kết nối: ${data.agent} (${data.platform})`, "ok");
    ui.stepAgent.classList.add("done");
    renderCertificates(data.certificates);
  } catch (error) {
    state.pairingCode = null;
    setStatus(ui.agentStatus, error.message, "err");
    ui.stepAgent.classList.remove("done");
    ui.certList.replaceChildren();
  }
}

async function detectDevice() {
  if (state.pairingCode) return;
  let info;
  try {
    info = await api("/api/agents");
  } catch {
    return;
  }

  ui.forgetDevice.hidden = !info.device;
  ui.deviceInfo.textContent = info.device ? `Máy: ${info.device.name}` : "";

  if (!info.device) {
    setStatus(
      ui.agentStatus,
      "Trình duyệt này chưa gắn với máy nào. Mở agent trên máy có token, " +
        "hoặc dùng mã ghép cặp bên dưới.",
      "muted",
    );
    ui.manualPair.open = true;
    ui.stepAgent.classList.remove("done");
    return;
  }

  if (!info.online) {
    setStatus(ui.agentStatus, "Agent chưa chạy trên máy này.", "busy");
    ui.stepAgent.classList.remove("done");
    renderCertificates([]);
    return;
  }

  setStatus(ui.agentStatus, `Đã sẵn sàng: ${info.agent} (${info.platform})`, "ok");
  ui.manualPair.open = false;
  ui.stepAgent.classList.add("done");
  renderCertificates(info.certificates);
}

function renderCertificates(certs) {
  const signature = (certs || []).map((c) => c.id).join("|");
  if (signature === state.certSignature) return;
  state.certSignature = signature;
  state.certId = null;
  state.cert = null;
  ui.stepCert.classList.remove("done");
  updateBoxInfo();

  if (!certs || !certs.length) {
    ui.certList.replaceChildren();
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "Chưa thấy chứng thư nào — cắm USB token vào máy.";
    ui.certList.appendChild(p);
    return;
  }

  ui.certList.replaceChildren(
    ...certs.map((cert) => {
      const div = document.createElement("div");
      div.className = "cert";

      const cn = document.createElement("div");
      cn.className = "cn";
      cn.textContent = cert.subject;

      const meta = document.createElement("div");
      meta.className = "meta";
      const notAfter = cert.not_after ? cert.not_after.slice(0, 10) : "";
      meta.textContent = `${cert.issuer}${notAfter ? ` · hiệu lực đến ${notAfter}` : ""}`;

      div.append(cn, meta);

      div.onclick = () => {
        state.certId = cert.id;
        state.cert = cert;
        ui.stepCert.classList.add("done");
        [...ui.certList.children].forEach((c) =>
          c.classList.toggle("selected", c === div),
        );
        refreshPreview();
        updateBoxInfo();
      };
      return div;
    }),
  );

  if (certs.length === 1) {
    ui.certList.firstChild.click();
  }
}

// --------------------------------------------------------------------------
// Thao tác Ký số, Duyệt & Từ chối
// --------------------------------------------------------------------------

async function sign() {
  if (!state.certId) {
    return setStatus(ui.signStatus, "Vui lòng chọn chứng thư ở bước 2.", "err");
  }
  if (!state.fixedField && !state.box) {
    return setStatus(ui.signStatus, "Vui lòng chọn vị trí ô ký ở bước 3.", "err");
  }

  ui.btnSign.disabled = true;
  ui.btnSign.classList.add("busy");
  setStatus(
    ui.signStatus,
    "Đang gửi yêu cầu tới agent — xác nhận và nhập PIN trên máy có token…",
    "busy",
  );

  try {
    const payload = {
      agent_code: state.pairingCode || undefined,
      cert_id: state.certId,
      color: ui.color.value,
      show_border: ui.border.checked,
      check_mark: ui.check.checked,
      use_logo: state.hasLogo,
    };
    if (!state.fixedField) {
      payload.page = state.box.page;
      payload.box = state.box.rect;
    }

    const result = await api(`/api/sign/${state.token}/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    setStatus(ui.signStatus, "Đã ký xong.", "ok");
    toast("Ký số thành công.");
    state.box = null;
    await handleActionResult(result);
    await runVerify();
  } catch (error) {
    handleError(error, ui.signStatus);
  } finally {
    ui.btnSign.classList.remove("busy");
    updateBoxInfo();
  }
}

async function approve() {
  ui.btnApprove.disabled = true;
  ui.btnApprove.classList.add("busy");
  setStatus(ui.approverStatus, "Đang duyệt tài liệu…", "busy");

  try {
    const result = await api(`/api/sign/${state.token}/approve`, {
      method: "POST",
    });
    setStatus(ui.approverStatus, "Đã duyệt thành công.", "ok");
    toast("Đã duyệt tài liệu.");
    await handleActionResult(result);
  } catch (error) {
    handleError(error, ui.approverStatus);
  } finally {
    ui.btnApprove.classList.remove("busy");
  }
}

function openDeclineDialog() {
  ui.declineReason.value = "";
  ui.declineError.hidden = true;
  ui.declineError.textContent = "";
  ui.declineDialog.showModal();
}

function closeDeclineDialog() {
  ui.declineDialog.close();
}

async function handleDeclineSubmit(e) {
  e.preventDefault();
  const reason = ui.declineReason.value.trim();
  if (!reason) {
    ui.declineError.hidden = false;
    ui.declineError.textContent = "Vui lòng nhập lý do từ chối.";
    return;
  }

  ui.btnDeclineConfirm.disabled = true;
  ui.btnDeclineConfirm.classList.add("busy");
  ui.declineError.hidden = true;

  try {
    const result = await api(`/api/sign/${state.token}/decline`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    closeDeclineDialog();
    toast("Đã từ chối tài liệu.");
    await handleActionResult(result);
  } catch (error) {
    ui.declineError.hidden = false;
    ui.declineError.textContent = error.message;
  } finally {
    ui.btnDeclineConfirm.classList.remove("busy");
    ui.btnDeclineConfirm.disabled = false;
  }
}

// --------------------------------------------------------------------------
// Logo / Con dấu
// --------------------------------------------------------------------------

async function refreshLogo() {
  try {
    const res = await api(`/api/sign/${state.token}/logo`);
    state.hasLogo = Boolean(res?.has_logo);
    setStatus(
      ui.logoStatus,
      state.hasLogo ? "Đã có logo, sẽ vẽ bên trái chữ ký." : "Chưa có logo.",
      state.hasLogo ? "ok" : "muted",
    );
  } catch {
    state.hasLogo = false;
    setStatus(ui.logoStatus, "", "muted");
  }
  refreshPreview();
}

async function uploadLogo() {
  const file = ui.logoInput.files[0];
  if (!file) return;
  const body = new FormData();
  body.append("file", file);
  try {
    const info = await api(`/api/sign/${state.token}/logo`, {
      method: "POST",
      body,
    });
    state.logoVersion = Date.now();
    setStatus(ui.logoStatus, `Đã tải logo ${info.format}.`, "ok");
    toast("Đã cập nhật logo.");
  } catch (error) {
    setStatus(ui.logoStatus, error.message, "err");
    toast(error.message, "err");
  }
  ui.logoInput.value = "";
  await refreshLogo();
}

// --------------------------------------------------------------------------
// Xác thực chữ ký
// --------------------------------------------------------------------------

async function runVerify() {
  ui.verifyCard.hidden = false;
  ui.verifyResult.replaceChildren();
  const p = document.createElement("p");
  p.className = "hint";
  p.textContent = "Đang kiểm tra chữ ký…";
  ui.verifyResult.appendChild(p);

  try {
    const reports = await api(`/api/sign/${state.token}/verify`);
    if (!reports || !reports.length) {
      ui.verifyResult.replaceChildren();
      const emptyP = document.createElement("p");
      emptyP.className = "hint";
      emptyP.textContent = "Tài liệu chưa có chữ ký số.";
      ui.verifyResult.appendChild(emptyP);
      return;
    }

    ui.verifyResult.replaceChildren(
      ...reports.map((report) => {
        const tone = !report.intact
          ? "invalid"
          : report.trusted
            ? "valid"
            : "warn";
        const div = document.createElement("div");
        div.className = `sig-report ${tone}`;

        const who = document.createElement("div");
        who.className = "who";
        who.textContent = `${tone === "valid" ? "✓" : tone === "warn" ? "!" : "✗"} ${report.signer}`;
        div.appendChild(who);

        const lines = [
          `${report.field_name} · ${report.issuer}`,
          report.tax_code ? `MST ${report.tax_code}` : null,
          report.signed_at ? `Ký lúc ${formatDate(report.signed_at)}` : null,
          report.timestamped
            ? `Dấu thời gian TSA: ${formatDate(report.timestamp_at)}${
                report.timestamp_trusted ? "" : " (chưa tin cậy)"
              }`
            : "Không có dấu thời gian",
          report.ltv
            ? "LTV: kiểm tra thu hồi bằng dữ liệu nhúng trong tệp"
            : "LTV: chưa nhúng dữ liệu thu hồi",
          `${report.profile} — ${report.summary}`,
          ...(report.problems || []),
          ...(report.notes || []),
        ].filter(Boolean);

        for (const line of lines) {
          const l = document.createElement("div");
          l.className = "line";
          l.textContent = line;
          div.appendChild(l);
        }
        return div;
      }),
    );
  } catch (error) {
    ui.verifyResult.replaceChildren();
    const errP = document.createElement("p");
    errP.className = "status err";
    errP.textContent = error.message;
    ui.verifyResult.appendChild(errP);
  }
}

// --------------------------------------------------------------------------
// Lắng nghe sự kiện
// --------------------------------------------------------------------------

ui.btnPlace.onclick = () => enablePlacing(!state.placing);
ui.btnClearBox.onclick = () => {
  if (state.fixedField) return;
  state.box = null;
  drawBox();
  updateBoxInfo();
};

ui.btnConnect.onclick = connectAgent;
ui.agentCode.addEventListener("keydown", (e) => {
  if (e.key === "Enter") connectAgent();
});

ui.forgetDevice.onclick = async () => {
  await api("/api/devices/browser", { method: "DELETE" }).catch(() => {});
  state.pairingCode = null;
  state.certSignature = null;
  await detectDevice();
  toast("Đã quên máy này trên trình duyệt hiện tại.");
};

ui.btnSign.onclick = sign;
ui.btnApprove.onclick = approve;
ui.btnDeclineApprover.onclick = openDeclineDialog;
ui.btnDeclineSigner.onclick = openDeclineDialog;
ui.btnDeclineCancel.onclick = closeDeclineDialog;
ui.declineForm.onsubmit = handleDeclineSubmit;

ui.btnVerify.onclick = runVerify;
ui.logoInput.onchange = uploadLogo;
ui.btnLogoClear.onclick = async () => {
  await api(`/api/sign/${state.token}/logo`, { method: "DELETE" }).catch(() => {});
  await refreshLogo();
};

ui.zoomIn.onclick = () => setScale(state.scale * 1.2);
ui.zoomOut.onclick = () => setScale(state.scale / 1.2);
ui.zoomFit.onclick = fitWidth;

for (const el of [ui.color, ui.border, ui.check]) {
  el.addEventListener("change", refreshPreview);
}

ui.size.addEventListener("change", () => {
  if (state.box && !state.fixedField) {
    const item = state.pages[state.box.page];
    const [w, h] = boxSize();
    state.box.rect = clampRect(item, state.box.rect[0], state.box.rect[1], w, h);
  }
  refreshPreview();
  updateBoxInfo();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && state.placing) enablePlacing(false);
  if (!state.box || state.placing || state.fixedField) return;
  const step = e.shiftKey ? 10 : 1;
  const delta = {
    ArrowLeft: [-step, 0],
    ArrowRight: [step, 0],
    ArrowUp: [0, step],
    ArrowDown: [0, -step],
  }[e.key];
  if (!delta || e.target.matches("input, select, textarea")) return;
  e.preventDefault();
  const item = state.pages[state.box.page];
  const [w, h] = boxSize();
  state.box.rect = clampRect(
    item,
    state.box.rect[0] + delta[0],
    state.box.rect[1] + delta[1],
    w,
    h,
  );
  drawBox();
  updateBoxInfo();
});

window.addEventListener("resize", () => {
  renderPreviewStage();
  drawBox();
});

// --------------------------------------------------------------------------
// Khởi tạo
// --------------------------------------------------------------------------

api("/api/config")
  .then((cfg) => {
    state.timestamping = Boolean(cfg.timestamping);
    const prof = state.profile || cfg.profile || "B-LT";
    setStatus(
      ui.profileHint,
      `Hồ sơ chữ ký: ${prof}${state.timestamping ? " (có dấu thời gian TSA)" : ""}`,
      "muted",
    );
  })
  .catch(() => {});

detectDevice();
setInterval(() => {
  if (!document.hidden) detectDevice();
}, 10000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) detectDevice();
});

openDocument();
