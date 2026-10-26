/**
 * Viewer + luồng ký.
 *
 * Browser chỉ gửi vị trí khung chữ ký (toạ độ PDF) lên server. Nó không chạm
 * vào USB token, không dựng CMS, không tải PDF về để ký.
 *
 * Hai chế độ dùng chung giao diện này:
 *   /            chủ tài liệu — tải lên, khai báo luồng ký, tự ký khi tự do
 *   /s/<invite>  người được mời ký — chỉ thấy đúng tài liệu của mình
 *
 * Viewer cuộn liên tục: mọi trang được dựng sẵn khung, canvas chỉ vẽ khi trang
 * lọt vào tầm nhìn — tài liệu vài trăm trang vẫn mở được mà không cần nút next.
 */
import * as pdfjs from "https://cdn.jsdelivr.net/npm/pdfjs-dist@4.10.38/build/pdf.min.mjs";

pdfjs.GlobalWorkerOptions.workerSrc =
  "https://cdn.jsdelivr.net/npm/pdfjs-dist@4.10.38/build/pdf.worker.min.mjs";

const INVITE = location.pathname.startsWith("/s/")
  ? decodeURIComponent(location.pathname.slice(3))
  : null;
const SIGNER_MODE = INVITE !== null;

const $ = (id) => document.getElementById(id);
const ui = {
  docName: $("doc-name"),
  docStatus: $("doc-status"),
  docList: $("doc-list"),
  fileInput: $("file-input"),
  pages: $("pages"),
  pageInfo: $("page-info"),
  emptyState: $("empty-state"),
  placeHint: $("place-hint"),
  zoomLevel: $("zoom-level"),
  agentCode: $("agent-code"),
  agentStatus: $("agent-status"),
  certList: $("cert-list"),
  boxInfo: $("box-info"),
  signStatus: $("sign-status"),
  profileHint: $("profile-hint"),
  logoInput: $("logo-input"),
  logoStatus: $("logo-status"),
  btnPlace: $("btn-place"),
  btnClearBox: $("btn-clear-box"),
  btnSign: $("btn-sign"),
  btnVerify: $("btn-verify"),
  btnConnect: $("btn-connect"),
  btnDownload: $("btn-download"),
  verifyCard: $("verify-card"),
  verifyResult: $("verify-result"),
  turnCard: $("turn-card"),
  turnInfo: $("turn-info"),
  signersCard: $("signers-card"),
  signersRows: $("signers-rows"),
  signersStatus: $("signers-status"),
  inviteList: $("invite-list"),
  size: $("sign-size"),
  color: $("sign-color"),
  border: $("sign-border"),
  check: $("sign-check"),
  deviceInfo: $("device-info"),
  manualPair: $("manual-pair"),
  forgetDevice: $("btn-forget-device"),
  previewStage: $("preview-stage"),
  toasts: $("toasts"),
};

/** Cỡ ô ký cố định (điểm PDF). 165×90 là cỡ cân đối nhất: tên tổ chức dài
 *  xuống dòng vẫn đủ chỗ, không phải co chữ. */
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

const state = {
  doc: null,
  pdf: null,
  pages: [], // { num, page, viewport, holder, canvas, overlay, rendered }
  scale: 1.3,
  placing: false,
  box: null, // { page: 0-based, rect: [x1,y1,x2,y2] điểm PDF }
  certId: null,
  cert: null,
  canSign: !SIGNER_MODE,
  hasLogo: false,
  // Mã ghép cặp đang dùng (đường dự phòng). null = đi theo cookie thiết bị.
  pairingCode: null,
  // Chữ ký của danh sách chứng thư, để vòng dò không xoá lựa chọn đang có.
  certSignature: null,
};

const STATUS_LABEL = {
  tu_do: "Ký tự do",
  da_ky: "Đã ký",
  chua_bat_dau: "Chờ người đầu tiên ký",
  cho_ky: "Đang ký",
  hoan_tat: "Hoàn tất",
};

// --------------------------------------------------------------------------
// Tiện ích
// --------------------------------------------------------------------------

function setStatus(el, text, kind = "muted") {
  el.className = `status ${kind}`;
  el.textContent = text;
}

/** Thông báo nổi — phản hồi ngay mà không cần người dùng đi tìm dòng chữ. */
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
    try {
      detail = (await response.json()).detail || detail;
    } catch {}
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}

/** Gốc API của tài liệu đang mở, khác nhau giữa hai chế độ. */
function docBase() {
  return SIGNER_MODE ? `/api/sign/${INVITE}` : `/api/documents/${state.doc.id}`;
}

// --------------------------------------------------------------------------
// Danh sách tài liệu (chủ tài liệu)
// --------------------------------------------------------------------------

async function refreshDocList() {
  if (SIGNER_MODE) return;
  const docs = await api("/api/documents");
  ui.docList.replaceChildren(
    ...docs.map((doc) => {
      const li = document.createElement("li");
      li.textContent = doc.name;
      li.className = doc.id === state.doc?.id ? "active" : "";
      const badge = document.createElement("div");
      badge.className = "sig-count";
      badge.textContent = `${STATUS_LABEL[doc.status]} · ${doc.signatures.length} chữ ký`;
      li.appendChild(badge);
      li.onclick = () => openDocument(doc.id);
      return li;
    }),
  );
}

// --------------------------------------------------------------------------
// Mở tài liệu
// --------------------------------------------------------------------------

async function openDocument(docId) {
  if (SIGNER_MODE) {
    const info = await api(`/api/sign/${INVITE}`);
    state.doc = info.document;
    applyTurn(info);
  } else {
    state.doc = await api(`/api/documents/${docId}`);
    state.canSign = !state.doc.signers.length;
    renderSigners();
  }

  state.box = null;
  enablePlacing(false);
  ui.docName.textContent = state.doc.name;
  ui.docStatus.hidden = false;
  ui.docStatus.textContent = STATUS_LABEL[state.doc.status];
  ui.emptyState.hidden = true;
  ui.btnPlace.disabled = !state.canSign;
  ui.btnVerify.disabled = false;
  ui.verifyCard.hidden = true;
  if (!SIGNER_MODE) {
    ui.btnDownload.hidden = state.doc.signatures.length === 0;
    ui.btnDownload.href = `/api/documents/${state.doc.id}/download`;
  }

  const url = `${docBase()}/file?r=${state.doc.revision}`;
  state.pdf = await pdfjs.getDocument({ url, withCredentials: true }).promise;
  await layoutPages();
  drawBox();
  updateBoxInfo();
  await refreshDocList();
}

function applyTurn(info) {
  ui.turnCard.hidden = false;
  if (info.already_signed) {
    state.canSign = false;
    setStatus(ui.turnInfo, `Bạn (${info.slot.name}) đã ký tài liệu này.`, "ok");
  } else if (info.my_turn) {
    state.canSign = true;
    setStatus(ui.turnInfo, `Đến lượt bạn: ${info.slot.name}`, "ok");
  } else {
    state.canSign = false;
    setStatus(
      ui.turnInfo,
      `Chưa tới lượt bạn — đang chờ ${info.waiting_for} ký.`,
      "busy",
    );
  }
}

// --------------------------------------------------------------------------
// Viewer cuộn liên tục
// --------------------------------------------------------------------------

/** Chỉ vẽ trang đang (sắp) nhìn thấy; phần còn lại giữ chỗ bằng khung trắng. */
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
    label.textContent = num;

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
  item.rendered = true; // chặn hai lần vẽ chồng lên nhau khi cuộn nhanh
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
    // Huỷ do đổi zoom. Chỉ hạ cờ khi không có lượt vẽ mới nào đã bắt đầu,
    // nếu không IntersectionObserver gọi render() thứ hai trên cùng canvas.
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
// Ô ký kích thước cố định
// --------------------------------------------------------------------------

function boxSize() {
  return BOX_SIZES[ui.size.value] || BOX_SIZES.chuan;
}

/** Ô ký luôn nằm trọn trong trang: kẹp lại theo hộp trang (điểm PDF). */
function clampRect(item, x1, y1, width, height) {
  const [vx1, vy1, vx2, vy2] = item.page.view;
  const x = Math.min(Math.max(x1, vx1), Math.max(vx1, vx2 - width));
  const y = Math.min(Math.max(y1, vy1), Math.max(vy1, vy2 - height));
  return [x, y, x + width, y + height].map((v) => Math.round(v));
}

function placeBoxAt(item, clientX, clientY) {
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
  state.placing = on && state.canSign;
  ui.placeHint.hidden = !state.placing;
  ui.btnPlace.classList.toggle("active", state.placing);
  ui.btnPlace.textContent = state.placing ? "✕ Huỷ đặt" : "✎ Đặt chữ ký";
  for (const item of state.pages) {
    item.overlay.classList.toggle("placing", state.placing);
  }
  if (!state.placing) removeGhost();
}

let ghost = null;

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

/** Vẽ (hoặc xoá) ô ký trên đúng trang của nó. */
function drawBox() {
  for (const item of state.pages) {
    for (const node of item.overlay.querySelectorAll(".sig-box:not(.ghost)")) {
      node.remove();
    }
  }
  ui.btnClearBox.hidden = !state.box;
  if (!state.box) return;

  const item = state.pages[state.box.page];
  if (!item) return;
  const [x1, y1, x2, y2] = state.box.rect;
  const [sx1, sy1] = item.viewport.convertToViewportPoint(x1, y2);
  const [sx2, sy2] = item.viewport.convertToViewportPoint(x2, y1);

  const div = document.createElement("div");
  div.className = "sig-box";
  const width = Math.abs(sx2 - sx1);
  const height = Math.abs(sy2 - sy1);
  div.style.left = `${Math.min(sx1, sx2)}px`;
  div.style.top = `${Math.min(sy1, sy2)}px`;
  div.style.width = `${width}px`;
  div.style.height = `${height}px`;
  div.appendChild(previewNode());
  div.appendChild(handleNode());
  applyPreviewScale(div, state.scale);
  attachDrag(div, item);
  item.overlay.appendChild(div);
}

function handleNode() {
  const grip = document.createElement("div");
  grip.className = "sig-grip";
  grip.textContent = "⠿ kéo";
  return grip;
}

/** Kéo ô ký trong phạm vi trang. Kích thước giữ nguyên — chỉ đổi vị trí. */
function attachDrag(div, item) {
  div.addEventListener("pointerdown", (event) => {
    if (state.placing) return;
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

/** Xem trước nội dung hình chữ ký đúng như server sẽ vẽ. */
function previewNode() {
  const wrap = document.createElement("div");
  wrap.className = "sig-preview";
  wrap.style.color = COLOR_HEX[ui.color.value];
  wrap.classList.toggle("bordered", ui.border.checked);

  if (ui.check.checked) {
    const check = document.createElement("div");
    check.className = "sig-check";
    check.innerHTML =
      '<svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path d="M3 13 L9 19 L21 5" fill="none" stroke="#22b32a"' +
      ' stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    wrap.appendChild(check);
  }

  if (state.hasLogo) {
    const logo = document.createElement("img");
    logo.className = "sig-logo";
    logo.src = `${logoBase()}/image?t=${state.logoVersion || 0}`;
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

/** Ngày ký hiển thị y như server đóng dấu: dd/mm/yyyy HH:MM:SS +0700. */
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

/** Chữ xem trước co theo tỉ lệ hiển thị để khớp cỡ thật (7pt trên hình ký). */
function applyPreviewScale(node, scale) {
  const preview = node.classList.contains("sig-preview")
    ? node
    : node.querySelector(".sig-preview");
  if (preview) preview.style.fontSize = `${Math.max(5, 7 * scale)}px`;
}

/** Khung xem trước luôn hiện trong panel: mọi tuỳ chọn đổi là thấy ngay. */
function renderPreviewStage() {
  const [w, h] = boxSize();
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
  } else if (!state.canSign) {
    setStatus(ui.boxInfo, "Tài liệu này hiện không nhận chữ ký của bạn.", "muted");
  } else if (!state.box) {
    setStatus(
      ui.boxInfo,
      "Chưa chọn vị trí — bấm “Đặt chữ ký” rồi bấm vào chỗ muốn ký.",
      "muted",
    );
  } else {
    const [x1, y1, x2, y2] = state.box.rect;
    setStatus(
      ui.boxInfo,
      `Trang ${state.box.page + 1} · ${x2 - x1}×${y2 - y1} pt tại (${x1}, ${y1})`,
      "ok",
    );
  }
  ui.btnSign.disabled = !(state.box && state.certId && state.doc && state.canSign);
}

// --------------------------------------------------------------------------
// Agent + chứng thư
// --------------------------------------------------------------------------

/** Mã ghép cặp — chỉ dùng khi trình duyệt chưa kích hoạt cookie thiết bị. */
async function connectAgent() {
  const code = ui.agentCode.value.trim();
  if (!code) return setStatus(ui.agentStatus, "Nhập mã ghép cặp.", "err");

  setStatus(ui.agentStatus, "Đang hỏi agent…", "busy");
  try {
    const data = await api(`/api/agents/${code}/certificates`);
    state.pairingCode = code;
    setStatus(ui.agentStatus, `Đã kết nối: ${data.agent} (${data.platform})`, "ok");
    $("step-agent").classList.add("done");
    renderCertificates(data.certificates);
  } catch (error) {
    state.pairingCode = null;
    setStatus(ui.agentStatus, error.message, "err");
    $("step-agent").classList.remove("done");
    ui.certList.replaceChildren();
  }
}

/**
 * Agent của chính máy này, tìm qua cookie thiết bị — không gõ gì cả.
 *
 * Chạy lặp để bắt được cả hai chiều: cắm/rút token, và agent bật/tắt.
 */
async function detectDevice() {
  if (state.pairingCode) return; // người dùng đã chọn đường mã ghép cặp
  let info;
  try {
    info = await api("/api/agents");
  } catch {
    return; // mạng chớp: giữ nguyên trạng thái, lần sau thử lại
  }

  ui.forgetDevice.hidden = !info.device;
  ui.deviceInfo.textContent = info.device
    ? `Máy: ${info.device.name}`
    : "";

  if (!info.device) {
    setStatus(
      ui.agentStatus,
      "Trình duyệt này chưa gắn với máy nào. Mở agent trên máy có token, " +
        "hoặc dùng mã ghép cặp bên dưới.",
      "muted",
    );
    ui.manualPair.open = true;
    $("step-agent").classList.remove("done");
    return;
  }

  if (!info.online) {
    setStatus(ui.agentStatus, "Agent chưa chạy trên máy này.", "busy");
    $("step-agent").classList.remove("done");
    renderCertificates([]);
    return;
  }

  setStatus(ui.agentStatus, `Đã sẵn sàng: ${info.agent} (${info.platform})`, "ok");
  ui.manualPair.open = false;
  $("step-agent").classList.add("done");
  renderCertificates(info.certificates);
}

function renderCertificates(certs) {
  const signature = certs.map((c) => c.id).join("|");
  if (signature === state.certSignature) return; // tránh xoá lựa chọn khi poll
  state.certSignature = signature;
  state.certId = null;
  state.cert = null;
  $("step-cert").classList.remove("done");
  updateBoxInfo();
  if (!certs.length) {
    ui.certList.innerHTML =
      '<p class="hint">Chưa thấy chứng thư nào — cắm USB token vào máy.</p>';
    return;
  }
  ui.certList.replaceChildren(
    ...certs.map((cert) => {
      const div = document.createElement("div");
      div.className = "cert";
      div.innerHTML = `<div class="cn"></div><div class="meta"></div>`;
      div.querySelector(".cn").textContent = cert.subject;
      div.querySelector(".meta").textContent =
        `${cert.issuer} · hiệu lực đến ${cert.not_after.slice(0, 10)}`;
      div.onclick = () => {
        state.certId = cert.id;
        state.cert = cert;
        $("step-cert").classList.add("done");
        [...ui.certList.children].forEach((c) =>
          c.classList.toggle("selected", c === div),
        );
        refreshPreview();
        updateBoxInfo();
      };
      return div;
    }),
  );
  if (certs.length === 1) ui.certList.firstChild.click();
}

// --------------------------------------------------------------------------
// Luồng ký (chủ tài liệu)
// --------------------------------------------------------------------------

function signerRow(name = "", taxCode = "") {
  const row = document.createElement("div");
  row.className = "signer-row";
  row.innerHTML = `
    <input class="signer-name" placeholder="Họ tên / tổ chức" />
    <input class="signer-mst" placeholder="MST (tuỳ chọn)" />
    <button class="signer-del" title="Xoá">×</button>`;
  row.querySelector(".signer-name").value = name;
  row.querySelector(".signer-mst").value = taxCode;
  row.querySelector(".signer-del").onclick = () => row.remove();
  return row;
}

function renderSigners() {
  ui.signersCard.hidden = false;
  ui.inviteList.replaceChildren();
  ui.signersRows.replaceChildren();

  // Luồng ký chốt ngay khi tạo liên kết: server từ chối sửa khi đã có chữ ký,
  // nên giấu luôn phần soạn thảo thay vì để người dùng bấm rồi nhận lỗi.
  const locked = state.doc.signers.length > 0;
  $("btn-add-signer").hidden = locked;
  $("btn-save-signers").hidden = locked;
  ui.signersRows.hidden = locked;

  if (locked) {
    for (const slot of state.doc.signers) {
      const item = document.createElement("div");
      item.className = `invite ${slot.signed_at ? "done" : ""}`;
      item.innerHTML = `<div class="who"></div><input readonly /><div class="line"></div>`;
      item.querySelector(".who").textContent = `${slot.order + 1}. ${slot.name}${
        slot.tax_code ? ` (MST ${slot.tax_code})` : ""
      }`;
      const input = item.querySelector("input");
      input.value = `${location.origin}/s/${slot.invite_token}`;
      input.onclick = (e) => e.target.select();
      item.querySelector(".line").textContent = slot.signed_at
        ? `✓ đã ký ${slot.signed_at.replace("T", " ")}`
        : "chờ ký";
      ui.inviteList.appendChild(item);
    }
    setStatus(
      ui.signersStatus,
      "Đã chốt luồng ký — gửi liên kết tương ứng cho từng người.",
      "ok",
    );
    return;
  }

  ui.signersRows.append(signerRow(), signerRow());
  setStatus(ui.signersStatus, "", "muted");
}

async function saveSigners() {
  const people = [...ui.signersRows.querySelectorAll(".signer-row")]
    .map((row) => ({
      name: row.querySelector(".signer-name").value.trim(),
      tax_code: row.querySelector(".signer-mst").value.trim() || null,
    }))
    .filter((p) => p.name);

  if (!people.length) {
    return setStatus(ui.signersStatus, "Cần ít nhất một người ký.", "err");
  }
  try {
    await api(`/api/documents/${state.doc.id}/signers`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(people),
    });
    await openDocument(state.doc.id);
    toast("Đã tạo liên kết ký cho từng người.");
  } catch (error) {
    setStatus(ui.signersStatus, error.message, "err");
  }
}

// --------------------------------------------------------------------------
// Ký
// --------------------------------------------------------------------------

async function sign() {
  ui.btnSign.disabled = true;
  ui.btnSign.classList.add("busy");
  setStatus(
    ui.signStatus,
    "Đang gửi yêu cầu tới agent — xác nhận và nhập PIN trên máy có token…",
    "busy",
  );
  try {
    await api(`${docBase()}/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agent_code: state.pairingCode,
        cert_id: state.certId,
        page: state.box.page,
        box: state.box.rect,
        color: ui.color.value,
        show_border: ui.border.checked,
        check_mark: ui.check.checked,
      }),
    });
    setStatus(ui.signStatus, "Đã ký xong.", "ok");
    toast("Ký số thành công.");
    state.box = null;
    await openDocument(state.doc?.id);
    await runVerify();
  } catch (error) {
    setStatus(ui.signStatus, error.message, "err");
    toast(error.message, "err");
  } finally {
    ui.btnSign.classList.remove("busy");
    updateBoxInfo();
  }
}

// --------------------------------------------------------------------------
// Logo / con dấu
// --------------------------------------------------------------------------

/** Logo gắn với người ký (cookie chủ hoặc liên kết mời), không gắn với tài liệu. */
function logoBase() {
  return SIGNER_MODE ? `/api/sign/${INVITE}/logo` : "/api/logo";
}

async function refreshLogo() {
  try {
    const { has_logo } = await api(logoBase());
    state.hasLogo = Boolean(has_logo);
    setStatus(
      ui.logoStatus,
      has_logo ? "Đã có logo, sẽ vẽ bên trái chữ ký." : "Chưa có logo.",
      has_logo ? "ok" : "muted",
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
    const info = await api(logoBase(), { method: "POST", body });
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

async function runVerify() {
  ui.verifyCard.hidden = false;
  ui.verifyResult.innerHTML = '<p class="hint">Đang kiểm tra…</p>';
  try {
    const reports = await api(`${docBase()}/verify`);
    if (!reports.length) {
      ui.verifyResult.innerHTML = '<p class="hint">Tài liệu chưa có chữ ký số.</p>';
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
        const lines = [
          `${report.field_name} · ${report.issuer}`,
          report.tax_code ? `MST ${report.tax_code}` : null,
          report.signed_at ? `Ký lúc ${report.signed_at.replace("T", " ")}` : null,
          report.timestamped
            ? `Dấu thời gian TSA: ${report.timestamp_at.replace("T", " ")}${
                report.timestamp_trusted ? "" : " (chưa tin cậy)"
              }`
            : "Không có dấu thời gian",
          report.ltv
            ? "LTV: kiểm tra thu hồi bằng dữ liệu nhúng trong tệp"
            : "LTV: chưa nhúng dữ liệu thu hồi",
          `${report.profile} — ${report.summary}`,
          ...report.problems,
          ...report.notes,
        ].filter(Boolean);
        const who = document.createElement("div");
        who.className = "who";
        who.textContent = `${tone === "valid" ? "✓" : tone === "warn" ? "!" : "✗"} ${report.signer}`;
        div.appendChild(who);
        for (const line of lines) {
          const p = document.createElement("div");
          p.className = "line";
          p.textContent = line;
          div.appendChild(p);
        }
        return div;
      }),
    );
  } catch (error) {
    ui.verifyResult.innerHTML = `<p class="status err"></p>`;
    ui.verifyResult.firstChild.textContent = error.message;
  }
}

// --------------------------------------------------------------------------
// Sự kiện
// --------------------------------------------------------------------------

if (!SIGNER_MODE) {
  ui.fileInput.onchange = async () => {
    const file = ui.fileInput.files[0];
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    const doc = await api("/api/documents", { method: "POST", body });
    ui.fileInput.value = "";
    await openDocument(doc.id);
    toast(`Đã mở ${doc.name}.`);
  };
  $("btn-add-signer").onclick = () => ui.signersRows.appendChild(signerRow());
  $("btn-save-signers").onclick = saveSigners;
} else {
  // Bỏ sidebar thì lưới phải còn 2 cột, nếu không viewer bị ép vào cột 210px
  // và canvas tràn ra ngoài màn hình.
  document.body.classList.add("signer-mode");
  for (const el of document.querySelectorAll("[data-owner-only]")) el.remove();
}

ui.btnPlace.onclick = () => enablePlacing(!state.placing);
ui.btnClearBox.onclick = () => {
  state.box = null;
  drawBox();
  updateBoxInfo();
};
ui.btnConnect.onclick = connectAgent;
ui.forgetDevice.onclick = async () => {
  await api("/api/devices/browser", { method: "DELETE" }).catch(() => {});
  state.pairingCode = null;
  state.certSignature = null;
  await detectDevice();
  toast("Đã quên máy này trên trình duyệt hiện tại.");
};
ui.btnSign.onclick = sign;
ui.btnVerify.onclick = runVerify;
ui.logoInput.onchange = uploadLogo;
$("btn-logo-clear").onclick = async () => {
  await api(logoBase(), { method: "DELETE" }).catch(() => {});
  await refreshLogo();
};
$("zoom-in").onclick = () => setScale(state.scale * 1.2);
$("zoom-out").onclick = () => setScale(state.scale / 1.2);
$("zoom-fit").onclick = fitWidth;

for (const el of [ui.color, ui.border, ui.check]) {
  el.addEventListener("change", refreshPreview);
}
ui.size.addEventListener("change", () => {
  if (state.box) {
    const item = state.pages[state.box.page];
    const [w, h] = boxSize();
    state.box.rect = clampRect(item, state.box.rect[0], state.box.rect[1], w, h);
  }
  refreshPreview();
  updateBoxInfo();
});

ui.agentCode.addEventListener("keydown", (e) => {
  if (e.key === "Enter") connectAgent();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && state.placing) enablePlacing(false);
  if (!state.box || state.placing) return;
  const step = e.shiftKey ? 10 : 1;
  const delta = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] }[e.key];
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

api("/api/session").then((s) => {
  setStatus(
    ui.profileHint,
    `Hồ sơ chữ ký: ${s.profile}${s.timestamping ? " (có dấu thời gian TSA)" : ""}`,
    "muted",
  );
});

refreshLogo(); // kéo theo refreshPreview() -> khung xem trước có ngay từ đầu
updateBoxInfo();

// Tự dò agent của máy này; lặp lại để bắt cắm/rút token và agent bật/tắt.
detectDevice();
// Mỗi lần dò là một chuyến hỏi agent, nên giãn ra và ngủ khi tab bị ẩn.
setInterval(() => {
  if (!document.hidden) detectDevice();
}, 10000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) detectDevice();
});

if (SIGNER_MODE) {
  openDocument(null).catch((error) => {
    ui.emptyState.textContent = error.message;
  });
} else {
  refreshDocList();
}
