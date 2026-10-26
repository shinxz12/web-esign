/**
 * Viewer + luồng ký.
 *
 * Browser chỉ gửi vị trí khung chữ ký (toạ độ PDF) lên server. Nó không chạm
 * vào USB token, không dựng CMS, không tải PDF về để ký.
 *
 * Hai chế độ dùng chung giao diện này:
 *   /            chủ tài liệu — tải lên, khai báo luồng ký, tự ký khi tự do
 *   /s/<invite>  người được mời ký — chỉ thấy đúng tài liệu của mình
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
  canvas: $("pdf-canvas"),
  overlay: $("overlay"),
  pager: $("pager"),
  pageInfo: $("page-info"),
  emptyState: $("empty-state"),
  agentCode: $("agent-code"),
  agentStatus: $("agent-status"),
  certList: $("cert-list"),
  boxInfo: $("box-info"),
  signStatus: $("sign-status"),
  profileHint: $("profile-hint"),
  reason: $("sign-reason"),
  location: $("sign-location"),
  btnPlace: $("btn-place"),
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
};

const state = {
  doc: null,
  pdf: null,
  pageNum: 1,
  viewport: null,
  placing: false,
  box: null,
  certId: null,
  scale: 1.35,
  canSign: !SIGNER_MODE,
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
  ui.docName.textContent = state.doc.name;
  ui.docStatus.hidden = false;
  ui.docStatus.textContent = STATUS_LABEL[state.doc.status];
  ui.emptyState.hidden = true;
  ui.pager.hidden = false;
  ui.btnPlace.disabled = !state.canSign;
  ui.btnVerify.disabled = false;
  ui.verifyCard.hidden = true;
  if (!SIGNER_MODE) {
    ui.btnDownload.hidden = state.doc.signatures.length === 0;
    ui.btnDownload.href = `/api/documents/${state.doc.id}/download`;
  }
  updateBoxInfo();

  const url = `${docBase()}/file?r=${state.doc.revision}`;
  state.pdf = await pdfjs.getDocument({ url, withCredentials: true }).promise;
  state.pageNum = Math.min(state.pageNum, state.pdf.numPages);
  await renderPage();
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

async function renderPage() {
  const page = await state.pdf.getPage(state.pageNum);
  const viewport = page.getViewport({ scale: state.scale });
  state.viewport = viewport;

  const dpr = window.devicePixelRatio || 1;
  const canvas = ui.canvas;
  canvas.width = Math.floor(viewport.width * dpr);
  canvas.height = Math.floor(viewport.height * dpr);
  canvas.style.width = `${viewport.width}px`;
  canvas.style.height = `${viewport.height}px`;

  await page.render({
    canvasContext: canvas.getContext("2d"),
    viewport,
    transform: dpr === 1 ? null : [dpr, 0, 0, dpr, 0, 0],
  }).promise;

  ui.pageInfo.textContent = `Trang ${state.pageNum} / ${state.pdf.numPages}`;
  drawExistingBox();
}

function drawExistingBox() {
  ui.overlay.replaceChildren();
  if (!state.box || state.box.page !== state.pageNum - 1) return;
  const [x1, y1, x2, y2] = state.box.rect;
  const [sx1, sy1] = state.viewport.convertToViewportPoint(x1, y2);
  const [sx2, sy2] = state.viewport.convertToViewportPoint(x2, y1);
  const div = document.createElement("div");
  div.className = "sig-box";
  div.style.left = `${Math.min(sx1, sx2)}px`;
  div.style.top = `${Math.min(sy1, sy2)}px`;
  div.style.width = `${Math.abs(sx2 - sx1)}px`;
  div.style.height = `${Math.abs(sy2 - sy1)}px`;
  ui.overlay.appendChild(div);
}

// --------------------------------------------------------------------------
// Kéo khung chữ ký
// --------------------------------------------------------------------------

function enablePlacing(on) {
  state.placing = on;
  ui.overlay.classList.toggle("placing", on);
  ui.btnPlace.classList.toggle("active", on);
}

ui.overlay.addEventListener("pointerdown", (event) => {
  if (!state.placing) return;
  const rect = ui.overlay.getBoundingClientRect();
  const start = { x: event.clientX - rect.left, y: event.clientY - rect.top };

  const preview = document.createElement("div");
  preview.className = "sig-box";
  ui.overlay.replaceChildren(preview);

  const move = (e) => {
    const x = Math.max(0, Math.min(rect.width, e.clientX - rect.left));
    const y = Math.max(0, Math.min(rect.height, e.clientY - rect.top));
    preview.style.left = `${Math.min(start.x, x)}px`;
    preview.style.top = `${Math.min(start.y, y)}px`;
    preview.style.width = `${Math.abs(x - start.x)}px`;
    preview.style.height = `${Math.abs(y - start.y)}px`;
  };

  const up = (e) => {
    ui.overlay.removeEventListener("pointermove", move);
    ui.overlay.removeEventListener("pointerup", up);
    const endX = Math.max(0, Math.min(rect.width, e.clientX - rect.left));
    const endY = Math.max(0, Math.min(rect.height, e.clientY - rect.top));

    if (Math.abs(endX - start.x) < 30 || Math.abs(endY - start.y) < 15) {
      setStatus(ui.boxInfo, "Khung quá nhỏ, hãy kéo lại.", "err");
      drawExistingBox();
      return;
    }

    // Màn hình -> toạ độ PDF (gốc dưới-trái)
    const [px1, py1] = state.viewport.convertToPdfPoint(
      Math.min(start.x, endX),
      Math.max(start.y, endY),
    );
    const [px2, py2] = state.viewport.convertToPdfPoint(
      Math.max(start.x, endX),
      Math.min(start.y, endY),
    );
    state.box = {
      page: state.pageNum - 1,
      rect: [px1, py1, px2, py2].map((v) => Math.round(v)),
    };
    enablePlacing(false);
    updateBoxInfo();
    drawExistingBox();
  };

  ui.overlay.addEventListener("pointermove", move);
  ui.overlay.addEventListener("pointerup", up);
});

function updateBoxInfo() {
  if (!state.canSign) {
    setStatus(ui.boxInfo, "Tài liệu này hiện không nhận chữ ký của bạn.", "muted");
  } else if (!state.box) {
    setStatus(
      ui.boxInfo,
      "Chưa chọn vị trí. Bấm “Đặt chữ ký” rồi kéo một khung trên trang.",
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

async function connectAgent() {
  const code = ui.agentCode.value.trim();
  if (!code) return setStatus(ui.agentStatus, "Nhập mã ghép cặp.", "err");

  setStatus(ui.agentStatus, "Đang hỏi agent…", "busy");
  try {
    const data = await api(`/api/agents/${code}/certificates`);
    setStatus(ui.agentStatus, `Đã kết nối: ${data.agent} (${data.platform})`, "ok");
    renderCertificates(data.certificates);
  } catch (error) {
    setStatus(ui.agentStatus, error.message, "err");
    ui.certList.replaceChildren();
  }
}

function renderCertificates(certs) {
  state.certId = null;
  if (!certs.length) {
    ui.certList.innerHTML = '<p class="hint">Token không có chứng thư nào.</p>';
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
        [...ui.certList.children].forEach((c) =>
          c.classList.toggle("selected", c === div),
        );
        updateBoxInfo();
      };
      return div;
    }),
  );
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
  } catch (error) {
    setStatus(ui.signersStatus, error.message, "err");
  }
}

// --------------------------------------------------------------------------
// Ký
// --------------------------------------------------------------------------

async function sign() {
  ui.btnSign.disabled = true;
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
        agent_code: ui.agentCode.value.trim(),
        cert_id: state.certId,
        page: state.box.page,
        box: state.box.rect,
        reason: ui.reason.value.trim(),
        location: ui.location.value.trim(),
      }),
    });
    setStatus(ui.signStatus, "Đã ký xong.", "ok");
    state.box = null;
    await openDocument(state.doc.id);
    await runVerify();
  } catch (error) {
    setStatus(ui.signStatus, error.message, "err");
  } finally {
    updateBoxInfo();
  }
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
          report.reason,
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
    state.pageNum = 1;
    await openDocument(doc.id);
  };
  $("btn-add-signer").onclick = () => ui.signersRows.appendChild(signerRow());
  $("btn-save-signers").onclick = saveSigners;
} else {
  // Bỏ sidebar thì lưới phải còn 2 cột, nếu không viewer bị ép vào cột 210px
  // và canvas tràn ra ngoài màn hình.
  document.body.classList.add("signer-mode");
  for (const el of document.querySelectorAll("[data-owner-only]")) el.remove();
}

$("prev-page").onclick = async () => {
  if (state.pageNum > 1) {
    state.pageNum--;
    await renderPage();
  }
};
$("next-page").onclick = async () => {
  if (state.pdf && state.pageNum < state.pdf.numPages) {
    state.pageNum++;
    await renderPage();
  }
};

ui.btnPlace.onclick = () => enablePlacing(!state.placing);
ui.btnConnect.onclick = connectAgent;
ui.btnSign.onclick = sign;
ui.btnVerify.onclick = runVerify;
ui.agentCode.addEventListener("keydown", (e) => {
  if (e.key === "Enter") connectAgent();
});

api("/api/session").then((s) => {
  setStatus(
    ui.profileHint,
    `Hồ sơ chữ ký: ${s.profile}${s.timestamping ? " (có dấu thời gian TSA)" : ""}`,
    "muted",
  );
});

if (SIGNER_MODE) {
  openDocument(null).catch((error) => {
    ui.emptyState.textContent = error.message;
  });
} else {
  refreshDocList();
}
