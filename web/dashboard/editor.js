/**
 * Trình chỉnh sửa bản nháp tài liệu (#/documents/<id> khi doc.status === 'draft')
 * Bao gồm: sửa thông tin, quản lý người nhận, xem PDF và đặt ô ký trực quan.
 */

import * as pdfjs from "/vendor/pdfjs/pdf.min.mjs";
import {
  api,
  BOX_SIZES,
  confirmModal,
  el,
  RECIPIENT_COLORS,
  ROLE_LABELS,
  toast,
} from "./api.js";

pdfjs.GlobalWorkerOptions.workerSrc = "/vendor/pdfjs/pdf.worker.min.mjs";

export async function renderDraftEditor(container, docId) {
  container.replaceChildren();

  const loadingMsg = el("div", { className: "loading-state" }, "Đang tải tài liệu…");
  container.appendChild(loadingMsg);

  let doc = null;
  try {
    doc = await api(`/v1/documents/${docId}`);
  } catch (err) {
    container.replaceChildren(
      el("div", { className: "error-state" }, `Không thể tải tài liệu: ${err.message}`)
    );
    return;
  }

  // Nếu tài liệu không còn là nháp, chuyển sang xem chi tiết
  if (doc.status !== "draft") {
    const { renderSentDoc } = await import("./viewer.js");
    return renderSentDoc(container, docId);
  }

  container.replaceChildren();

  // State cục bộ cho editor
  let recipients = (doc.recipients || []).map((r, i) => ({
    id: r.id,
    name: r.name || "",
    email: r.email || "",
    tax_code: r.tax_code || "",
    role: r.role || "signer",
    order: r.order || i + 1,
    field: r.field || null, // { page: 0, box: [x1, y1, x2, y2] }
  }));

  let selectedRecipientIndex = recipients.findIndex((r) => r.role === "signer");
  if (selectedRecipientIndex === -1 && recipients.length > 0) selectedRecipientIndex = 0;

  let currentBoxSizeKey = "chuan";
  let placingMode = false;
  let pdfDoc = null;
  let pages = [];
  let scale = 1.0;
  const MIN_SCALE = 0.5;
  const MAX_SCALE = 2.5;

  // Header thanh công cụ
  const backLink = el("a", { href: "#/documents", className: "button" }, "← Danh sách");
  const docTitleSpan = el("span", { className: "editor-header-title" }, doc.title || doc.filename);
  const draftBadge = el("span", { className: "badge badge-draft" }, "Bản nháp");

  const saveDetailsBtn = el(
    "button",
    {
      className: "button",
      onClick: saveDocDetails,
    },
    "Lưu thông tin"
  );

  const saveRecipientsBtn = el(
    "button",
    {
      className: "button",
      onClick: saveRecipients,
    },
    "Lưu người nhận"
  );

  const deleteDraftBtn = el(
    "button",
    {
      className: "button danger",
      onClick: () => {
        confirmModal({
          title: "Xoá bản nháp",
          message: "Bạn có chắc chắn muốn xoá vĩnh viễn bản nháp này không?",
          confirmText: "Xoá tài liệu",
          danger: true,
          onConfirm: async () => {
            try {
              await api(`/v1/documents/${doc.id}`, { method: "DELETE" });
              toast("Đã xoá bản nháp.", "ok");
              location.hash = "#/documents";
            } catch (err) {
              toast(`Không thể xoá: ${err.message}`, "err");
            }
          },
        });
      },
    },
    "Xoá nháp"
  );

  const sendDocBtn = el(
    "button",
    {
      className: "button primary",
      onClick: sendDocument,
    },
    "Gửi tài liệu ▶"
  );

  const topBar = el(
    "div",
    { className: "editor-topbar" },
    el("div", { className: "editor-topbar-left" }, backLink, docTitleSpan, draftBadge),
    el(
      "div",
      { className: "editor-topbar-right" },
      saveDetailsBtn,
      saveRecipientsBtn,
      deleteDraftBtn,
      sendDocBtn
    )
  );

  // PDF Viewer controls
  const btnPlaceBox = el(
    "button",
    {
      className: "button",
      disabled: recipients.length === 0,
      onClick: togglePlacingMode,
    },
    "✎ Đặt ô ký"
  );

  const boxSizeSelect = el(
    "select",
    {
      className: "select-box-size",
      onChange: (e) => {
        currentBoxSizeKey = e.target.value;
      },
    },
    el("option", { value: "nho" }, "Nhỏ (140×76 pt)"),
    el("option", { value: "chuan", selected: true }, "Chuẩn (165×90 pt)"),
    el("option", { value: "lon" }, "Lớn (190×104 pt)"),
    el("option", { value: "rat_lon" }, "Rất lớn (220×120 pt)")
  );

  const zoomOutBtn = el("button", { className: "button", onClick: () => setScale(scale - 0.15) }, "−");
  const zoomLevelLabel = el("span", { className: "zoom-label" }, "100%");
  const zoomInBtn = el("button", { className: "button", onClick: () => setScale(scale + 0.15) }, "+");
  const zoomFitBtn = el("button", { className: "button", onClick: fitToWidth }, "Vừa khung");

  const pageInfoSpan = el("span", { className: "page-info muted" }, "Đang tải trang…");

  const viewerToolbar = el(
    "div",
    { className: "viewer-bar" },
    btnPlaceBox,
    boxSizeSelect,
    el("span", { className: "bar-gap" }),
    el("div", { className: "zoom-controls" }, zoomOutBtn, zoomLevelLabel, zoomInBtn, zoomFitBtn),
    pageInfoSpan
  );

  const pagesContainer = el("div", { className: "pages", id: "editor-pages" });
  const placeHintBanner = el(
    "div",
    { className: "place-hint", hidden: true },
    "Nhấp chuột vào vị trí trên trang để đặt ô ký · kéo để chỉnh vị trí · Esc để huỷ"
  );

  const viewerSection = el(
    "section",
    { className: "viewer" },
    viewerToolbar,
    pagesContainer,
    placeHintBanner
  );

  // Sidebar: Form thông tin & Người nhận
  const titleInput = el("input", { type: "text", value: doc.title || "" });
  const messageInput = el("textarea", { rows: 2 }, doc.message || "");
  const externalRefInput = el("input", { type: "text", value: doc.external_ref || "" });

  let expiryFormatted = "";
  if (doc.expires_at) {
    try {
      const dt = new Date(doc.expires_at);
      expiryFormatted = new Date(dt.getTime() - dt.getTimezoneOffset() * 60000)
        .toISOString()
        .slice(0, 16);
    } catch {}
  }
  const expiresAtInput = el("input", { type: "datetime-local", value: expiryFormatted });

  const docInfoForm = el(
    "div",
    { className: "card editor-card" },
    el("h4", { className: "editor-section-title" }, "1. Thông tin tài liệu"),
    el("div", { className: "form-group" }, el("label", {}, "Tiêu đề tài liệu"), titleInput),
    el("div", { className: "form-group" }, el("label", {}, "Mã tham chiếu ngoài"), externalRefInput),
    el("div", { className: "form-group" }, el("label", {}, "Thời hạn ký"), expiresAtInput),
    el("div", { className: "form-group" }, el("label", {}, "Lời nhắn"), messageInput)
  );

  const recipientsListContainer = el("div", { className: "recipients-list" });
  const addRecipientBtn = el(
    "button",
    {
      className: "button",
      style: { width: "100%", marginTop: "12px" },
      onClick: () => {
        const nextOrder =
          recipients.length > 0 ? Math.max(...recipients.map((r) => r.order || 1)) + 1 : 1;
        recipients.push({
          name: "",
          email: "",
          tax_code: "",
          role: "signer",
          order: nextOrder,
          field: null,
        });
        selectedRecipientIndex = recipients.length - 1;
        renderRecipientsList();
        drawAllBoxes();
      },
    },
    "+ Thêm người nhận"
  );

  const recipientsSection = el(
    "div",
    { className: "card editor-card", style: { marginTop: "16px" } },
    el("h4", { className: "editor-section-title" }, "2. Danh sách người nhận"),
    el(
      "p",
      { className: "hint" },
      "Thứ tự: Các người nhận có cùng số thứ tự sẽ được ký song song. Số nhỏ hơn ký trước."
    ),
    recipientsListContainer,
    addRecipientBtn
  );

  const sidePanel = el("aside", { className: "editor-sidebar" }, docInfoForm, recipientsSection);
  const mainLayout = el("div", { className: "editor-layout" }, viewerSection, sidePanel);

  container.append(topBar, mainLayout);

  // Lưu thông tin tài liệu (PATCH)
  async function saveDocDetails() {
    saveDetailsBtn.disabled = true;
    try {
      const patchData = {
        title: titleInput.value.trim() || doc.filename,
        message: messageInput.value.trim() || null,
        external_ref: externalRefInput.value.trim() || null,
        expires_at: expiresAtInput.value ? new Date(expiresAtInput.value).toISOString() : null,
      };
      const res = await api(`/v1/documents/${doc.id}`, {
        method: "PATCH",
        body: patchData,
      });
      doc = res;
      docTitleSpan.textContent = doc.title || doc.filename;
      toast("Đã lưu thông tin tài liệu.", "ok");
    } catch (err) {
      toast(`Lỗi khi lưu thông tin: ${err.message}`, "err");
    } finally {
      saveDetailsBtn.disabled = false;
    }
  }

  // Lưu danh sách người nhận (PUT)
  async function saveRecipients() {
    saveRecipientsBtn.disabled = true;
    try {
      // Chuẩn hoá danh sách gửi lên
      const payload = recipients.map((r) => ({
        name: r.name.trim(),
        email: r.email.trim() || null,
        tax_code: r.tax_code.trim() || null,
        role: r.role,
        order: Number(r.order) || 1,
        field: r.role === "signer" && r.field ? r.field : null,
      }));

      const res = await api(`/v1/documents/${doc.id}/recipients`, {
        method: "PUT",
        body: payload,
      });
      doc = res;
      recipients = (doc.recipients || []).map((r, i) => ({
        id: r.id,
        name: r.name || "",
        email: r.email || "",
        tax_code: r.tax_code || "",
        role: r.role || "signer",
        order: r.order || i + 1,
        field: r.field || null,
      }));
      renderRecipientsList();
      drawAllBoxes();
      toast("Đã lưu danh sách người nhận.", "ok");
      return true;
    } catch (err) {
      toast(`Lỗi khi lưu người nhận: ${err.message}`, "err");
      return false;
    } finally {
      saveRecipientsBtn.disabled = false;
    }
  }

  // Gửi tài liệu (POST /send)
  async function sendDocument() {
    // Kiểm tra tính hợp lệ tối thiểu
    if (recipients.length === 0) {
      toast("Vui lòng thêm ít nhất một người ký trước khi gửi.", "err");
      return;
    }
    const hasSigner = recipients.some((r) => r.role === "signer");
    if (!hasSigner) {
      toast("Tài liệu cần có ít nhất một người ký (role: signer).", "err");
      return;
    }
    for (const r of recipients) {
      if (!r.name.trim()) {
        toast("Vui lòng nhập họ tên cho tất cả người nhận.", "err");
        return;
      }
    }

    confirmModal({
      title: "Gửi tài liệu ký",
      message:
        "Tài liệu sau khi gửi sẽ không thể sửa đổi danh sách người nhận hay vị trí ô ký. Bạn có muốn gửi ngay?",
      confirmText: "Gửi tài liệu",
      onConfirm: async () => {
        sendDocBtn.disabled = true;
        sendDocBtn.textContent = "Đang gửi…";

        // Tự động lưu thông tin và người nhận trước
        await saveDocDetails();
        const saved = await saveRecipients();
        if (!saved) {
          sendDocBtn.disabled = false;
          sendDocBtn.textContent = "Gửi tài liệu ▶";
          return;
        }

        try {
          const res = await api(`/v1/documents/${doc.id}/send`, { method: "POST" });
          toast("Tài liệu đã được gửi thành công!", "ok");
          const { renderSentDoc } = await import("./viewer.js");
          renderSentDoc(container, doc.id);
        } catch (err) {
          toast(`Không thể gửi tài liệu: ${err.message}`, "err");
          sendDocBtn.disabled = false;
          sendDocBtn.textContent = "Gửi tài liệu ▶";
        }
      },
    });
  }

  // Vẽ danh sách người nhận trong Sidebar
  function renderRecipientsList() {
    recipientsListContainer.replaceChildren();

    recipients.forEach((rec, idx) => {
      const color = RECIPIENT_COLORS[idx % RECIPIENT_COLORS.length];
      const isSelected = selectedRecipientIndex === idx;

      const nameInput = el("input", {
        type: "text",
        placeholder: "Họ và tên *",
        value: rec.name,
        style: { fontSize: "13px" },
        onInput: (e) => {
          rec.name = e.target.value;
          drawAllBoxes();
        },
      });

      const emailInput = el("input", {
        type: "email",
        placeholder: "Email người nhận",
        value: rec.email,
        style: { fontSize: "12px" },
        onInput: (e) => (rec.email = e.target.value),
      });

      const taxInput = el("input", {
        type: "text",
        placeholder: "MST (khớp chứng thư)",
        value: rec.tax_code,
        style: { fontSize: "12px" },
        onInput: (e) => (rec.tax_code = e.target.value),
      });

      const roleSelect = el(
        "select",
        {
          style: { fontSize: "12px" },
          onChange: (e) => {
            rec.role = e.target.value;
            if (rec.role === "approver") {
              rec.field = null;
            }
            renderRecipientsList();
            drawAllBoxes();
          },
        },
        el("option", { value: "signer", selected: rec.role === "signer" }, "Người ký"),
        el("option", { value: "approver", selected: rec.role === "approver" }, "Người duyệt")
      );

      const orderInput = el("input", {
        type: "number",
        min: "1",
        max: "100",
        value: String(rec.order || idx + 1),
        style: { width: "55px", fontSize: "12px" },
        onInput: (e) => (rec.order = parseInt(e.target.value, 10) || 1),
      });

      const delBtn = el(
        "button",
        {
          type: "button",
          className: "btn-icon-del",
          title: "Xoá người nhận",
          onClick: (e) => {
            e.stopPropagation();
            recipients.splice(idx, 1);
            if (selectedRecipientIndex >= recipients.length) {
              selectedRecipientIndex = Math.max(0, recipients.length - 1);
            }
            renderRecipientsList();
            drawAllBoxes();
          },
        },
        "✕"
      );

      // Thông tin ô ký (nếu là signer)
      const fieldInfoRow = el("div", { className: "recipient-field-info" });
      if (rec.role === "signer") {
        if (rec.field) {
          const [x1, y1, x2, y2] = rec.field.box;
          const w = Math.round(x2 - x1);
          const h = Math.round(y2 - y1);
          fieldInfoRow.append(
            el(
              "span",
              { className: "badge", style: { background: color.bg, color: color.text, border: `1px solid ${color.border}` } },
              `Trang ${rec.field.page + 1}: ${w}×${h}pt`
            ),
            el(
              "button",
              {
                type: "button",
                className: "btn-clear-field",
                onClick: (e) => {
                  e.stopPropagation();
                  rec.field = null;
                  renderRecipientsList();
                  drawAllBoxes();
                },
              },
              "Bỏ ô ký"
            )
          );
        } else {
          const btnSetField = el(
            "button",
            {
              type: "button",
              className: "button small",
              style: { borderColor: color.border, color: color.text },
              onClick: (e) => {
                e.stopPropagation();
                selectedRecipientIndex = idx;
                renderRecipientsList();
                enablePlacing(true);
              },
            },
            "✎ Đặt ô ký"
          );
          fieldInfoRow.appendChild(btnSetField);
        }
      } else {
        fieldInfoRow.appendChild(
          el("span", { className: "muted", style: { fontSize: "11px" } }, "Người duyệt không cần ô ký")
        );
      }

      const card = el(
        "div",
        {
          className: `recipient-edit-card ${isSelected ? "selected" : ""}`,
          style: { borderLeftColor: color.border },
          onClick: () => {
            if (selectedRecipientIndex !== idx) {
              selectedRecipientIndex = idx;
              renderRecipientsList();
            }
          },
        },
        el(
          "div",
          { className: "recipient-row-header" },
          el("span", { className: "recipient-num-tag", style: { background: color.bg, color: color.text } }, `#${idx + 1}`),
          el("div", { className: "recipient-order-box" }, el("span", { className: "muted" }, "Thứ tự:"), orderInput),
          delBtn
        ),
        el("div", { className: "form-group", style: { margin: "4px 0" } }, nameInput),
        el("div", { className: "form-row-2" }, emailInput, taxInput),
        el("div", { className: "form-row-2", style: { marginTop: "6px" } }, roleSelect, fieldInfoRow)
      );

      recipientsListContainer.appendChild(card);
    });

    btnPlaceBox.disabled = recipients.length === 0 || recipients[selectedRecipientIndex]?.role !== "signer";
  }

  // Bật/tắt chế độ đặt ô ký
  function togglePlacingMode() {
    enablePlacing(!placingMode);
  }

  function enablePlacing(on) {
    const currentRec = recipients[selectedRecipientIndex];
    if (on && (!currentRec || currentRec.role !== "signer")) {
      toast("Vui lòng chọn một người ký để đặt ô ký.", "err");
      return;
    }
    placingMode = on;
    placeHintBanner.hidden = !placingMode;
    btnPlaceBox.classList.toggle("active", placingMode);
    btnPlaceBox.textContent = placingMode ? "✕ Huỷ đặt" : "✎ Đặt ô ký";

    for (const item of pages) {
      item.overlay.classList.toggle("placing", placingMode);
    }
  }

  // Phím Esc để huỷ đặt ô ký
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && placingMode) {
      enablePlacing(false);
    }
  });

  // Khởi tạo PDF.js
  const visibilityObserver = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const item = pages[Number(entry.target.dataset.index)];
        if (entry.isIntersecting && item) renderPage(item);
      }
    },
    { root: pagesContainer, rootMargin: "400px 0px" }
  );

  async function loadPdf() {
    try {
      const url = `/v1/documents/${doc.id}/file?revision=${doc.revision || 0}`;
      pdfDoc = await pdfjs.getDocument({
        url,
        withCredentials: true,
        isEvalSupported: false,
      }).promise;

      await layoutPages();
      drawAllBoxes();
    } catch (err) {
      pagesContainer.replaceChildren(
        el("div", { className: "error-state" }, `Không thể tải tệp PDF: ${err.message}`)
      );
    }
  }

  async function layoutPages() {
    visibilityObserver.disconnect();
    pagesContainer.replaceChildren();
    pages = [];

    for (let num = 1; num <= pdfDoc.numPages; num++) {
      const page = await pdfDoc.getPage(num);
      const holder = el("div", { className: "page", dataset: { index: String(num - 1) } });
      const label = el("div", { className: "page-label" }, String(num));
      const canvas = el("canvas");
      const overlay = el("div", { className: "overlay" });

      holder.append(canvas, overlay, label);
      pagesContainer.appendChild(holder);

      const item = { num, page, holder, canvas, overlay, viewport: null, rendered: false };
      pages.push(item);
      sizePage(item);
      visibilityObserver.observe(holder);
    }

    updatePageInfo();
    updateZoomLabel();
  }

  function sizePage(item) {
    const viewport = item.page.getViewport({ scale });
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

  function setScale(newScale) {
    scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, newScale));
    for (const item of pages) {
      item.task?.cancel?.();
      sizePage(item);
    }
    for (const item of visiblePages()) renderPage(item);
    drawAllBoxes();
    updateZoomLabel();
  }

  function fitToWidth() {
    if (!pages[0]) return;
    const containerWidth = pagesContainer.clientWidth - 48;
    const originalWidth = pages[0].page.getViewport({ scale: 1.0 }).width;
    setScale(containerWidth / originalWidth);
  }

  function visiblePages() {
    const top = pagesContainer.scrollTop - 400;
    const bottom = top + pagesContainer.clientHeight + 800;
    return pages.filter((item) => {
      const elTop = item.holder.offsetTop;
      const elBottom = elTop + item.holder.offsetHeight;
      return elBottom >= top && elTop <= bottom;
    });
  }

  function updateZoomLabel() {
    zoomLevelLabel.textContent = `${Math.round(scale * 100)}%`;
  }

  function updatePageInfo() {
    pageInfoSpan.textContent = `Tổng ${pages.length} trang`;
  }

  // Toán học kẹp toạ độ ô ký trong trang
  function clampRect(item, x1, y1, width, height) {
    const [vx1, vy1, vx2, vy2] = item.page.view;
    const x = Math.min(Math.max(x1, vx1), Math.max(vx1, vx2 - width));
    const y = Math.min(Math.max(y1, vy1), Math.max(vy1, vy2 - height));
    return [x, y, x + width, y + height].map((v) => Math.round(v));
  }

  // Sự kiện nhấp để đặt ô ký
  pagesContainer.addEventListener("pointerdown", (event) => {
    if (!placingMode) return;
    const holder = event.target.closest?.(".page");
    if (!holder) return;
    const item = pages[Number(holder.dataset.index)];
    if (!item) return;

    event.preventDefault();
    const rect = item.overlay.getBoundingClientRect();
    const [px, py] = item.viewport.convertToPdfPoint(
      event.clientX - rect.left,
      event.clientY - rect.top
    );

    const [w, h] = BOX_SIZES[currentBoxSizeKey] || BOX_SIZES.chuan;
    const targetRec = recipients[selectedRecipientIndex];
    if (targetRec && targetRec.role === "signer") {
      targetRec.field = {
        page: item.num - 1,
        box: clampRect(item, px - w / 2, py - h / 2, w, h),
      };
      enablePlacing(false);
      renderRecipientsList();
      drawAllBoxes();
      toast(`Đã đặt ô ký cho ${targetRec.name || "người ký"}. Kéo để điều chỉnh.`, "ok");
    }
  });

  // Vẽ các ô ký trên các trang
  function drawAllBoxes() {
    for (const item of pages) {
      for (const node of item.overlay.querySelectorAll(".sig-box")) {
        node.remove();
      }
    }

    recipients.forEach((rec, idx) => {
      if (rec.role !== "signer" || !rec.field) return;
      const pageIndex = rec.field.page;
      const item = pages[pageIndex];
      if (!item) return;

      const color = RECIPIENT_COLORS[idx % RECIPIENT_COLORS.length];
      const [x1, y1, x2, y2] = rec.field.box;
      const [sx1, sy1] = item.viewport.convertToViewportPoint(x1, y2);
      const [sx2, sy2] = item.viewport.convertToViewportPoint(x2, y1);

      const width = Math.abs(sx2 - sx1);
      const height = Math.abs(sy2 - sy1);
      const left = Math.min(sx1, sx2);
      const top = Math.min(sy1, sy2);

      const div = el("div", {
        className: "sig-box",
        style: {
          left: `${left}px`,
          top: `${top}px`,
          width: `${width}px`,
          height: `${height}px`,
          borderColor: color.border,
          background: color.bg,
          color: color.text,
        },
      });

      const label = el(
        "div",
        { className: "sig-box-label", style: { color: color.text } },
        el("strong", {}, rec.name || `Người ký #${idx + 1}`),
        el("span", { className: "sig-box-sub" }, `${Math.round(x2 - x1)}×${Math.round(y2 - y1)} pt`)
      );

      const grip = el("div", { className: "sig-grip" }, "⠿ kéo");

      const delBtn = el(
        "button",
        {
          type: "button",
          className: "sig-box-del",
          title: "Xoá ô ký",
          onClick: (e) => {
            e.stopPropagation();
            rec.field = null;
            renderRecipientsList();
            drawAllBoxes();
          },
        },
        "✕"
      );

      div.append(label, grip, delBtn);
      attachBoxDrag(div, item, rec);
      item.overlay.appendChild(div);
    });
  }

  // Kéo ô ký trên trang
  function attachBoxDrag(div, item, recipient) {
    div.addEventListener("pointerdown", (event) => {
      if (placingMode) return;
      if (event.target.closest(".sig-box-del")) return;

      event.preventDefault();
      event.stopPropagation();
      div.setPointerCapture(event.pointerId);
      div.classList.add("dragging");

      const overlayRect = item.overlay.getBoundingClientRect();
      const startPt = item.viewport.convertToPdfPoint(
        event.clientX - overlayRect.left,
        event.clientY - overlayRect.top
      );
      const originBox = recipient.field.box.slice();
      const w = originBox[2] - originBox[0];
      const h = originBox[3] - originBox[1];

      const onPointerMove = (e) => {
        const nowPt = item.viewport.convertToPdfPoint(
          e.clientX - overlayRect.left,
          e.clientY - overlayRect.top
        );
        const newBox = clampRect(
          item,
          originBox[0] + (nowPt[0] - startPt[0]),
          originBox[1] + (nowPt[1] - startPt[1]),
          w,
          h
        );
        recipient.field.box = newBox;

        const [sx1, sy1] = item.viewport.convertToViewportPoint(newBox[0], newBox[3]);
        div.style.left = `${sx1}px`;
        div.style.top = `${sy1}px`;
      };

      const onPointerUp = () => {
        div.classList.remove("dragging");
        div.removeEventListener("pointermove", onPointerMove);
        div.removeEventListener("pointerup", onPointerUp);
        renderRecipientsList();
      };

      div.addEventListener("pointermove", onPointerMove);
      div.addEventListener("pointerup", onPointerUp);
    });
  }

  renderRecipientsList();
  loadPdf();
}
