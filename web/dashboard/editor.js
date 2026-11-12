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
  state,
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
  let isDirty = false;
  const recipientErrors = new Map(); // idx -> { name?, email?, field? }

  let recipients = (doc.recipients || []).map((r, i) => ({
    id: r.id,
    name: r.name || "",
    email: r.email || "",
    tax_code: r.tax_code || "",
    role: r.role || "signer",
    method: r.method || "digital",
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
  const MIN_SCALE = 0.4;
  const MAX_SCALE = 2.5;

  function markDirty() {
    if (!isDirty) {
      isDirty = true;
      updateSaveButton();
    }
  }

  function updateSaveButton() {
    if (isDirty) {
      saveDraftBtn.disabled = false;
      saveDraftBtn.textContent = "Lưu nháp";
    } else {
      saveDraftBtn.disabled = true;
      saveDraftBtn.textContent = "Đã lưu";
    }
  }

  // Unsaved changes guards
  state.navigationGuard = () => {
    if (!isDirty) return true;
    return window.confirm("Bạn có thay đổi chưa lưu trên bản nháp này. Bạn có chắc chắn muốn rời đi?");
  };

  function onBeforeUnload(e) {
    if (isDirty) {
      e.preventDefault();
      e.returnValue = "";
    }
  }
  window.addEventListener("beforeunload", onBeforeUnload);

  function cleanup() {
    isDirty = false;
    state.navigationGuard = null;
    window.removeEventListener("beforeunload", onBeforeUnload);
    window.removeEventListener("keydown", onKeyDownEsc);
    visibilityObserver.disconnect();
  }

  // Header thanh công cụ
  const backLink = el("a", { href: "#/documents", className: "button" }, "Danh sách");
  const docTitleSpan = el("span", { className: "editor-header-title" }, doc.title || doc.filename);
  const draftBadge = el("span", { className: "badge badge-draft" }, "Bản nháp");

  const saveDraftBtn = el(
    "button",
    {
      type: "button",
      className: "button",
      disabled: true,
      onClick: () => saveDraft(false),
    },
    "Đã lưu"
  );

  const deleteDraftBtn = el(
    "button",
    {
      type: "button",
      className: "button danger",
      onClick: () => {
        confirmModal({
          title: "Xoá bản nháp",
          message: "Bản nháp này sẽ bị xoá vĩnh viễn và không thể khôi phục.",
          confirmText: "Xoá bản nháp",
          danger: true,
          onConfirm: async () => {
            try {
              await api(`/v1/documents/${doc.id}`, { method: "DELETE" });
              cleanup();
              toast("Đã xoá bản nháp.", "ok");
              location.hash = "#/documents";
            } catch (err) {
              toast(`Không thể xoá: ${err.message}`, "err");
            }
          },
        });
      },
    },
    "Xoá bản nháp"
  );

  const sendDocBtn = el(
    "button",
    {
      type: "button",
      className: "button primary",
      onClick: sendDocument,
    },
    "Gửi tài liệu"
  );

  const topBar = el(
    "div",
    { className: "editor-topbar" },
    el("div", { className: "editor-topbar-left" }, backLink, docTitleSpan, draftBadge),
    el(
      "div",
      { className: "editor-topbar-right" },
      saveDraftBtn,
      deleteDraftBtn,
      sendDocBtn
    )
  );

  // PDF Viewer controls
  const btnPlaceBox = el(
    "button",
    {
      type: "button",
      className: "button",
      disabled: recipients.length === 0,
      onClick: togglePlacingMode,
    },
    "Đặt ô ký"
  );

  const toolbarPlaceHint = el("span", { className: "toolbar-hint muted" });

  const boxSizeSelect = el(
    "select",
    {
      className: "select-box-size",
      "aria-label": "Kích thước ô ký",
      onChange: (e) => {
        currentBoxSizeKey = e.target.value;
      },
    },
    el("option", { value: "nho" }, "Nhỏ (140×76 pt)"),
    el("option", { value: "chuan", selected: true }, "Chuẩn (165×90 pt)"),
    el("option", { value: "lon" }, "Lớn (190×104 pt)"),
    el("option", { value: "rat_lon" }, "Rất lớn (220×120 pt)")
  );

  const zoomOutBtn = el("button", { type: "button", className: "button", "aria-label": "Thu nhỏ", onClick: () => setScale(scale - 0.15) }, "−");
  const zoomLevelLabel = el("span", { className: "zoom-label", "aria-live": "polite" }, "100%");
  const zoomInBtn = el("button", { type: "button", className: "button", "aria-label": "Phóng to", onClick: () => setScale(scale + 0.15) }, "+");
  const zoomFitBtn = el("button", { type: "button", className: "button", onClick: fitToWidth }, "Vừa khung");

  const pageInfoSpan = el("span", { className: "page-info muted" }, "Đang tải trang…");

  const viewerToolbar = el(
    "div",
    { className: "viewer-bar" },
    btnPlaceBox,
    toolbarPlaceHint,
    boxSizeSelect,
    el("span", { className: "bar-gap" }),
    el("div", { className: "zoom-controls" }, zoomOutBtn, zoomLevelLabel, zoomInBtn, zoomFitBtn),
    pageInfoSpan
  );

  const pagesContainer = el("div", { className: "pages", id: "editor-pages" });
  const placeHintBanner = el(
    "div",
    { className: "place-hint", hidden: true },
    "Nhấp chuột vào vị trí trên trang để đặt ô ký. Kéo để chỉnh vị trí. Nhấn Esc để huỷ."
  );

  const viewerSection = el(
    "section",
    { className: "viewer" },
    viewerToolbar,
    pagesContainer,
    placeHintBanner
  );

  // Sidebar: Form thông tin & Người nhận
  const titleInput = el("input", {
    id: "doc-title-input",
    type: "text",
    value: doc.title || "",
    onInput: markDirty,
  });
  const messageInput = el("textarea", {
    id: "doc-message-input",
    rows: 2,
    onInput: markDirty,
  }, doc.message || "");
  const externalRefInput = el("input", {
    id: "doc-ref-input",
    type: "text",
    value: doc.external_ref || "",
    onInput: markDirty,
  });

  let expiryFormatted = "";
  if (doc.expires_at) {
    try {
      const dt = new Date(doc.expires_at);
      expiryFormatted = new Date(dt.getTime() - dt.getTimezoneOffset() * 60000)
        .toISOString()
        .slice(0, 16);
    } catch {}
  }
  const expiresAtInput = el("input", {
    id: "doc-expiry-input",
    type: "datetime-local",
    value: expiryFormatted,
    onInput: markDirty,
  });

  const docInfoForm = el(
    "div",
    { className: "card editor-card" },
    el("h4", { className: "editor-section-title" }, "Thông tin tài liệu"),
    el("div", { className: "form-group" }, el("label", { htmlFor: "doc-title-input" }, "Tiêu đề tài liệu"), titleInput),
    el("div", { className: "form-group" }, el("label", { htmlFor: "doc-ref-input" }, "Mã hồ sơ (không bắt buộc)"), externalRefInput),
    el("div", { className: "form-group" }, el("label", { htmlFor: "doc-expiry-input" }, "Thời hạn ký"), expiresAtInput),
    el("div", { className: "form-group" }, el("label", { htmlFor: "doc-message-input" }, "Lời nhắn"), messageInput)
  );

  const recipientsListContainer = el("div", { className: "recipients-list" });
  const addRecipientBtn = el(
    "button",
    {
      type: "button",
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
          method: "digital",
          order: nextOrder,
          field: null,
        });
        selectedRecipientIndex = recipients.length - 1;
        markDirty();
        renderRecipientsList();
        drawAllBoxes();
      },
    },
    "Thêm người nhận"
  );

  const recipientsSection = el(
    "div",
    { className: "card editor-card", style: { marginTop: "16px" } },
    el("h4", { className: "editor-section-title" }, "Danh sách người nhận"),
    el(
      "p",
      { className: "hint" },
      "Cùng số thứ tự thì ký cùng lúc; số nhỏ ký trước."
    ),
    recipientsListContainer,
    addRecipientBtn
  );

  const sidePanel = el("aside", { className: "editor-sidebar" }, docInfoForm, recipientsSection);
  const mainLayout = el("div", { className: "editor-layout" }, viewerSection, sidePanel);

  container.append(topBar, mainLayout);

  function updateToolbarPlaceBtn() {
    const currentRec = recipients[selectedRecipientIndex];
    const canPlace = Boolean(currentRec && currentRec.role === "signer");
    btnPlaceBox.disabled = !canPlace;

    if (recipients.length === 0) {
      btnPlaceBox.title = "Thêm người nhận để đặt ô ký";
      toolbarPlaceHint.textContent = "Thêm người nhận để đặt ô ký";
    } else if (!currentRec || currentRec.role !== "signer") {
      btnPlaceBox.title = "Chọn người ký để đặt ô ký";
      toolbarPlaceHint.textContent = "Chọn người ký để đặt ô ký";
    } else {
      btnPlaceBox.title = `Đặt ô ký cho ${currentRec.name || "người ký đang chọn"}`;
      toolbarPlaceHint.textContent = "";
    }
  }

  // Lưu bản nháp (thông tin + người nhận cùng lúc)
  async function saveDraft(silent = false) {
    saveDraftBtn.disabled = true;
    saveDraftBtn.textContent = "Đang lưu…";

    try {
      // 1. Lưu thông tin tài liệu (PATCH)
      const patchData = {
        title: titleInput.value.trim() || doc.filename,
        message: messageInput.value.trim() || null,
        external_ref: externalRefInput.value.trim() || null,
        expires_at: expiresAtInput.value ? new Date(expiresAtInput.value).toISOString() : null,
      };
      const resDoc = await api(`/v1/documents/${doc.id}`, {
        method: "PATCH",
        body: patchData,
      });
      doc = resDoc;
      docTitleSpan.textContent = doc.title || doc.filename;

      // 2. Lưu danh sách người nhận (PUT)
      const payload = recipients.map((r) => ({
        name: r.name.trim(),
        email: r.email.trim() || null,
        tax_code: r.tax_code.trim() || null,
        role: r.role,
        method: r.role === "signer" ? (r.method || "digital") : "digital",
        order: Number(r.order) || 1,
        field: r.role === "signer" && r.field ? r.field : null,
      }));

      const resRecipients = await api(`/v1/documents/${doc.id}/recipients`, {
        method: "PUT",
        body: payload,
      });
      doc = resRecipients;
      recipients = (doc.recipients || []).map((r, i) => ({
        id: r.id,
        name: r.name || "",
        email: r.email || "",
        tax_code: r.tax_code || "",
        role: r.role || "signer",
        method: r.method || "digital",
        order: r.order || i + 1,
        field: r.field || null,
      }));

      isDirty = false;
      updateSaveButton();
      renderRecipientsList();
      drawAllBoxes();

      if (!silent) {
        toast("Đã lưu bản nháp.", "ok");
      }
      return true;
    } catch (err) {
      toast(`Lỗi khi lưu bản nháp: ${err.message}`, "err");
      updateSaveButton();
      return false;
    }
  }

  // Gửi tài liệu (POST /send) với xác thực đầu vào chi tiết
  async function sendDocument() {
    // 1. Kiểm tra tối thiểu
    if (recipients.length === 0) {
      toast("Vui lòng thêm ít nhất một người ký trước khi gửi.", "err");
      return;
    }
    const hasSigner = recipients.some((r) => r.role === "signer");
    if (!hasSigner) {
      toast("Tài liệu cần có ít nhất một người ký.", "err");
      return;
    }

    // 2. Xác thực từng người nhận và gắn lỗi inline
    recipientErrors.clear();
    let firstErrorIdx = -1;
    let firstErrorField = null;

    recipients.forEach((r, idx) => {
      const errs = {};
      if (!r.name.trim()) {
        errs.name = "Vui lòng nhập họ và tên";
      }
      if (!r.email.trim()) {
        errs.email = "Vui lòng nhập email";
      } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r.email.trim())) {
        errs.email = "Email không đúng định dạng";
      }
      if (r.role === "signer" && !r.field) {
        errs.field = "Cần đặt ô ký trên tài liệu cho người ký này";
      }

      if (Object.keys(errs).length > 0) {
        recipientErrors.set(idx, errs);
        if (firstErrorIdx === -1) {
          firstErrorIdx = idx;
          firstErrorField = Object.keys(errs)[0];
        }
      }
    });

    if (recipientErrors.size > 0) {
      selectedRecipientIndex = firstErrorIdx;
      renderRecipientsList();
      toast("Vui lòng kiểm tra lại thông tin người nhận trước khi gửi.", "err");

      // Tập trung vào lỗi đầu tiên
      requestAnimationFrame(() => {
        const targetCard = recipientsListContainer.querySelector(
          `.recipient-edit-card[data-index="${firstErrorIdx}"]`
        );
        if (targetCard) {
          targetCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
          const focusInput =
            firstErrorField === "field"
              ? targetCard.querySelector(".btn-place-field")
              : targetCard.querySelector(`#rec-${firstErrorField}-${firstErrorIdx}`);
          if (focusInput) focusInput.focus();
        }
      });
      return;
    }

    // 3. Hộp thoại xác nhận trước khi gửi
    confirmModal({
      title: "Gửi tài liệu ký",
      message:
        "Tài liệu sau khi gửi sẽ không thể sửa đổi danh sách người nhận hay vị trí ô ký. Bạn có muốn gửi ngay?",
      confirmText: "Gửi tài liệu",
      onConfirm: async () => {
        sendDocBtn.disabled = true;
        sendDocBtn.textContent = "Đang gửi…";

        // Tự động lưu bản nháp ngầm (không thông báo trùng lặp)
        const saved = await saveDraft(true);
        if (!saved) {
          sendDocBtn.disabled = false;
          sendDocBtn.textContent = "Gửi tài liệu";
          return;
        }

        try {
          await api(`/v1/documents/${doc.id}/send`, { method: "POST" });
          cleanup();
          toast(`Đã gửi tài liệu cho ${recipients.length} người nhận.`, "ok");
          const { renderSentDoc } = await import("./viewer.js");
          renderSentDoc(container, doc.id);
        } catch (err) {
          toast(`Không thể gửi tài liệu: ${err.message}`, "err");
          sendDocBtn.disabled = false;
          sendDocBtn.textContent = "Gửi tài liệu";
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
      const errs = recipientErrors.get(idx) || {};

      const nameId = `rec-name-${idx}`;
      const emailId = `rec-email-${idx}`;
      const taxId = `rec-tax-${idx}`;
      const roleId = `rec-role-${idx}`;
      const methodId = `rec-method-${idx}`;
      const orderId = `rec-order-${idx}`;

      const nameInput = el("input", {
        id: nameId,
        type: "text",
        placeholder: "Nguyễn Văn A",
        value: rec.name,
        className: errs.name ? "input-error" : "",
        onInput: (e) => {
          rec.name = e.target.value;
          if (errs.name && rec.name.trim()) {
            delete errs.name;
            if (Object.keys(errs).length === 0) recipientErrors.delete(idx);
          }
          markDirty();
          drawAllBoxes();
        },
      });

      const emailInput = el("input", {
        id: emailId,
        type: "email",
        placeholder: "nguyenvana@example.com",
        value: rec.email,
        className: errs.email ? "input-error" : "",
        onInput: (e) => {
          rec.email = e.target.value;
          if (errs.email && rec.email.trim()) {
            delete errs.email;
            if (Object.keys(errs).length === 0) recipientErrors.delete(idx);
          }
          markDirty();
        },
      });

      const taxInput = el("input", {
        id: taxId,
        type: "text",
        placeholder: "0101234567",
        value: rec.tax_code,
        onInput: (e) => {
          rec.tax_code = e.target.value;
          markDirty();
        },
      });

      const roleSelect = el(
        "select",
        {
          id: roleId,
          onChange: (e) => {
            rec.role = e.target.value;
            if (rec.role === "approver") {
              rec.field = null;
              rec.method = "digital";
              if (errs.field) delete errs.field;
            }
            markDirty();
            renderRecipientsList();
            drawAllBoxes();
            updateToolbarPlaceBtn();
          },
        },
        el("option", { value: "signer", selected: rec.role === "signer" }, "Người ký"),
        el("option", { value: "approver", selected: rec.role === "approver" }, "Người duyệt")
      );

      const methodSelect = el(
        "select",
        {
          id: methodId,
          onChange: (e) => {
            rec.method = e.target.value;
            markDirty();
          },
        },
        el("option", { value: "digital", selected: (rec.method || "digital") === "digital" }, "Ký số (USB token)"),
        el("option", { value: "handwritten", selected: rec.method === "handwritten" }, "Ký tay")
      );

      const orderInput = el("input", {
        id: orderId,
        type: "number",
        min: "1",
        max: "100",
        value: String(rec.order || idx + 1),
        className: "recipient-order-input",
        "aria-label": "Thứ tự ký",
        onInput: (e) => {
          rec.order = parseInt(e.target.value, 10) || 1;
          markDirty();
        },
      });

      const delBtn = el(
        "button",
        {
          type: "button",
          className: "btn-icon-del",
          title: "Xoá người nhận này",
          "aria-label": "Xoá người nhận này",
          onClick: (e) => {
            e.stopPropagation();
            recipients.splice(idx, 1);
            recipientErrors.delete(idx);
            if (selectedRecipientIndex >= recipients.length) {
              selectedRecipientIndex = Math.max(0, recipients.length - 1);
            }
            markDirty();
            renderRecipientsList();
            drawAllBoxes();
            updateToolbarPlaceBtn();
          },
        }
      );
      delBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 1l12 12M13 1L1 13"/></svg>`;

      // Thông tin ô ký (nếu là signer)
      const fieldInfoRow = el("div", { className: "recipient-field-info" });
      if (rec.role === "signer") {
        if (rec.field) {
          fieldInfoRow.append(
            el(
              "span",
              {
                className: "badge badge-field",
                style: { background: color.bg, color: color.text, borderColor: color.border },
              },
              `Ô ký (trang ${rec.field.page + 1})`
            ),
            el(
              "button",
              {
                type: "button",
                className: "button small btn-clear-field",
                onClick: (e) => {
                  e.stopPropagation();
                  rec.field = null;
                  markDirty();
                  renderRecipientsList();
                  drawAllBoxes();
                  updateToolbarPlaceBtn();
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
              className: "button small btn-place-field",
              style: { borderColor: color.border, color: color.text },
              onClick: (e) => {
                e.stopPropagation();
                selectedRecipientIndex = idx;
                renderRecipientsList();
                updateToolbarPlaceBtn();
                enablePlacing(true);
              },
            },
            "Đặt ô ký"
          );
          fieldInfoRow.appendChild(btnSetField);
        }
      } else {
        fieldInfoRow.appendChild(
          el("span", { className: "muted form-help" }, "Người duyệt duyệt nội dung, không cần đặt ô ký")
        );
      }

      const card = el(
        "div",
        {
          className: `recipient-edit-card ${isSelected ? "selected" : ""}`,
          dataset: { index: String(idx) },
          style: { borderLeftColor: color.border },
          onClick: () => {
            if (selectedRecipientIndex !== idx) {
              selectedRecipientIndex = idx;
              renderRecipientsList();
              updateToolbarPlaceBtn();
            }
          },
        },
        el(
          "div",
          { className: "recipient-row-header" },
          el(
            "div",
            { className: "recipient-order-box" },
            el("label", { className: "compact-label", htmlFor: orderId }, "Thứ tự ký"),
            orderInput
          ),
          delBtn
        ),
        el(
          "div",
          { className: "form-group compact" },
          el("label", { className: "compact-label", htmlFor: nameId }, "Họ và tên"),
          nameInput,
          errs.name ? el("div", { className: "form-error compact-error" }, errs.name) : null
        ),
        el(
          "div",
          { className: "form-row-2" },
          el(
            "div",
            { className: "form-group compact" },
            el("label", { className: "compact-label", htmlFor: emailId }, "Email"),
            emailInput,
            errs.email ? el("div", { className: "form-error compact-error" }, errs.email) : null
          ),
          el(
            "div",
            { className: "form-group compact" },
            el("label", { className: "compact-label", htmlFor: taxId }, "Mã số thuế (không bắt buộc)"),
            taxInput,
            el("div", { className: "form-help" }, "Khớp với MST trên USB token")
          )
        ),
        el(
          "div",
          { className: "form-row-2" },
          el(
            "div",
            { className: "form-group compact" },
            el("label", { className: "compact-label", htmlFor: roleId }, "Vai trò"),
            roleSelect
          ),
          rec.role === "signer"
            ? el(
                "div",
                { className: "form-group compact" },
                el("label", { className: "compact-label", htmlFor: methodId }, "Hình thức ký"),
                methodSelect
              )
            : el("div")
        ),
        el(
          "div",
          { className: "recipient-field-row" },
          fieldInfoRow,
          errs.field ? el("div", { className: "form-error compact-error" }, errs.field) : null
        )
      );

      recipientsListContainer.appendChild(card);
    });

    updateToolbarPlaceBtn();
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
    btnPlaceBox.textContent = placingMode ? "Huỷ đặt" : "Đặt ô ký";

    for (const item of pages) {
      item.overlay.classList.toggle("placing", placingMode);
    }
  }

  // Phím Esc để huỷ đặt ô ký
  function onKeyDownEsc(e) {
    if (e.key === "Escape" && placingMode) {
      enablePlacing(false);
    }
  }
  window.addEventListener("keydown", onKeyDownEsc);

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
      // Màn hẹp: trang rộng hơn khung thì co vừa bề ngang ngay từ đầu
      if (pages[0] && pages[0].holder.offsetWidth > pagesContainer.clientWidth - 48) fitToWidth();
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
      const errs = recipientErrors.get(selectedRecipientIndex);
      if (errs && errs.field) {
        delete errs.field;
        if (Object.keys(errs).length === 0) recipientErrors.delete(selectedRecipientIndex);
      }
      enablePlacing(false);
      markDirty();
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
        el("span", { className: "sig-box-kind" }, "Ô ký"),
        el("strong", { className: "sig-box-name" }, rec.name || `Người ký #${idx + 1}`)
      );

      const cornerHandle = el("div", { className: "sig-corner-handle", "aria-hidden": "true" });

      const delBtn = el(
        "button",
        {
          type: "button",
          className: "sig-box-del",
          title: "Xoá ô ký",
          "aria-label": "Xoá ô ký",
          onClick: (e) => {
            e.stopPropagation();
            rec.field = null;
            markDirty();
            renderRecipientsList();
            drawAllBoxes();
            updateToolbarPlaceBtn();
          },
        }
      );
      delBtn.innerHTML = `<svg width="10" height="10" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M1 1l12 12M13 1L1 13"/></svg>`;

      div.append(label, cornerHandle, delBtn);
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
        markDirty();
        renderRecipientsList();
      };

      div.addEventListener("pointermove", onPointerMove);
      div.addEventListener("pointerup", onPointerUp);
    });
  }

  renderRecipientsList();
  loadPdf();
}
