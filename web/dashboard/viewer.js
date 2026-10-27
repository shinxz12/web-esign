/**
 * Màn hình xem chi tiết tài liệu đã gửi (in_progress, completed, declined, voided, expired).
 * Bao gồm: PDF viewer đọc, timeline người nhận, liên kết ký, xác thực chữ ký, nhật ký kiểm toán hash-chain.
 */

import * as pdfjs from "/vendor/pdfjs/pdf.min.mjs";
import {
  api,
  AUDIT_EVENT_LABELS,
  confirmModal,
  el,
  formatDate,
  promptModal,
  RECIPIENT_COLORS,
  ROLE_LABELS,
  showModal,
  state,
  STATUS_LABELS,
  toast,
} from "./api.js";

pdfjs.GlobalWorkerOptions.workerSrc = "/vendor/pdfjs/pdf.worker.min.mjs";

export async function renderSentDoc(container, docId) {
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

  // Nếu vẫn là draft, chuyển sang draft editor
  if (doc.status === "draft") {
    const { renderDraftEditor } = await import("./editor.js");
    return renderDraftEditor(container, docId);
  }

  container.replaceChildren();

  let activeTab = "recipients"; // "recipients" | "audit"
  let pdfDoc = null;
  let pages = [];
  let scale = 1.0;
  const MIN_SCALE = 0.5;
  const MAX_SCALE = 2.5;

  // Header thanh công cụ
  const backLink = el("a", { href: "#/documents", className: "button" }, "← Danh sách");
  const docTitleSpan = el("span", { className: "editor-header-title" }, doc.title || doc.filename);
  const statusBadge = el(
    "span",
    { className: `badge badge-${doc.status}` },
    STATUS_LABELS[doc.status] || doc.status
  );

  const downloadBtn = el(
    "a",
    {
      href: `/v1/documents/${doc.id}/file?download=true`,
      className: "button",
      target: "_blank",
      rel: "noopener",
    },
    "⤓ Tải PDF"
  );

  const verifyBtn = el(
    "button",
    {
      className: "button",
      onClick: verifySignatures,
    },
    "Xác thực chữ ký"
  );

  const actionsRight = el("div", { className: "editor-topbar-right" }, downloadBtn, verifyBtn);

  // Huỷ tài liệu nếu đang ký
  if (doc.status === "in_progress") {
    const voidBtn = el(
      "button",
      {
        className: "button danger",
        onClick: () => {
          promptModal({
            title: "Huỷ tài liệu",
            message: "Nhập lý do huỷ tài liệu (người nhận sẽ không thể ký tiếp):",
            placeholder: "Lý do huỷ...",
            confirmText: "Xác nhận huỷ",
            onConfirm: async (reason) => {
              if (!reason) {
                toast("Vui lòng nhập lý do huỷ tài liệu.", "err");
                return;
              }
              try {
                await api(`/v1/documents/${doc.id}/void`, {
                  method: "POST",
                  body: { reason },
                });
                toast("Đã huỷ tài liệu.", "ok");
                renderSentDoc(container, doc.id);
              } catch (err) {
                toast(`Không thể huỷ: ${err.message}`, "err");
              }
            },
          });
        },
      },
      "Huỷ tài liệu"
    );
    actionsRight.appendChild(voidBtn);
  }

  // Xoá tài liệu nếu không phải đang ký
  if (doc.status !== "in_progress") {
    const deleteBtn = el(
      "button",
      {
        className: "button danger",
        onClick: () => {
          confirmModal({
            title: "Xoá tài liệu",
            message: "Bạn có chắc chắn muốn xoá vĩnh viễn tài liệu này không?",
            confirmText: "Xoá vĩnh viễn",
            danger: true,
            onConfirm: async () => {
              try {
                await api(`/v1/documents/${doc.id}`, { method: "DELETE" });
                toast("Đã xoá tài liệu.", "ok");
                location.hash = "#/documents";
              } catch (err) {
                toast(`Không thể xoá: ${err.message}`, "err");
              }
            },
          });
        },
      },
      "Xoá"
    );
    actionsRight.appendChild(deleteBtn);
  }

  const topBar = el(
    "div",
    { className: "editor-topbar" },
    el("div", { className: "editor-topbar-left" }, backLink, docTitleSpan, statusBadge),
    actionsRight
  );

  // PDF Viewer controls
  const zoomOutBtn = el("button", { className: "button", onClick: () => setScale(scale - 0.15) }, "−");
  const zoomLevelLabel = el("span", { className: "zoom-label" }, "100%");
  const zoomInBtn = el("button", { className: "button", onClick: () => setScale(scale + 0.15) }, "+");
  const zoomFitBtn = el("button", { className: "button", onClick: fitToWidth }, "Vừa khung");
  const pageInfoSpan = el("span", { className: "page-info muted" }, "Đang tải trang…");

  const viewerToolbar = el(
    "div",
    { className: "viewer-bar" },
    el("span", { className: "viewer-bar-label muted" }, "Xem tài liệu PDF"),
    el("span", { className: "bar-gap" }),
    el("div", { className: "zoom-controls" }, zoomOutBtn, zoomLevelLabel, zoomInBtn, zoomFitBtn),
    pageInfoSpan
  );

  const pagesContainer = el("div", { className: "pages", id: "viewer-pages" });
  const viewerSection = el("section", { className: "viewer" }, viewerToolbar, pagesContainer);

  // Sidebar Panels
  const sidePanel = el("aside", { className: "editor-sidebar" });

  const tabRecipientsBtn = el(
    "button",
    {
      className: `detail-tab ${activeTab === "recipients" ? "active" : ""}`,
      onClick: () => switchTab("recipients"),
    },
    "Người nhận"
  );

  const tabAuditBtn = el(
    "button",
    {
      className: `detail-tab ${activeTab === "audit" ? "active" : ""}`,
      onClick: () => switchTab("audit"),
    },
    "Nhật ký kiểm toán"
  );

  const tabNav = el("div", { className: "detail-tabs" }, tabRecipientsBtn, tabAuditBtn);
  const tabContent = el("div", { className: "detail-tab-content" });

  sidePanel.append(tabNav, tabContent);

  const mainLayout = el("div", { className: "editor-layout" }, viewerSection, sidePanel);
  container.append(topBar, mainLayout);

  function switchTab(tab) {
    activeTab = tab;
    tabRecipientsBtn.classList.toggle("active", activeTab === "recipients");
    tabAuditBtn.classList.toggle("active", activeTab === "audit");
    if (activeTab === "recipients") {
      renderRecipientsTab();
    } else {
      renderAuditTab();
    }
  }

  // Tab 1: Chi tiết người nhận & Tiến độ
  function renderRecipientsTab() {
    tabContent.replaceChildren();

    // Thông tin metadata tài liệu
    const metaCard = el(
      "div",
      { className: "card editor-card", style: { marginBottom: "16px" } },
      el("h4", { className: "editor-section-title" }, "Thông tin"),
      el("div", { className: "detail-meta-row" }, el("span", { className: "muted" }, "Tệp gốc:"), el("span", {}, doc.filename)),
      el(
        "div",
        { className: "detail-meta-row" },
        el("span", { className: "muted" }, "Mã tham chiếu:"),
        el("span", {}, doc.external_ref ? el("code", {}, doc.external_ref) : "—")
      ),
      el("div", { className: "detail-meta-row" }, el("span", { className: "muted" }, "Ngày tạo:"), el("span", {}, formatDate(doc.created_at))),
      doc.sent_at ? el("div", { className: "detail-meta-row" }, el("span", { className: "muted" }, "Ngày gửi:"), el("span", {}, formatDate(doc.sent_at))) : null,
      doc.completed_at ? el("div", { className: "detail-meta-row" }, el("span", { className: "muted" }, "Hoàn tất lúc:"), el("span", {}, formatDate(doc.completed_at))) : null,
      doc.expires_at ? el("div", { className: "detail-meta-row" }, el("span", { className: "muted" }, "Hết hạn:"), el("span", {}, formatDate(doc.expires_at))) : null,
      doc.void_reason ? el("div", { className: "detail-meta-row err" }, el("span", { className: "muted" }, "Lý do huỷ:"), el("span", {}, doc.void_reason)) : null
    );

    // Timeline người nhận
    const recipientsTitle = el("h4", { className: "editor-section-title" }, "Tiến trình người nhận");
    const timelineList = el("div", { className: "timeline-list" });

    (doc.recipients || []).forEach((rec, idx) => {
      const color = RECIPIENT_COLORS[idx % RECIPIENT_COLORS.length];
      const roleText = ROLE_LABELS[rec.role] || rec.role;
      const statusText =
        rec.status === "signed"
          ? "Đã ký số"
          : rec.status === "approved"
          ? "Đã duyệt"
          : rec.status === "declined"
          ? "Đã từ chối"
          : "Chờ xử lý";

      const statusBadge = el(
        "span",
        { className: `badge badge-${rec.status}` },
        statusText
      );

      const header = el(
        "div",
        { className: "timeline-item-header" },
        el("div", {},
          el("span", { className: "timeline-order-badge" }, `Bước ${rec.order}`),
          el("strong", { style: { marginLeft: "8px" } }, rec.name)
        ),
        statusBadge
      );

      const subInfo = el(
        "div",
        { className: "timeline-item-meta muted" },
        el("span", {}, `${roleText}`),
        rec.email ? el("span", {}, ` · ${rec.email}`) : null,
        rec.tax_code ? el("span", {}, ` · MST: ${rec.tax_code}`) : null
      );

      const timestamps = el(
        "div",
        { className: "timeline-timestamps table-subtext" },
        rec.viewed_at ? el("div", {}, `Đã xem: ${formatDate(rec.viewed_at)}`) : null,
        rec.acted_at ? el("div", {}, `Đã xử lý: ${formatDate(rec.acted_at)}`) : null,
        rec.decline_reason ? el("div", { className: "status-err" }, `Lý do từ chối: ${rec.decline_reason}`) : null
      );

      // Chi tiết chữ ký số (nếu đã ký)
      let signatureBox = null;
      if (rec.signature) {
        const sig = rec.signature;
        signatureBox = el(
          "div",
          { className: "sig-details-box" },
          el("div", { className: "sig-details-title" }, "✓ Thông tin chứng thư số:"),
          el("div", { className: "sig-details-row" }, el("span", { className: "muted" }, "Người ký:"), el("strong", {}, sig.signer)),
          sig.tax_code ? el("div", { className: "sig-details-row" }, el("span", { className: "muted" }, "MST:"), el("span", {}, sig.tax_code)) : null,
          el("div", { className: "sig-details-row" }, el("span", { className: "muted" }, "Nhà cấp (CA):"), el("span", {}, sig.cert_issuer)),
          el("div", { className: "sig-details-row" }, el("span", { className: "muted" }, "Serial chứng thư:"), el("code", {}, sig.cert_serial)),
          el("div", { className: "sig-details-row" }, el("span", { className: "muted" }, "Chuẩn ký:"), el("span", {}, sig.profile || "PAdES"))
        );
      }

      // Thao tác cho người nhận đang chờ (chưa xong)
      let pendingActions = null;
      if (rec.status === "pending" && doc.status === "in_progress") {
        pendingActions = el("div", { className: "timeline-actions" });

        // Copy signing URL
        if (rec.signing_url) {
          const copyBtn = el(
            "button",
            {
              className: "button small",
              onClick: async () => {
                try {
                  await navigator.clipboard.writeText(rec.signing_url);
                  toast("Đã sao chép liên kết ký!", "ok");
                } catch {
                  promptModal({
                    title: "Liên kết ký",
                    message: "Sao chép liên kết dưới đây:",
                    defaultValue: rec.signing_url,
                  });
                }
              },
            },
            "📋 Sao chép liên kết ký"
          );
          pendingActions.appendChild(copyBtn);
        }

        // Nhắc lại qua email (nếu email_enabled)
        if (state.config?.email_enabled && rec.email) {
          const remindBtn = el(
            "button",
            {
              className: "button small",
              onClick: async () => {
                remindBtn.disabled = true;
                try {
                  await api(`/v1/documents/${doc.id}/recipients/${rec.id}/remind`, {
                    method: "POST",
                  });
                  toast(`Đã gửi email nhắc nhở tới ${rec.email}`, "ok");
                } catch (err) {
                  toast(`Không thể gửi nhắc nhở: ${err.message}`, "err");
                } finally {
                  remindBtn.disabled = false;
                }
              },
            },
            "✉ Nhắc lại"
          );
          pendingActions.appendChild(remindBtn);
        }

        // Cấp liên kết mới (rotate-link)
        const rotateBtn = el(
          "button",
          {
            className: "button small",
            onClick: () => {
              confirmModal({
                title: "Cấp liên kết mới",
                message:
                  "Liên kết ký cũ sẽ bị vô hiệu hoá ngay lập tức. Bạn có chắc chắn muốn tạo liên kết mới cho người này?",
                confirmText: "Cấp liên kết mới",
                onConfirm: async () => {
                  try {
                    const updated = await api(
                      `/v1/documents/${doc.id}/recipients/${rec.id}/rotate-link`,
                      { method: "POST" }
                    );
                    rec.signing_url = updated.signing_url;
                    toast("Đã cấp liên kết mới thành công!", "ok");
                    renderRecipientsTab();
                  } catch (err) {
                    toast(`Lỗi khi tạo liên kết mới: ${err.message}`, "err");
                  }
                },
              });
            },
          },
          "🔄 Cấp liên kết mới"
        );
        pendingActions.appendChild(rotateBtn);
      }

      const card = el(
        "div",
        {
          className: "timeline-card card",
          style: { borderLeft: `3px solid ${color.border}` },
        },
        header,
        subInfo,
        timestamps,
        signatureBox,
        pendingActions
      );

      timelineList.appendChild(card);
    });

    tabContent.append(metaCard, recipientsTitle, timelineList);
  }

  // Tab 2: Nhật ký kiểm toán (Audit Trail)
  async function renderAuditTab() {
    tabContent.replaceChildren(el("div", { className: "loading-state" }, "Đang tải nhật ký kiểm toán…"));

    try {
      const [auditData, members] = await Promise.all([
        api(`/v1/documents/${doc.id}/audit`),
        api("/api/org/members").catch(() => []),
      ]);
      const memberNames = new Map(members.map((m) => [m.id, m.name]));
      const recipientNames = new Map((doc.recipients || []).map((r) => [r.id, r.name]));
      // actor dạng "user:<id>" | "api_key:<id>" | "recipient:<id>" | "system"
      const actorLabel = (actor) => {
        const [kind, id] = String(actor || "system").split(":");
        if (kind === "user") return memberNames.get(id) || `Thành viên ${id}`;
        if (kind === "api_key") return `Khoá API ${id}`;
        if (kind === "recipient") return `${recipientNames.get(id) || "Người nhận"} (người nhận)`;
        return "Hệ thống";
      };
      tabContent.replaceChildren();

      // Badge tính toàn vẹn chuỗi băm
      const chainValid = auditData.chain_valid;
      const chainBadge = el(
        "div",
        {
          className: `chain-status-banner ${chainValid ? "valid" : "broken"}`,
        },
        chainValid
          ? "✓ Chuỗi băm nhật ký kiểm toán toàn vẹn (SHA-256)"
          : `✗ Cảnh báo: Chuỗi kiểm toán bị đứt đoạn tại sự kiện #${auditData.broken_at}`
      );

      const headHashBox = el(
        "div",
        { className: "head-hash-box" },
        el("span", { className: "muted" }, "Head Hash: "),
        el("code", { className: "hash-text" }, auditData.head || "—")
      );

      const eventsList = el("div", { className: "audit-events-list" });
      const events = auditData.events || [];

      if (events.length === 0) {
        eventsList.appendChild(el("p", { className: "muted" }, "Chưa có sự kiện nào được ghi nhận."));
      } else {
        events.forEach((ev) => {
          const typeLabel = AUDIT_EVENT_LABELS[ev.type] || ev.type;
          const actorText = actorLabel(ev.actor);

          const evItem = el(
            "div",
            { className: "audit-event-item" },
            el(
              "div",
              { className: "audit-event-header" },
              el("span", { className: "audit-seq" }, `#${ev.seq}`),
              el("strong", { className: "audit-type" }, typeLabel),
              el("span", { className: "audit-time muted" }, formatDate(ev.at))
            ),
            el(
              "div",
              { className: "audit-event-body muted" },
              el("span", {}, `Tác nhân: ${actorText}`),
              ev.ip ? el("span", {}, ` · IP: ${ev.ip}`) : null
            ),
            ev.data && Object.keys(ev.data).length > 0
              ? el(
                  "div",
                  { className: "audit-event-data" },
                  el("pre", {}, JSON.stringify(ev.data, null, 2))
                )
              : null,
            el("div", { className: "audit-hash muted" }, `Hash: ${ev.hash.slice(0, 16)}…`)
          );

          eventsList.appendChild(evItem);
        });
      }

      tabContent.append(chainBadge, headHashBox, eventsList);
    } catch (err) {
      tabContent.replaceChildren(
        el("div", { className: "error-state" }, `Không thể tải nhật ký kiểm toán: ${err.message}`)
      );
    }
  }

  // Xác thực chữ ký số (/v1/documents/{id}/verify)
  async function verifySignatures() {
    showModal({
      title: "Xác thực chữ ký số tài liệu",
      content: el("div", { className: "loading-state" }, "Đang kiểm tra chứng thư và tính toàn vẹn…"),
      actions: [{ label: "Đóng", primary: true }],
    });

    const modalBody = document.querySelector(".modal-body");
    try {
      const reports = await api(`/v1/documents/${doc.id}/verify`);
      modalBody.replaceChildren();

      if (!reports || reports.length === 0) {
        modalBody.appendChild(el("p", { className: "muted" }, "Tài liệu này hiện chưa có chữ ký số nào."));
        return;
      }

      reports.forEach((report) => {
        const tone = !report.intact ? "invalid" : report.trusted ? "valid" : "warn";
        const statusIcon = tone === "valid" ? "✓" : tone === "warn" ? "!" : "✗";

        const lines = [
          `${report.field_name || "Chữ ký"} · ${report.issuer}`,
          report.tax_code ? `MST: ${report.tax_code}` : null,
          report.signed_at ? `Ký lúc: ${formatDate(report.signed_at)}` : null,
          report.timestamped
            ? `Dấu thời gian TSA: ${formatDate(report.timestamp_at)}${
                report.timestamp_trusted ? " (Tin cậy)" : " (Chưa tin cậy)"
              }`
            : "Không có dấu thời gian TSA",
          report.ltv
            ? "LTV: Dữ liệu kiểm tra thu hồi được nhúng trong tệp"
            : "LTV: Chưa nhúng dữ liệu thu hồi",
          `${report.profile} — ${report.summary}`,
          ...(report.problems || []),
          ...(report.notes || []),
        ].filter(Boolean);

        const card = el(
          "div",
          { className: `sig-report ${tone}`, style: { marginBottom: "12px" } },
          el("div", { className: "who" }, `${statusIcon} ${report.signer}`),
          ...lines.map((l) => el("div", { className: "line table-subtext" }, l))
        );

        modalBody.appendChild(card);
      });
    } catch (err) {
      modalBody.replaceChildren(
        el("div", { className: "form-error" }, `Lỗi khi xác thực: ${err.message}`)
      );
    }
  }

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
      drawPlacedBoxes();
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
    drawPlacedBoxes();
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

  // Vẽ các ô ký trên trang (chỉ đọc)
  function drawPlacedBoxes() {
    for (const item of pages) {
      for (const node of item.overlay.querySelectorAll(".sig-box")) {
        node.remove();
      }
    }

    (doc.recipients || []).forEach((rec, idx) => {
      if (rec.role !== "signer" || !rec.field) return;
      const pageIndex = rec.field.page;
      const item = pages[pageIndex];
      if (!item) return;

      const isSigned = rec.status === "signed";
      const color = isSigned
        ? { border: "#22c55e", bg: "rgba(34, 197, 94, 0.12)", text: "#86efac" }
        : RECIPIENT_COLORS[idx % RECIPIENT_COLORS.length];

      const [x1, y1, x2, y2] = rec.field.box;
      const [sx1, sy1] = item.viewport.convertToViewportPoint(x1, y2);
      const [sx2, sy2] = item.viewport.convertToViewportPoint(x2, y1);

      const width = Math.abs(sx2 - sx1);
      const height = Math.abs(sy2 - sy1);
      const left = Math.min(sx1, sx2);
      const top = Math.min(sy1, sy2);

      const div = el("div", {
        className: `sig-box readonly ${isSigned ? "signed" : "pending"}`,
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
        el("strong", {}, isSigned ? `✓ ${rec.name}` : rec.name),
        el("span", { className: "sig-box-sub" }, isSigned ? "Đã ký số" : "Chờ ký")
      );

      div.appendChild(label);
      item.overlay.appendChild(div);
    });
  }

  renderRecipientsTab();
  loadPdf();
}
