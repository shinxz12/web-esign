/**
 * Danh sách tài liệu và tạo tài liệu mới (tải PDF lên).
 */

import { api, el, formatDate, STATUS_LABELS, toast } from "./api.js";

/**
 * Màn hình danh sách tài liệu (#/documents)
 */
export function renderDocumentsList(container, filterStatus = "", query = "") {
  container.replaceChildren();

  let currentStatus = filterStatus;
  let searchQuery = query;
  let nextCursor = null;
  let isLoading = false;
  let documents = [];

  const statusTabs = [
    { id: "", label: "Tất cả" },
    { id: "draft", label: "Nháp" },
    { id: "in_progress", label: "Đang ký" },
    { id: "completed", label: "Hoàn tất" },
    { id: "declined", label: "Bị từ chối" },
    { id: "voided", label: "Đã huỷ" },
    { id: "expired", label: "Hết hạn" },
  ];

  // Header & Controls
  const titleHeading = el("h2", { className: "page-title" }, "Tài liệu");
  const newDocBtn = el(
    "a",
    { href: "#/documents/new", className: "button primary" },
    "+ Tạo tài liệu"
  );
  const header = el("div", { className: "page-header" }, titleHeading, newDocBtn);

  // Filter Tabs
  const tabsContainer = el("div", { className: "filter-tabs" });
  for (const tab of statusTabs) {
    const tabBtn = el(
      "button",
      {
        className: `filter-tab ${currentStatus === tab.id ? "active" : ""}`,
        onClick: () => {
          if (currentStatus === tab.id) return;
          currentStatus = tab.id;
          for (const btn of tabsContainer.children) {
            btn.classList.remove("active");
          }
          tabBtn.classList.add("active");
          loadData(true);
        },
      },
      tab.label
    );
    tabsContainer.appendChild(tabBtn);
  }

  // Search box
  let searchTimeout = null;
  const searchInput = el("input", {
    type: "search",
    className: "search-input",
    placeholder: "Tìm theo tiêu đề, tên tệp, external_ref…",
    value: searchQuery,
    onInput: (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        searchQuery = e.target.value.trim();
        loadData(true);
      }, 300);
    },
  });

  const controls = el(
    "div",
    { className: "table-controls" },
    tabsContainer,
    el("div", { className: "search-box" }, searchInput)
  );

  // Table
  const tableBody = el("tbody");
  const table = el(
    "table",
    { className: "data-table" },
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        el("th", {}, "Tiêu đề & Tệp"),
        el("th", {}, "Mã tham chiếu"),
        el("th", {}, "Trạng thái"),
        el("th", {}, "Tiến độ ký"),
        el("th", {}, "Cập nhật"),
        el("th", { style: { textAlign: "right" } }, "Thao tác")
      )
    ),
    tableBody
  );

  const loadMoreBtn = el(
    "button",
    {
      className: "button",
      style: { margin: "16px auto", display: "none" },
      onClick: () => loadData(false),
    },
    "Tải thêm"
  );

  const emptyState = el(
    "div",
    { className: "empty-state", hidden: true },
    el("div", { className: "empty-icon" }, "📄"),
    el("p", { className: "muted" }, "Không tìm thấy tài liệu nào phù hợp."),
    el(
      "a",
      { href: "#/documents/new", className: "button primary", style: { marginTop: "12px" } },
      "Tải lên tài liệu đầu tiên"
    )
  );

  const tableWrapper = el(
    "div",
    { className: "table-responsive" },
    table,
    emptyState,
    loadMoreBtn
  );

  container.append(header, controls, tableWrapper);

  async function loadData(reset = false) {
    if (isLoading) return;
    isLoading = true;

    if (reset) {
      nextCursor = null;
      documents = [];
      tableBody.replaceChildren();
      emptyState.hidden = true;
    }

    loadMoreBtn.disabled = true;
    loadMoreBtn.textContent = "Đang tải…";

    try {
      const params = new URLSearchParams({ limit: "20" });
      if (currentStatus) params.set("status", currentStatus);
      if (searchQuery) params.set("q", searchQuery);
      if (nextCursor) params.set("cursor", nextCursor);

      const res = await api(`/v1/documents?${params.toString()}`);
      const list = res.data || [];
      nextCursor = res.next_cursor || null;

      if (reset && list.length === 0) {
        emptyState.hidden = false;
        table.hidden = true;
        loadMoreBtn.style.display = "none";
        return;
      }

      table.hidden = false;
      emptyState.hidden = true;

      for (const doc of list) {
        documents.push(doc);
        renderDocRow(doc, tableBody);
      }

      if (nextCursor) {
        loadMoreBtn.style.display = "block";
        loadMoreBtn.disabled = false;
        loadMoreBtn.textContent = "Tải thêm";
      } else {
        loadMoreBtn.style.display = "none";
      }
    } catch (err) {
      toast(`Không thể tải danh sách tài liệu: ${err.message}`, "err");
    } finally {
      isLoading = false;
    }
  }

  function renderDocRow(doc, tbody) {
    // Tính tiến độ ký: số người đã ký/duyệt trên tổng số người nhận
    const total = doc.recipients ? doc.recipients.length : 0;
    const completed = doc.recipients
      ? doc.recipients.filter((r) => r.status === "signed" || r.status === "approved").length
      : 0;

    let progressText = "—";
    if (total > 0) {
      progressText = `${completed}/${total} người`;
    }

    const statusBadge = el(
      "span",
      { className: `badge badge-${doc.status}` },
      STATUS_LABELS[doc.status] || doc.status
    );

    const titleLink = el(
      "a",
      {
        href: `#/documents/${doc.id}`,
        className: "doc-title-link",
      },
      doc.title || doc.filename || "Không có tiêu đề"
    );

    const filenameSub = el("div", { className: "table-subtext" }, doc.filename);

    const actionBtn = el(
      "a",
      {
        href: `#/documents/${doc.id}`,
        className: `button ${doc.status === "draft" ? "primary" : ""}`,
      },
      doc.status === "draft" ? "Sửa bản nháp" : "Xem chi tiết"
    );

    const tr = el(
      "tr",
      {
        className: "data-row",
        onClick: (e) => {
          // Tránh chặn click vào nút hoặc link
          if (e.target.closest("a, button")) return;
          location.hash = `#/documents/${doc.id}`;
        },
      },
      el("td", {}, titleLink, filenameSub),
      el("td", {}, doc.external_ref ? el("code", {}, doc.external_ref) : "—"),
      el("td", {}, statusBadge),
      el("td", {}, progressText),
      el("td", { className: "muted" }, formatDate(doc.updated_at || doc.created_at)),
      el("td", { style: { textAlign: "right" } }, actionBtn)
    );

    tbody.appendChild(tr);
  }

  loadData(true);
}

/**
 * Màn hình tải tệp PDF lên để tạo tài liệu mới (#/documents/new)
 */
export function renderNewDocument(container) {
  container.replaceChildren();

  const fileInput = el("input", {
    type: "file",
    accept: "application/pdf",
    required: true,
    hidden: true,
  });

  const fileDropZone = el(
    "div",
    {
      className: "file-drop-zone",
      onClick: () => fileInput.click(),
      onDragover: (e) => {
        e.preventDefault();
        fileDropZone.classList.add("drag-over");
      },
      onDragleave: () => fileDropZone.classList.remove("drag-over"),
      onDrop: (e) => {
        e.preventDefault();
        fileDropZone.classList.remove("drag-over");
        if (e.dataTransfer.files?.length) {
          handleFileSelect(e.dataTransfer.files[0]);
        }
      },
    },
    el("div", { className: "drop-icon" }, "📥"),
    el("div", { className: "drop-prompt" }, "Chọn tệp PDF hoặc kéo thả vào đây"),
    el("div", { className: "drop-hint muted" }, "Định dạng .pdf, tối đa theo giới hạn của gói"),
    fileInput
  );

  const fileInfoBox = el("div", { className: "selected-file-info", hidden: true });

  let selectedFile = null;

  function handleFileSelect(file) {
    if (!file || !file.name.toLowerCase().endsWith(".pdf")) {
      toast("Vui lòng chọn tệp có định dạng PDF.", "err");
      return;
    }
    selectedFile = file;
    fileInfoBox.replaceChildren(
      el("span", { className: "file-icon" }, "📄"),
      el("span", { className: "file-name" }, file.name),
      el("span", { className: "file-size muted" }, ` (${(file.size / 1024 / 1024).toFixed(2)} MB)`),
      el(
        "button",
        {
          type: "button",
          className: "btn-remove-file",
          onClick: (e) => {
            e.stopPropagation();
            selectedFile = null;
            fileInput.value = "";
            fileInfoBox.hidden = true;
            fileDropZone.hidden = false;
            submitBtn.disabled = true;
          },
        },
        "✕"
      )
    );
    fileInfoBox.hidden = false;
    fileDropZone.hidden = true;

    // Tự động điền tiêu đề nếu chưa có
    if (!titleInput.value) {
      titleInput.value = file.name.replace(/\.pdf$/i, "");
    }
    submitBtn.disabled = false;
  }

  fileInput.addEventListener("change", () => {
    if (fileInput.files?.length) {
      handleFileSelect(fileInput.files[0]);
    }
  });

  const titleInput = el("input", {
    type: "text",
    placeholder: "Hợp đồng kinh tế số 01/2026...",
  });
  const messageInput = el("textarea", {
    placeholder: "Lời nhắn gửi đến những người nhận (không bắt buộc)…",
    rows: 3,
  });
  const externalRefInput = el("input", {
    type: "text",
    placeholder: "HD-2026-001 (mã hợp đồng nội bộ)",
  });
  const expiryInput = el("input", {
    type: "datetime-local",
  });

  const submitBtn = el(
    "button",
    {
      type: "submit",
      className: "primary",
      disabled: true,
    },
    "Tải lên & Chuyển sang chỉnh sửa"
  );

  const cancelBtn = el(
    "a",
    {
      href: "#/documents",
      className: "button",
    },
    "Huỷ"
  );

  const form = el(
    "form",
    {
      className: "new-doc-form",
      onSubmit: async (e) => {
        e.preventDefault();
        if (!selectedFile) {
          toast("Vui lòng chọn tệp PDF trước.", "err");
          return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Đang tải tệp lên…";

        try {
          const docData = {
            title: titleInput.value.trim() || selectedFile.name.replace(/\.pdf$/i, ""),
          };
          if (messageInput.value.trim()) {
            docData.message = messageInput.value.trim();
          }
          if (externalRefInput.value.trim()) {
            docData.external_ref = externalRefInput.value.trim();
          }
          if (expiryInput.value) {
            docData.expires_at = new Date(expiryInput.value).toISOString();
          }

          const formData = new FormData();
          formData.append("file", selectedFile);
          formData.append("data", JSON.stringify(docData));

          const res = await api("/v1/documents", {
            method: "POST",
            body: formData,
          });

          toast("Đã tạo tài liệu thành công!", "ok");
          location.hash = `#/documents/${res.id}`;
        } catch (err) {
          toast(err.message, "err");
          submitBtn.disabled = false;
          submitBtn.textContent = "Tải lên & Chuyển sang chỉnh sửa";
        }
      },
    },
    el("div", { className: "form-group" }, el("label", {}, "Tệp tài liệu PDF *"), fileDropZone, fileInfoBox),
    el("div", { className: "form-group" }, el("label", {}, "Tiêu đề tài liệu"), titleInput),
    el("div", { className: "form-group" }, el("label", {}, "Mã tham chiếu ngoài (external_ref)"), externalRefInput),
    el("div", { className: "form-group" }, el("label", {}, "Thời hạn hoàn tất"), expiryInput),
    el("div", { className: "form-group" }, el("label", {}, "Lời nhắn gửi kèm"), messageInput),
    el("div", { className: "form-actions", style: { marginTop: "24px" } }, submitBtn, cancelBtn)
  );

  const card = el(
    "div",
    { className: "card content-card", style: { maxWidth: "720px", margin: "0 auto" } },
    el("h2", { style: { marginTop: 0 } }, "Tải lên tài liệu mới"),
    el("p", { className: "muted" }, "Tải lên tệp PDF để thiết lập người nhận và vị trí các ô ký"),
    form
  );

  container.append(
    el(
      "div",
      { className: "breadcrumb" },
      el("a", { href: "#/documents" }, "← Danh sách tài liệu")
    ),
    card
  );
}
