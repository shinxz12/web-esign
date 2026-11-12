/**
 * Danh sách tài liệu và tạo tài liệu mới (tải PDF lên).
 */

import { api, el, STATUS_LABELS, toast } from "./api.js";

function formatShortDate(isoString) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    const parts = new Intl.DateTimeFormat("vi-VN", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).formatToParts(d);
    const map = Object.fromEntries(parts.map((p) => [p.type, p.value]));
    return `${map.day}/${map.month}/${map.year} ${map.hour}:${map.minute}`;
  } catch {
    return isoString;
  }
}
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
    "Tạo tài liệu"
  );
  const header = el("div", { className: "page-header" }, titleHeading, newDocBtn);

  // Filter Tabs
  const tabsContainer = el("div", { className: "filter-tabs" });
  for (const tab of statusTabs) {
    const tabBtn = el(
      "button",
      {
        className: `filter-tab ${currentStatus === tab.id ? "active" : ""}`,
        dataset: { tabId: tab.id },
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
    placeholder: "Tìm theo tiêu đề hoặc tên tệp…",
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
        el("th", {}, "Tài liệu"),
        el("th", {}, "Mã hồ sơ"),
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

  const emptyState = el("div", { className: "empty-state", hidden: true });

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
        emptyState.replaceChildren();

        const isFiltered = Boolean(currentStatus || searchQuery);
        if (isFiltered) {
          emptyState.appendChild(
            el("p", { className: "muted" }, "Không tìm thấy tài liệu nào phù hợp với bộ lọc hiện tại.")
          );
          const clearFilterBtn = el(
            "button",
            {
              className: "button",
              style: { marginTop: "12px" },
              onClick: () => {
                currentStatus = "";
                searchQuery = "";
                searchInput.value = "";
                for (const btn of tabsContainer.children) {
                  btn.classList.toggle("active", btn.dataset?.tabId === "");
                }
                loadData(true);
              },
            },
            "Xoá bộ lọc"
          );
          emptyState.appendChild(clearFilterBtn);
        } else {
          emptyState.appendChild(
            el("p", { className: "muted" }, "Chưa có tài liệu nào. Tải lên tệp PDF đầu tiên để gửi đi ký.")
          );
          emptyState.appendChild(
            el(
              "a",
              { href: "#/documents/new", className: "button primary", style: { marginTop: "12px" } },
              "Tạo tài liệu"
            )
          );
        }
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
      progressText = `${completed}/${total} đã ký`;
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
      el("td", { className: "muted" }, formatShortDate(doc.updated_at || doc.created_at)),
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
    id: "new-doc-file",
    type: "file",
    accept: "application/pdf",
    required: true,
    hidden: true,
  });

  function createUploadSvg() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", "32");
    svg.setAttribute("height", "32");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.75");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>';
    return svg;
  }

  function createPdfSvg() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", "16");
    svg.setAttribute("height", "16");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>';
    return svg;
  }

  function createCloseSvg() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>';
    return svg;
  }

  function createRefreshSvg() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = '<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>';
    return svg;
  }

  const fileDropZone = el(
    "div",
    {
      className: "file-drop-zone",
      tabIndex: 0,
      role: "button",
      ariaLabel: "Chọn tệp PDF hoặc kéo thả vào đây",
      onClick: () => fileInput.click(),
      onKeydown: (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          fileInput.click();
        }
      },
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
    el("div", { className: "drop-icon-wrap" }, createUploadSvg()),
    el("div", { className: "drop-prompt" }, "Chọn tệp PDF hoặc kéo thả vào đây"),
    el("div", { className: "drop-hint muted" }, "Định dạng .pdf, dung lượng tối đa theo giới hạn của gói"),
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

    const removeBtn = el(
      "button",
      {
        type: "button",
        className: "btn-remove-file",
        ariaLabel: "Xoá tệp đã chọn",
        title: "Xoá tệp đã chọn",
        onClick: (e) => {
          e.stopPropagation();
          selectedFile = null;
          fileInput.value = "";
          fileInfoBox.hidden = true;
          fileDropZone.hidden = false;
          updateSubmit();
        },
      },
      createCloseSvg()
    );

    fileInfoBox.replaceChildren(
      createPdfSvg(),
      el("span", { className: "file-name" }, file.name),
      el("span", { className: "file-size muted" }, ` (${(file.size / 1024 / 1024).toFixed(2)} MB)`),
      removeBtn
    );
    fileInfoBox.hidden = false;
    fileDropZone.hidden = true;

    if (!titleInput.value) {
      titleInput.value = file.name.replace(/\.pdf$/i, "");
    }
    updateSubmit();
  }

  fileInput.addEventListener("change", () => {
    if (fileInput.files?.length) {
      handleFileSelect(fileInput.files[0]);
    }
  });

  const titleInput = el("input", {
    id: "new-doc-title",
    type: "text",
    placeholder: "Hợp đồng kinh tế số 01/2026...",
  });

  let mode = "send";
  let certificates = [];
  const certSelect = el("select", { id: "new-doc-cert", hidden: true });
  const pairingInput = el("input", {
    id: "new-doc-pairing",
    type: "text",
    inputMode: "numeric",
    maxLength: 6,
    placeholder: "Mã 6 chữ số",
    style: { width: "130px", flex: "none" },
  });
  const certStatus = el("span", { className: "muted", style: { fontSize: "13px", flex: "1 1 100%" } });

  function fillCertificates(list, source) {
    certificates = list;
    certSelect.hidden = !list.length;
    certSelect.replaceChildren(
      ...list.map((c, i) =>
        el("option", { value: String(i) }, `${c.subject}${c.tax_code ? ` — MST ${c.tax_code}` : ""} (${c.issuer})`)
      )
    );
    certStatus.textContent = list.length
      ? `${list.length} chứng thư từ ứng dụng Web Signer trên máy tính.`
      : "Ứng dụng Web Signer trên máy tính đang chạy nhưng chưa thấy chứng thư. Hãy kiểm tra token đã cắm vào máy.";
    updateSubmit();
  }

  async function loadDeviceCertificates() {
    certStatus.textContent = "Đang tìm ứng dụng Web Signer trên máy tính…";
    try {
      const res = await api("/api/agents");
      if (res.online) {
        fillCertificates(res.certificates, "ứng dụng của máy này");
        return;
      }
      certificates = [];
      certSelect.replaceChildren();
      certSelect.hidden = true;
      certStatus.textContent = res.device
        ? "Ứng dụng Web Signer trên máy tính chưa mở. Hãy mở ứng dụng rồi bấm tìm lại, hoặc nhập mã ghép cặp."
        : "Chưa kết nối với ứng dụng Web Signer trên máy tính. Mở ứng dụng và bấm “Kích hoạt trình duyệt”, hoặc nhập mã ghép cặp.";
    } catch (err) {
      certStatus.textContent = err.message;
    }
    updateSubmit();
  }

  async function loadPairedCertificates() {
    const code = pairingInput.value.trim();
    if (!/^\d{6}$/.test(code)) {
      toast("Mã ghép cặp gồm 6 chữ số.", "err");
      return;
    }
    try {
      const res = await api(`/api/agents/${code}/certificates`);
      fillCertificates(res.certificates, `agent ${res.agent}`);
    } catch (err) {
      toast(err.message, "err");
    }
  }

  const nowrap = { whiteSpace: "nowrap", flex: "none" };
  const refreshBtn = el(
    "button",
    {
      type: "button",
      title: "Tìm lại kết nối ứng dụng Web Signer",
      ariaLabel: "Tìm lại kết nối ứng dụng Web Signer",
      style: nowrap,
      onClick: loadDeviceCertificates,
    },
    createRefreshSvg()
  );

  const selfBox = el(
    "div",
    { className: "form-group", hidden: true },
    el("label", { htmlFor: "new-doc-cert" }, "Chứng thư dùng để ký"),
    certSelect,
    el(
      "div",
      { style: { display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px", marginTop: "6px" } },
      certStatus,
      refreshBtn,
      pairingInput,
      el("button", { type: "button", style: nowrap, onClick: loadPairedCertificates }, "Dùng mã")
    )
  );

  const submitBtn = el(
    "button",
    {
      type: "submit",
      className: "primary",
      disabled: true,
    },
    "Tải lên và thêm người nhận"
  );

  function submitLabel() {
    return mode === "self" ? "Tải lên và ký" : "Tải lên và thêm người nhận";
  }

  function updateSubmit() {
    submitBtn.textContent = submitLabel();
    submitBtn.disabled = !selectedFile || (mode === "self" && !certificates.length);
  }

  const titleGroup = el(
    "div",
    { className: "form-group" },
    el("label", { htmlFor: "new-doc-title" }, "Tiêu đề tài liệu"),
    titleInput
  );

  function setMode(next) {
    mode = next;
    const self = mode === "self";
    selfBox.hidden = !self;
    titleGroup.hidden = self;
    form.classList.toggle("compact", self);
    if (self && !certificates.length) loadDeviceCertificates();
    updateSubmit();
  }

  const optionStyle = {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    fontWeight: "normal",
    textTransform: "none",
    letterSpacing: "normal",
    margin: 0,
    cursor: "pointer",
  };

  const modeGroup = el(
    "fieldset",
    { className: "form-group mode-group" },
    el("legend", {}, "Hình thức xử lý"),
    el(
      "div",
      { style: { display: "flex", flexWrap: "wrap", gap: "12px 24px" } },
      el(
        "label",
        { style: optionStyle },
        el("input", {
          type: "radio",
          name: "sign-mode",
          id: "mode-send",
          value: "send",
          checked: true,
          onChange: () => setMode("send"),
        }),
        "Gửi người khác ký"
      ),
      el(
        "label",
        { style: optionStyle },
        el("input", {
          type: "radio",
          name: "sign-mode",
          id: "mode-self",
          value: "self",
          onChange: () => setMode("self"),
        }),
        "Tự ký bằng USB token"
      )
    )
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
        submitBtn.textContent = "Đang tải lên…";

        try {
          const docData = {
            title: titleInput.value.trim() || selectedFile.name.replace(/\.pdf$/i, ""),
          };
          if (mode === "self") {
            const cert = certificates[Number(certSelect.value) || 0];
            if (!cert) throw new Error("Chưa chọn chứng thư để ký.");
            docData.send = true;
            docData.recipients = [{ name: cert.subject, ...(cert.tax_code ? { tax_code: cert.tax_code } : {}) }];
          }

          const formData = new FormData();
          formData.append("file", selectedFile);
          formData.append("data", JSON.stringify(docData));

          const res = await api("/v1/documents", {
            method: "POST",
            body: formData,
          });

          const selfLink = mode === "self" ? res.recipients?.[0]?.signing_url : null;
          if (selfLink) {
            location.href = selfLink;
            return;
          }
          toast("Đã tạo tài liệu thành công.", "ok");
          location.hash = `#/documents/${res.id}`;
        } catch (err) {
          toast(err.message, "err");
          updateSubmit();
        }
      },
    },
    modeGroup,
    el(
      "div",
      { className: "form-group" },
      el("label", { htmlFor: "new-doc-file" }, "Tệp PDF cần ký"),
      fileDropZone,
      fileInfoBox
    ),
    selfBox,
    titleGroup,
    el("div", { className: "form-actions", style: { marginTop: "24px" } }, submitBtn, cancelBtn)
  );

  const heading = el("h2", { className: "page-title" }, "Tải lên tài liệu mới");
  const subtext = el(
    "p",
    { className: "muted" },
    "Tải lên tệp PDF để chuẩn bị người nhận và vị trí ký."
  );

  const card = el(
    "div",
    { className: "card content-card", style: { maxWidth: "680px" } },
    form
  );

  container.append(
    el(
      "div",
      { className: "breadcrumb" },
      el("a", { href: "#/documents" }, "Quay lại danh sách tài liệu")
    ),
    el("div", { className: "page-header" }, el("div", {}, heading, subtext)),
    card
  );
}
