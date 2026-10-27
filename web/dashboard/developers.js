/**
 * Màn hình Nhà phát triển (#/developers — Quản trị viên & Chủ sở hữu)
 * Quản lý Khoá API, Webhooks, Lịch sử gửi (Deliveries), và Hướng dẫn tích hợp curl.
 */

import {
  api,
  confirmModal,
  el,
  formatDate,
  promptModal,
  showModal,
  state,
  toast,
} from "./api.js";

export async function renderDevelopers(container) {
  container.replaceChildren();

  // Kiểm tra quyền
  if (state.me?.user?.role === "member") {
    container.appendChild(
      el(
        "div",
        { className: "card content-card", style: { margin: "24px auto", maxWidth: "600px", textAlign: "center" } },
        el("h3", {}, "Không có quyền truy cập"),
        el("p", { className: "muted" }, "Trang Nhà phát triển chỉ dành cho Quản trị viên và Chủ sở hữu tổ chức."),
        el("a", { href: "#/documents", className: "button primary" }, "Quay lại Tài liệu")
      )
    );
    return;
  }

  const heading = el("h2", { className: "page-title" }, "Nhà phát triển & Tích hợp");
  const subtext = el(
    "p",
    { className: "muted" },
    "Quản lý khoá API, webhook nhận thông báo tự động và hướng dẫn tích hợp hệ thống."
  );

  // Tab chuyển đổi nội dung
  const sectionsWrapper = el("div", { className: "developers-wrapper" });
  container.append(heading, subtext, sectionsWrapper);

  // Render các phần
  await renderApiKeysSection(sectionsWrapper);
  await renderWebhooksSection(sectionsWrapper);
  await renderEmbedOriginsSection(sectionsWrapper);
  renderQuickstartSection(sectionsWrapper);
}

/**
 * 1. Khoá API (API Keys)
 */
async function renderApiKeysSection(wrapper) {
  const sectionCard = el("div", { className: "card dev-section-card" });
  wrapper.appendChild(sectionCard);

  const header = el(
    "div",
    { className: "section-header" },
    el("div", {},
      el("h3", { style: { margin: 0 } }, "Khoá API (API Keys)"),
      el("p", { className: "muted", style: { margin: "4px 0 0" } }, "Dùng để xác thực API REST /v1 khi tích hợp từ hệ thống máy chủ của bạn.")
    ),
    el(
      "button",
      {
        className: "button primary",
        onClick: createApiKey,
      },
      "+ Tạo khoá API mới"
    )
  );

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
        el("th", {}, "Tên khoá"),
        el("th", {}, "Tiền tố (Prefix)"),
        el("th", {}, "Ngày tạo"),
        el("th", {}, "Sử dụng gần nhất"),
        el("th", {}, "Trạng thái"),
        el("th", { style: { textAlign: "right" } }, "Thao tác")
      )
    ),
    tableBody
  );

  sectionCard.append(header, el("div", { className: "table-responsive", style: { marginTop: "16px" } }, table));

  async function loadKeys() {
    tableBody.replaceChildren(
      el("tr", {}, el("td", { colSpan: 6, className: "muted", style: { textAlign: "center" } }, "Đang tải danh sách khoá…"))
    );

    try {
      const keys = await api("/api/org/api-keys");
      tableBody.replaceChildren();

      if (!keys || keys.length === 0) {
        tableBody.appendChild(
          el(
            "tr",
            {},
            el(
              "td",
              { colSpan: 6, className: "muted", style: { textAlign: "center", padding: "24px" } },
              "Chưa có khoá API nào được tạo."
            )
          )
        );
        return;
      }

      keys.forEach((key) => {
        const isRevoked = Boolean(key.revoked_at);
        const statusBadge = el(
          "span",
          { className: `badge ${isRevoked ? "badge-voided" : "badge-completed"}` },
          isRevoked ? "Đã thu hồi" : "Hoạt động"
        );

        let actionBtn = "—";
        if (!isRevoked) {
          actionBtn = el(
            "button",
            {
              className: "button small danger",
              onClick: () => {
                confirmModal({
                  title: "Thu hồi khoá API",
                  message: `Bạn có chắc chắn muốn thu hồi khoá "${key.name}"? Mọi ứng dụng dùng khoá này sẽ bị từ chối kết nối ngay lập tức.`,
                  confirmText: "Thu hồi khoá",
                  danger: true,
                  onConfirm: async () => {
                    try {
                      await api(`/api/org/api-keys/${key.id}`, { method: "DELETE" });
                      toast("Đã thu hồi khoá API thành công.", "ok");
                      loadKeys();
                    } catch (err) {
                      toast(`Lỗi khi thu hồi: ${err.message}`, "err");
                    }
                  },
                });
              },
            },
            "Thu hồi"
          );
        }

        const tr = el(
          "tr",
          {},
          el("td", {}, el("strong", {}, key.name)),
          el("td", {}, el("code", {}, `${key.prefix}••••••••`)),
          el("td", { className: "muted" }, formatDate(key.created_at)),
          el("td", { className: "muted" }, key.last_used_at ? formatDate(key.last_used_at) : "Chưa sử dụng"),
          el("td", {}, statusBadge),
          el("td", { style: { textAlign: "right" } }, actionBtn)
        );

        tableBody.appendChild(tr);
      });
    } catch (err) {
      tableBody.replaceChildren(
        el("tr", {}, el("td", { colSpan: 6, className: "form-error", style: { textAlign: "center" } }, err.message))
      );
    }
  }

  function createApiKey() {
    promptModal({
      title: "Tạo khoá API mới",
      message: "Nhập tên gợi nhớ cho khoá API này (ví dụ: Production Server, ERP, CRM):",
      placeholder: "Tên khoá API...",
      confirmText: "Tạo khoá",
      onConfirm: async (name) => {
        if (!name) {
          toast("Vui lòng nhập tên cho khoá API.", "err");
          return;
        }
        try {
          const res = await api("/api/org/api-keys", {
            method: "POST",
            body: { name },
          });

          // Hiển thị Secret một lần duy nhất
          const secretInput = el("input", {
            type: "text",
            readOnly: true,
            value: res.secret,
            style: { width: "100%", fontFamily: "monospace", margin: "8px 0" },
          });

          showModal({
            title: "🔑 Khoá API đã được tạo",
            content: el(
              "div",
              {},
              el(
                "div",
                { className: "warning-banner" },
                "⚠️ Hãy lưu lại chuỗi khoá bí mật này ngay bây giờ. Bạn sẽ KHÔNG THỂ XEM LẠI nó sau khi đóng hộp thoại này!"
              ),
              el("label", { style: { display: "block", marginTop: "12px" } }, "Khoá bí mật (API Secret):"),
              secretInput
            ),
            actions: [
              {
                label: "📋 Sao chép khoá",
                primary: true,
                onClick: async () => {
                  await navigator.clipboard.writeText(res.secret);
                  toast("Đã sao chép khoá bí mật vào clipboard!", "ok");
                },
              },
              { label: "Đã lưu xong, Đóng" },
            ],
            onClose: () => loadKeys(),
          });
        } catch (err) {
          toast(`Không thể tạo khoá API: ${err.message}`, "err");
        }
      },
    });
  }

  await loadKeys();
}

/**
 * 2. Webhooks
 */
async function renderWebhooksSection(wrapper) {
  const sectionCard = el("div", { className: "card dev-section-card", style: { marginTop: "24px" } });
  wrapper.appendChild(sectionCard);

  const header = el(
    "div",
    { className: "section-header" },
    el("div", {},
      el("h3", { style: { margin: 0 } }, "Webhooks"),
      el("p", { className: "muted", style: { margin: "4px 0 0" } }, "Nhận thông báo HTTP POST tự động theo thời gian thực khi trạng thái tài liệu thay đổi.")
    ),
    el(
      "button",
      {
        className: "button primary",
        onClick: createWebhook,
      },
      "+ Thêm Webhook mới"
    )
  );

  const listContainer = el("div", { className: "webhooks-list", style: { marginTop: "16px" } });
  sectionCard.append(header, listContainer);

  async function loadWebhooks() {
    listContainer.replaceChildren(
      el("div", { className: "loading-state" }, "Đang tải danh sách webhook…")
    );

    try {
      const endpoints = await api("/api/org/webhooks");
      listContainer.replaceChildren();

      if (!endpoints || endpoints.length === 0) {
        listContainer.appendChild(
          el(
            "div",
            { className: "empty-state-card" },
            el("p", { className: "muted" }, "Chưa có webhook nào. Hãy tạo webhook để nhận sự kiện tự động.")
          )
        );
        return;
      }

      for (const ep of endpoints) {
        renderWebhookCard(ep, listContainer);
      }
    } catch (err) {
      listContainer.replaceChildren(
        el("div", { className: "form-error" }, `Lỗi tải webhook: ${err.message}`)
      );
    }
  }

  function renderWebhookCard(ep, container) {
    const isAllEvents = ep.events.includes("*");
    const eventsBadges = isAllEvents
      ? [el("span", { className: "badge badge-completed" }, "Tất cả sự kiện (*)")]
      : ep.events.map((ev) => el("span", { className: "badge", style: { marginRight: "4px" } }, ev));

    const statusBadge = el(
      "span",
      { className: `badge ${ep.enabled ? "badge-completed" : "badge-voided"}` },
      ep.enabled ? "Đang bật" : "Tắt"
    );

    const toggleBtn = el(
      "button",
      {
        className: "button small",
        onClick: async () => {
          toggleBtn.disabled = true;
          try {
            await api(`/api/org/webhooks/${ep.id}`, {
              method: "PATCH",
              body: { enabled: !ep.enabled },
            });
            toast(`Đã ${!ep.enabled ? "bật" : "tắt"} webhook.`, "ok");
            loadWebhooks();
          } catch (err) {
            toast(err.message, "err");
            toggleBtn.disabled = false;
          }
        },
      },
      ep.enabled ? "Tắt webhook" : "Bật webhook"
    );

    const testBtn = el(
      "button",
      {
        className: "button small",
        onClick: async () => {
          testBtn.disabled = true;
          testBtn.textContent = "Đang gửi…";
          try {
            await api(`/api/org/webhooks/${ep.id}/test`, { method: "POST" });
            toast("Đã xếp sự kiện thử nghiệm vào hàng đợi gửi!", "ok");
          } catch (err) {
            toast(`Lỗi gửi thử nghiệm: ${err.message}`, "err");
          } finally {
            testBtn.disabled = false;
            testBtn.textContent = "Gửi thử nghiệm (Test)";
          }
        },
      },
      "Gửi thử nghiệm (Test)"
    );

    const secretBtn = el(
      "button",
      {
        className: "button small",
        onClick: async () => {
          try {
            const detail = await api(`/api/org/webhooks/${ep.id}`);
            const secretInput = el("input", {
              type: "text",
              readOnly: true,
              value: detail.secret,
              style: { width: "100%", fontFamily: "monospace", margin: "8px 0" },
            });

            showModal({
              title: "Khoá bí mật Webhook (Secret)",
              content: el(
                "div",
                {},
                el("p", { className: "muted" }, "Secret dùng để tạo chữ ký HMAC-SHA256 trong header WebSigner-Signature:"),
                secretInput
              ),
              actions: [
                {
                  label: "📋 Sao chép Secret",
                  primary: true,
                  onClick: async () => {
                    await navigator.clipboard.writeText(detail.secret);
                    toast("Đã sao chép secret!", "ok");
                  },
                },
                {
                  label: "Đổi Secret mới",
                  danger: true,
                  onClick: async () => {
                    confirmModal({
                      title: "Đổi Secret Webhook",
                      message: "Bạn có chắc muốn đổi secret mới? Hệ thống nhận cũ sẽ không thể xác thực chữ ký cho đến khi bạn cập nhật.",
                      confirmText: "Đổi Secret",
                      danger: true,
                      onConfirm: async () => {
                        try {
                          const rotated = await api(`/api/org/webhooks/${ep.id}/rotate-secret`, { method: "POST" });
                          toast("Đã đổi secret mới thành công!", "ok");
                          secretInput.value = rotated.secret;
                        } catch (err) {
                          toast(err.message, "err");
                        }
                      },
                    });
                    return false;
                  },
                },
                { label: "Đóng" },
              ],
            });
          } catch (err) {
            toast(err.message, "err");
          }
        },
      },
      "🔑 Xem Secret"
    );

    const deliveriesBtn = el(
      "button",
      {
        className: "button small",
        onClick: () => viewDeliveries(ep),
      },
      "Lịch sử gửi (Deliveries)"
    );

    const deleteBtn = el(
      "button",
      {
        className: "button small danger",
        onClick: () => {
          confirmModal({
            title: "Xoá Webhook",
            message: `Bạn có chắc chắn muốn xoá webhook "${ep.url}"?`,
            confirmText: "Xoá Webhook",
            danger: true,
            onConfirm: async () => {
              try {
                await api(`/api/org/webhooks/${ep.id}`, { method: "DELETE" });
                toast("Đã xoá webhook.", "ok");
                loadWebhooks();
              } catch (err) {
                toast(err.message, "err");
              }
            },
          });
        },
      },
      "Xoá"
    );

    const card = el(
      "div",
      { className: "card webhook-card" },
      el(
        "div",
        { className: "webhook-header" },
        el("div", { className: "webhook-url-box" },
          statusBadge,
          el("code", { className: "webhook-url" }, ep.url)
        ),
        el("div", { className: "webhook-actions" }, toggleBtn, testBtn, secretBtn, deliveriesBtn, deleteBtn)
      ),
      ep.description ? el("p", { className: "webhook-desc muted" }, ep.description) : null,
      el("div", { className: "webhook-events-row" }, el("span", { className: "muted" }, "Sự kiện: "), ...eventsBadges)
    );

    container.appendChild(card);
  }

  function createWebhook() {
    const urlInput = el("input", {
      type: "url",
      required: true,
      placeholder: "https://api.yourdomain.com/webhooks/websigner",
      style: { width: "100%" },
    });
    const descInput = el("input", {
      type: "text",
      placeholder: "Hệ thống quản lý hợp đồng CRM...",
      style: { width: "100%" },
    });

    // Danh sách sự kiện do backend công bố ở /api/config — không tự chép tay.
    const eventsList = state.config?.webhook_events || [];

    const allEventsCheckbox = el("input", { type: "checkbox", checked: true });
    const eventCheckboxes = eventsList.map((ev) => ({
      name: ev,
      input: el("input", { type: "checkbox", checked: false, disabled: true }),
    }));

    allEventsCheckbox.addEventListener("change", () => {
      const isAll = allEventsCheckbox.checked;
      for (const { input } of eventCheckboxes) {
        input.disabled = isAll;
        if (isAll) input.checked = false;
      }
    });

    const form = el(
      "div",
      {},
      el("div", { className: "form-group" }, el("label", {}, "URL nhận webhook (POST) *"), urlInput),
      el("div", { className: "form-group" }, el("label", {}, "Mô tả"), descInput),
      el("div", { className: "form-group" },
        el("label", {}, "Chọn sự kiện gửi về:"),
        el("label", { className: "checkbox-label", style: { display: "block", margin: "6px 0" } },
          allEventsCheckbox,
          el("strong", { style: { marginLeft: "8px" } }, "Tất cả các sự kiện (*)")
        ),
        el(
          "div",
          { className: "events-checkbox-grid" },
          ...eventCheckboxes.map(({ name, input }) =>
            el("label", { className: "checkbox-label", style: { display: "flex", alignItems: "center", gap: "6px" } },
              input,
              el("span", { style: { fontSize: "12px" } }, name)
            )
          )
        )
      )
    );

    showModal({
      title: "Thêm Webhook mới",
      content: form,
      actions: [
        { label: "Huỷ" },
        {
          label: "Thêm Webhook",
          primary: true,
          onClick: async () => {
            const url = urlInput.value.trim();
            if (!url) {
              toast("Vui lòng nhập URL hợp lệ.", "err");
              return false;
            }

            let selectedEvents = ["*"];
            if (!allEventsCheckbox.checked) {
              selectedEvents = eventCheckboxes.filter((item) => item.input.checked).map((item) => item.name);
              if (selectedEvents.length === 0) {
                toast("Vui lòng chọn ít nhất một sự kiện.", "err");
                return false;
              }
            }

            try {
              const res = await api("/api/org/webhooks", {
                method: "POST",
                body: {
                  url,
                  description: descInput.value.trim() || null,
                  events: selectedEvents,
                },
              });

              toast("Đã tạo webhook thành công!", "ok");
              loadWebhooks();

              // Hiển thị secret
              showModal({
                title: "🔑 Khoá bí mật của Webhook",
                content: el(
                  "div",
                  {},
                  el("p", { className: "muted" }, "Đây là secret để bạn xác thực chữ ký gói tin gửi đến máy chủ của bạn:"),
                  el("input", {
                    type: "text",
                    readOnly: true,
                    value: res.secret,
                    style: { width: "100%", fontFamily: "monospace", margin: "8px 0" },
                  })
                ),
                actions: [
                  {
                    label: "📋 Sao chép Secret",
                    primary: true,
                    onClick: async () => {
                      await navigator.clipboard.writeText(res.secret);
                      toast("Đã sao chép secret!", "ok");
                    },
                  },
                  { label: "Đóng" },
                ],
              });
            } catch (err) {
              toast(`Không thể thêm webhook: ${err.message}`, "err");
              return false;
            }
          },
        },
      ],
    });
  }

  // Xem lịch sử gửi webhook (Deliveries)
  async function viewDeliveries(ep) {
    const tableBody = el("tbody");
    const deliveriesTable = el(
      "table",
      { className: "data-table" },
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", {}, "Sự kiện"),
          el("th", {}, "Trạng thái"),
          el("th", {}, "Lần thử"),
          el("th", {}, "HTTP Code"),
          el("th", {}, "Thời gian"),
          el("th", { style: { textAlign: "right" } }, "Thao tác")
        )
      ),
      tableBody
    );

    showModal({
      title: `Lịch sử gửi webhook: ${ep.url}`,
      content: el("div", { className: "table-responsive", style: { maxHeight: "400px", overflowY: "auto" } }, deliveriesTable),
      actions: [{ label: "Đóng", primary: true }],
    });

    tableBody.replaceChildren(
      el("tr", {}, el("td", { colSpan: 6, className: "muted", style: { textAlign: "center" } }, "Đang tải lịch sử…"))
    );

    try {
      const deliveries = await api(`/api/org/webhooks/${ep.id}/deliveries`);
      tableBody.replaceChildren();

      if (!deliveries || deliveries.length === 0) {
        tableBody.appendChild(
          el(
            "tr",
            {},
            el("td", { colSpan: 6, className: "muted", style: { textAlign: "center", padding: "20px" } }, "Chưa có lần gửi nào.")
          )
        );
        return;
      }

      deliveries.forEach((deliv) => {
        const isSucceeded = deliv.status === "succeeded";
        const statusBadge = el(
          "span",
          { className: `badge ${isSucceeded ? "badge-completed" : deliv.status === "failed" ? "badge-declined" : "badge-in_progress"}` },
          deliv.status
        );

        const viewPayloadBtn = el(
          "button",
          {
            className: "button small",
            onClick: () => {
              showModal({
                title: `Payload: ${deliv.event_type}`,
                content: el(
                  "div",
                  {},
                  deliv.last_error ? el("p", { className: "form-error" }, `Lỗi: ${deliv.last_error}`) : null,
                  el("pre", { style: { maxHeight: "350px", overflowY: "auto" } }, JSON.stringify(deliv.payload, null, 2))
                ),
                actions: [{ label: "Đóng", primary: true }],
              });
            },
          },
          "Payload"
        );

        let retryBtn = null;
        if (!isSucceeded) {
          retryBtn = el(
            "button",
            {
              className: "button small",
              onClick: async () => {
                retryBtn.disabled = true;
                try {
                  await api(`/api/org/webhooks/${ep.id}/deliveries/${deliv.id}/retry`, { method: "POST" });
                  toast("Đã xếp gửi lại webhook!", "ok");
                  viewDeliveries(ep);
                } catch (err) {
                  toast(`Không thể gửi lại: ${err.message}`, "err");
                  retryBtn.disabled = false;
                }
              },
            },
            "Gửi lại"
          );
        }

        const tr = el(
          "tr",
          {},
          el("td", {}, el("code", {}, deliv.event_type)),
          el("td", {}, statusBadge),
          el("td", {}, String(deliv.attempts)),
          el("td", {}, deliv.last_status_code ? String(deliv.last_status_code) : "—"),
          el("td", { className: "muted" }, formatDate(deliv.delivered_at || deliv.created_at)),
          el("td", { style: { textAlign: "right" } }, viewPayloadBtn, retryBtn ? el("span", { style: { marginLeft: "4px" } }, retryBtn) : null)
        );

        tableBody.appendChild(tr);
      });
    } catch (err) {
      tableBody.replaceChildren(
        el("tr", {}, el("td", { colSpan: 6, className: "form-error" }, err.message))
      );
    }
  }

  await loadWebhooks();
}

/**
 * 3. Nhúng trang ký (iframe)
 */
async function renderEmbedOriginsSection(wrapper) {
  const sectionCard = el("div", {
    className: "card dev-section-card",
    style: { marginTop: "24px" },
  });
  wrapper.appendChild(sectionCard);

  const header = el(
    "div",
    { className: "section-header" },
    el(
      "div",
      {},
      el("h3", { style: { margin: 0 } }, "Nhúng trang ký (iframe)"),
      el(
        "p",
        { className: "muted", style: { margin: "4px 0 0" } },
        "Cấu hình các Origin (giao thức + tên miền) được phép nhúng liên kết ký /s/<token> vào thẻ <iframe> trên hệ thống của bạn."
      )
    )
  );

  const errorBox = el("div", {
    className: "status err",
    style: { marginTop: "12px", display: "none" },
  });

  function showError(msg) {
    if (msg) {
      errorBox.textContent = msg;
      errorBox.style.display = "block";
    } else {
      errorBox.textContent = "";
      errorBox.style.display = "none";
    }
  }

  let origins = [...(state.me?.org?.embed_origins || [])];

  const originsContainer = el("div", { style: { marginTop: "16px" } });

  const inputNewOrigin = el("input", {
    type: "text",
    placeholder: "https://erp.partner.vn (chỉ gồm giao thức + tên miền, tối đa 10 origin)",
    style: { flex: "1", fontSize: "13px" },
    onKeyDown: (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        btnAddOrigin.click();
      }
    },
  });

  const btnAddOrigin = el(
    "button",
    {
      type: "button",
      className: "button",
      onClick: () => {
        showError("");
        const val = inputNewOrigin.value.trim().replace(/\/+$/, "");
        if (!val) {
          showError("Vui lòng nhập origin (dạng https://ten-mien.vn)");
          return;
        }
        if (origins.includes(val)) {
          showError(`Origin ${val} đã tồn tại trong danh sách`);
          return;
        }
        if (origins.length >= 10) {
          showError("Tối đa 10 origin được nhúng");
          return;
        }
        origins.push(val);
        inputNewOrigin.value = "";
        renderOriginsList();
      },
    },
    "+ Thêm origin"
  );

  const addRow = el(
    "div",
    { style: { display: "flex", gap: "8px", marginTop: "12px", alignItems: "center" } },
    inputNewOrigin,
    btnAddOrigin
  );

  const btnSaveOrigins = el(
    "button",
    {
      type: "button",
      className: "button primary",
      style: { marginTop: "16px" },
      onClick: async () => {
        showError("");
        btnSaveOrigins.disabled = true;
        btnSaveOrigins.textContent = "Đang lưu…";
        try {
          const res = await api("/api/org", {
            method: "PATCH",
            body: { embed_origins: origins },
          });
          origins = [...(res.embed_origins || [])];
          if (state.me?.org) {
            state.me.org.embed_origins = origins;
          }
          renderOriginsList();
          toast("Đã lưu danh sách origin nhúng iframe thành công!", "ok");
        } catch (err) {
          showError(err.message || "Lỗi khi lưu danh sách origin");
        } finally {
          btnSaveOrigins.disabled = false;
          btnSaveOrigins.textContent = "Lưu thay đổi";
        }
      },
    },
    "Lưu thay đổi"
  );

  function renderOriginsList() {
    originsContainer.replaceChildren();
    if (origins.length === 0) {
      originsContainer.appendChild(
        el(
          "p",
          { className: "muted", style: { fontStyle: "italic", margin: "8px 0" } },
          "Chưa cấu hình origin nào. Mặc định trang ký từ chối mọi yêu cầu nhúng (frame-ancestors 'none')."
        )
      );
      return;
    }

    const list = el("div", {
      style: { display: "flex", flexDirection: "column", gap: "6px" },
    });

    origins.forEach((orig, idx) => {
      const row = el(
        "div",
        {
          style: {
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "8px 12px",
            background: "rgba(255, 255, 255, 0.03)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius)",
          },
        },
        el("code", { style: { color: "var(--fg)", fontSize: "13px" } }, orig),
        el(
          "button",
          {
            type: "button",
            className: "btn-icon-del",
            title: "Xoá origin",
            onClick: () => {
              showError("");
              origins.splice(idx, 1);
              renderOriginsList();
            },
          },
          "✕"
        )
      );
      list.appendChild(row);
    });

    originsContainer.appendChild(list);
  }

  renderOriginsList();

  const explanation = el(
    "div",
    { style: { marginTop: "20px", fontSize: "13px", lineHeight: "1.6" } },
    el("h4", { style: { margin: "0 0 8px 0" } }, "Hướng dẫn & Lưu ý bảo mật:"),
    el(
      "ul",
      { style: { paddingLeft: "20px", margin: 0 }, className: "muted" },
      el(
        "li",
        {},
        el("strong", { style: { color: "var(--fg)" } }, "Chính sách CSP: "),
        "Web Signer bảo vệ trang ký bằng Content-Security-Policy: frame-ancestors. Chỉ các origin khai báo ở trên mới có thể nhúng liên kết ký /s/<token>."
      ),
      el(
        "li",
        { style: { marginTop: "4px" } },
        el("strong", { style: { color: "var(--fg)" } }, "Liên kết ký (signing_url): "),
        "Đường dẫn ký được sinh từ API phía máy chủ (server-side) khi tạo tài liệu hoặc lấy thông tin người nhận — ",
        el("em", { style: { color: "var(--fg)" } }, "tuyệt đối không tự ghép đường dẫn ở phía client"),
        "."
      ),
      el(
        "li",
        { style: { marginTop: "4px" } },
        el("strong", { style: { color: "var(--fg)" } }, "Phương thức ký trong iframe: "),
        "Ký số bằng USB token trong iframe thường yêu cầu người dùng nhập mã ghép cặp (pairing code) do các trình duyệt hiện đại chặn cookie bên thứ ba trong iframe; trong khi ",
        el("strong", { style: { color: "var(--fg)" } }, "Ký tay hoạt động hoàn chỉnh trực tiếp"),
        "."
      ),
      el(
        "li",
        { style: { marginTop: "4px" } },
        el("strong", { style: { color: "var(--fg)" } }, "Sự kiện postMessage: "),
        "Trang ký tự động gửi sự kiện (websigner.loaded, websigner.signed, websigner.approved, websigner.declined) tới đúng các origin được cấp phép."
      )
    )
  );

  const iframeSnippet = `<iframe src="{signing_url}" allow="clipboard-write" style="width:100%;height:900px;border:0"></iframe>`;

  const originOfSigner = window.location.origin;
  const listenerSnippet = `// Lắng nghe sự kiện từ Web Signer trong trang cha
window.addEventListener("message", (event) => {
  // 1. Kiểm tra nguồn gửi đúng từ Web Signer
  if (event.origin !== "${originOfSigner}") return;

  // 2. Kiểm tra định dạng dữ liệu
  if (event.data?.source !== "websigner") return;

  const { type, document_id, recipient_id, document_status } = event.data;
  console.log("Web Signer event:", type, { document_id, recipient_id, document_status });

  switch (type) {
    case "websigner.loaded":
      console.log("Trang ký đã nạp xong:", document_id);
      break;
    case "websigner.signed":
      console.log("Người nhận đã ký thành công:", recipient_id);
      break;
    case "websigner.approved":
      console.log("Người nhận đã duyệt tài liệu:", recipient_id);
      break;
    case "websigner.declined":
      console.log("Người nhận đã từ chối tài liệu:", recipient_id);
      break;
  }
});`;

  function createSnippetBox(title, codeText) {
    const box = el("div", { style: { marginTop: "16px" } });
    const top = el(
      "div",
      { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" } },
      el("strong", { style: { fontSize: "13px" } }, title),
      el(
        "button",
        {
          type: "button",
          className: "button small",
          onClick: async () => {
            try {
              await navigator.clipboard.writeText(codeText);
              toast("Đã sao chép đoạn mã!", "ok");
            } catch {
              promptModal({
                title: "Sao chép đoạn mã",
                message: "Sao chép mã dưới đây:",
                defaultValue: codeText,
              });
            }
          },
        },
        "📋 Sao chép"
      )
    );
    const pre = el("pre", { className: "code-block" }, codeText);
    box.append(top, pre);
    return box;
  }

  sectionCard.append(
    header,
    errorBox,
    originsContainer,
    addRow,
    btnSaveOrigins,
    explanation,
    createSnippetBox("Mã HTML nhúng iframe:", iframeSnippet),
    createSnippetBox("Mã JavaScript lắng nghe sự kiện (Parent Listener):", listenerSnippet)
  );
}

/**
 * 3. Hướng dẫn Bắt đầu nhanh (Quickstart)
 */
function renderQuickstartSection(wrapper) {
  const origin = window.location.origin;

  const createDocSnippet = `curl -X POST "${origin}/v1/documents" \\
  -H "Authorization: Bearer <API_SECRET>" \\
  -F "file=@hop-dong.pdf;type=application/pdf" \\
  -F 'data={
    "title": "Hợp đồng dịch vụ 2026",
    "recipients": [
      {
        "name": "Nguyễn Văn A",
        "email": "a.nguyen@doitac.vn",
        "role": "signer",
        "order": 1,
        "field": { "page": 0, "box": [100, 100, 265, 190] }
      }
    ],
    "send": true
  }'`;

  const getDocSnippet = `curl -X GET "${origin}/v1/documents/doc_abc123" \\
  -H "Authorization: Bearer <API_SECRET>"`;

  const webhookVerifyNodeSnippet = `// Node.js Express Webhook verification
const crypto = require("crypto");

function verifyWebhook(req, res, next) {
  const sigHeader = req.headers["websigner-signature"]; // t=1730000000,v1=abcdef...
  if (!sigHeader) return res.status(401).send("Missing signature");

  const parts = Object.fromEntries(sigHeader.split(",").map(p => p.split("=")));
  const timestamp = parts.t;
  const expectedSig = parts.v1;

  // Tính HMAC-SHA256(secret, "\${timestamp}.\${rawBody}")
  const computed = crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(\`\${timestamp}.\${req.rawBody}\`)
    .digest("hex");

  if (computed !== expectedSig) {
    return res.status(403).send("Invalid signature");
  }
  next();
}`;

  const webhookVerifyPythonSnippet = `# Python FastAPI/Flask Webhook verification
import hmac, hashlib

def verify_signature(secret: str, header_value: str, raw_body: bytes) -> bool:
    # header: WebSigner-Signature: t=1730000000,v1=...
    parts = dict(kv.split("=", 1) for kv in header_value.split(","))
    t = parts.get("t", "")
    sig = parts.get("v1", "")
    payload = f"{t}.".encode("utf-8") + raw_body
    computed = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, sig)`;

  const card = el(
    "div",
    { className: "card dev-section-card", style: { marginTop: "24px" } },
    el(
      "div",
      { className: "section-header" },
      el("div", {},
        el("h3", { style: { margin: 0 } }, "Bắt đầu nhanh (Quick Start)"),
        el("p", { className: "muted", style: { margin: "4px 0 0" } }, "Các ví dụ lệnh gọi API và xác thực webhook tiêu chuẩn.")
      ),
      el(
        "div",
        {},
        el("a", { href: "/docs", target: "_blank", rel: "noopener", className: "button", style: { marginRight: "8px" } }, "📖 Swagger API Docs"),
        el("a", { href: "/redoc", target: "_blank", rel: "noopener", className: "button" }, "ReDoc")
      )
    ),

    el("h4", { style: { marginTop: "20px" } }, "1. Tạo và gửi tài liệu qua cURL:"),
    el("pre", { className: "code-block" }, createDocSnippet),

    el("h4", { style: { marginTop: "20px" } }, "2. Lấy thông tin tài liệu và liên kết ký:"),
    el("pre", { className: "code-block" }, getDocSnippet),

    el("h4", { style: { marginTop: "20px" } }, "3. Xác thực chữ ký Webhook (HMAC-SHA256):"),
    el("p", { className: "muted" }, "Mỗi webhook được gửi kèm header WebSigner-Signature: t=<timestamp>,v1=<hex_hmac>. Chữ ký được tính từ ${t}.${rawBody}."),
    el("pre", { className: "code-block" }, webhookVerifyNodeSnippet),
    el("pre", { className: "code-block", style: { marginTop: "12px" } }, webhookVerifyPythonSnippet)
  );

  wrapper.appendChild(card);
}
