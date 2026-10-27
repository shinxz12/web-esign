/**
 * Quản lý thành viên tổ chức (#/members)
 * Xem danh sách thành viên, mời thành viên mới, đổi vai trò, và xoá thành viên.
 */

import {
  api,
  confirmModal,
  el,
  formatDate,
  ROLE_LABELS,
  showModal,
  state,
  toast,
} from "./api.js";

export async function renderMembers(container) {
  container.replaceChildren();

  const isAdminOrOwner =
    state.me?.user?.role === "owner" || state.me?.user?.role === "admin";

  const heading = el("h2", { className: "page-title" }, "Thành viên tổ chức");
  const subtext = el(
    "p",
    { className: "muted" },
    "Danh sách các tài khoản thuộc tổ chức của bạn và phân quyền truy cập."
  );

  const inviteBtn = isAdminOrOwner
    ? el(
        "button",
        {
          className: "button primary",
          onClick: inviteMember,
        },
        "+ Mời thành viên mới"
      )
    : null;

  const header = el(
    "div",
    { className: "page-header" },
    el("div", {}, heading, subtext),
    inviteBtn
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
        el("th", {}, "Họ và tên"),
        el("th", {}, "Email"),
        el("th", {}, "Vai trò"),
        el("th", {}, "Trạng thái"),
        el("th", {}, "Ngày tham gia"),
        el("th", { style: { textAlign: "right" } }, "Thao tác")
      )
    ),
    tableBody
  );

  const tableCard = el(
    "div",
    { className: "card content-card", style: { marginTop: "16px" } },
    el("div", { className: "table-responsive" }, table)
  );

  container.append(header, tableCard);

  async function loadMembers() {
    tableBody.replaceChildren(
      el(
        "tr",
        {},
        el(
          "td",
          { colSpan: 6, className: "muted", style: { textAlign: "center" } },
          "Đang tải danh sách thành viên…"
        )
      )
    );

    try {
      const members = await api("/api/org/members");
      tableBody.replaceChildren();

      if (!members || members.length === 0) {
        tableBody.appendChild(
          el(
            "tr",
            {},
            el(
              "td",
              { colSpan: 6, className: "muted", style: { textAlign: "center", padding: "24px" } },
              "Chưa có thành viên nào."
            )
          )
        );
        return;
      }

      members.forEach((m) => {
        const isOwner = m.role === "owner";
        const isSelf = m.id === state.me?.user?.id;
        const isPending = Boolean(m.pending);

        const roleText = ROLE_LABELS[m.role] || m.role;
        const roleBadge = el(
          "span",
          { className: `badge ${isOwner ? "badge-owner" : m.role === "admin" ? "badge-completed" : "badge-draft"}` },
          roleText
        );

        const statusBadge = el(
          "span",
          { className: `badge ${isPending ? "badge-in_progress" : "badge-completed"}` },
          isPending ? "Chờ chấp nhận" : "Hoạt động"
        );

        // Nút thao tác
        const actionsTd = el("td", { style: { textAlign: "right" } });

        if (isAdminOrOwner && !isOwner && !isSelf) {
          // Nút đổi vai trò (admin <-> member)
          const newRole = m.role === "admin" ? "member" : "admin";
          const changeRoleBtn = el(
            "button",
            {
              className: "button small",
              style: { marginRight: "6px" },
              onClick: () => {
                confirmModal({
                  title: "Thay đổi vai trò",
                  message: `Bạn có muốn đổi vai trò của ${m.name} thành "${ROLE_LABELS[newRole]}"?`,
                  confirmText: "Đổi vai trò",
                  onConfirm: async () => {
                    try {
                      await api(`/api/org/members/${m.id}`, {
                        method: "PATCH",
                        body: { role: newRole },
                      });
                      toast("Đã cập nhật vai trò thành viên.", "ok");
                      loadMembers();
                    } catch (err) {
                      toast(`Lỗi cập nhật vai trò: ${err.message}`, "err");
                    }
                  },
                });
              },
            },
            newRole === "admin" ? "Thăng cấp Admin" : "Chuyển thành Member"
          );

          // Nút xoá thành viên
          const removeBtn = el(
            "button",
            {
              className: "button small danger",
              onClick: () => {
                confirmModal({
                  title: "Xoá thành viên",
                  message: `Bạn có chắc chắn muốn xoá ${m.name} (${m.email}) khỏi tổ chức?`,
                  confirmText: "Xoá thành viên",
                  danger: true,
                  onConfirm: async () => {
                    try {
                      await api(`/api/org/members/${m.id}`, { method: "DELETE" });
                      toast("Đã xoá thành viên khỏi tổ chức.", "ok");
                      loadMembers();
                    } catch (err) {
                      toast(`Lỗi khi xoá: ${err.message}`, "err");
                    }
                  },
                });
              },
            },
            "Xoá"
          );

          actionsTd.append(changeRoleBtn, removeBtn);
        } else if (isOwner) {
          actionsTd.appendChild(
            el("span", { className: "muted", style: { fontSize: "12px" } }, "🔒 Chủ sở hữu")
          );
        } else {
          actionsTd.textContent = "—";
        }

        const tr = el(
          "tr",
          {},
          el("td", {}, el("strong", {}, m.name), isSelf ? el("span", { className: "badge badge-draft", style: { marginLeft: "6px" } }, "Bạn") : null),
          el("td", {}, m.email),
          el("td", {}, roleBadge),
          el("td", {}, statusBadge),
          el("td", { className: "muted" }, formatDate(m.created_at)),
          actionsTd
        );

        tableBody.appendChild(tr);
      });
    } catch (err) {
      tableBody.replaceChildren(
        el(
          "tr",
          {},
          el("td", { colSpan: 6, className: "form-error", style: { textAlign: "center" } }, err.message)
        )
      );
    }
  }

  function inviteMember() {
    const emailInput = el("input", {
      type: "email",
      required: true,
      placeholder: "dongnghiep@congty.vn",
      style: { width: "100%" },
    });
    const nameInput = el("input", {
      type: "text",
      required: true,
      placeholder: "Nguyễn Văn B",
      style: { width: "100%" },
    });
    const roleSelect = el(
      "select",
      { style: { width: "100%" } },
      el("option", { value: "member", selected: true }, "Thành viên (Member)"),
      el("option", { value: "admin" }, "Quản trị viên (Admin)")
    );

    const form = el(
      "div",
      {},
      el("div", { className: "form-group" }, el("label", {}, "Email thành viên *"), emailInput),
      el("div", { className: "form-group" }, el("label", {}, "Họ và tên *"), nameInput),
      el("div", { className: "form-group" }, el("label", {}, "Vai trò trong tổ chức"), roleSelect)
    );

    showModal({
      title: "Mời thành viên mới",
      content: form,
      actions: [
        { label: "Huỷ" },
        {
          label: "Gửi lời mời",
          primary: true,
          onClick: async () => {
            const email = emailInput.value.trim();
            const name = nameInput.value.trim();
            const role = roleSelect.value;

            if (!email || !name) {
              toast("Vui lòng nhập đầy đủ Email và Họ tên.", "err");
              return false;
            }

            try {
              const res = await api("/api/org/members", {
                method: "POST",
                body: { email, name, role },
              });

              toast("Đã tạo lời mời thành công!", "ok");
              loadMembers();

              // Hiển thị liên kết lời mời để sao chép
              const inviteUrl = res.invite_url;
              const linkInput = el("input", {
                type: "text",
                readOnly: true,
                value: inviteUrl,
                style: { width: "100%", fontFamily: "monospace", margin: "8px 0" },
              });

              showModal({
                title: "✉ Liên kết mời tham gia",
                content: el(
                  "div",
                  {},
                  el(
                    "p",
                    { className: "muted" },
                    `Thành viên ${name} (${email}) đã được thêm vào danh sách chờ. Hãy gửi liên kết này để họ kích hoạt tài khoản:`
                  ),
                  linkInput
                ),
                actions: [
                  {
                    label: "📋 Sao chép liên kết",
                    primary: true,
                    onClick: async () => {
                      await navigator.clipboard.writeText(inviteUrl);
                      toast("Đã sao chép liên kết lời mời!", "ok");
                    },
                  },
                  { label: "Đóng" },
                ],
              });
            } catch (err) {
              toast(`Không thể mời thành viên: ${err.message}`, "err");
              return false;
            }
          },
        },
      ],
    });
  }

  await loadMembers();
}
