/**
 * Quản lý Tài khoản & Tổ chức (#/account)
 * Thông tin cá nhân, đổi mật khẩu, và đổi tên tổ chức (Admin/Owner).
 */

import { api, el, formatDate, ROLE_LABELS, state, toast } from "./api.js";

export function renderAccount(container) {
  container.replaceChildren();

  const user = state.me?.user;
  const org = state.me?.org;
  const isAdminOrOwner = user?.role === "owner" || user?.role === "admin";

  const heading = el("h2", { className: "page-title" }, "Tài khoản & Thiết lập");
  const subtext = el(
    "p",
    { className: "muted" },
    "Quản lý thông tin tài khoản cá nhân, bảo mật mật khẩu và tên doanh nghiệp."
  );

  const wrapper = el("div", { className: "account-sections-wrapper" });
  container.append(el("div", { className: "page-header" }, el("div", {}, heading, subtext)), wrapper);

  // 1. Thông tin cá nhân
  const profileCard = el(
    "div",
    { className: "card content-card" },
    el("h3", { style: { marginTop: 0 } }, "Thông tin cá nhân"),
    el(
      "div",
      { className: "profile-details-grid" },
      el("div", { className: "profile-row" }, el("span", { className: "muted" }, "Họ và tên:"), el("strong", {}, user?.name || "—")),
      el("div", { className: "profile-row" }, el("span", { className: "muted" }, "Email tài khoản:"), el("span", {}, user?.email || "—")),
      el(
        "div",
        { className: "profile-row" },
        el("span", { className: "muted" }, "Vai trò:"),
        el("span", { className: `badge ${user?.role === "owner" ? "badge-owner" : user?.role === "admin" ? "badge-completed" : "badge-draft"}` }, ROLE_LABELS[user?.role] || user?.role)
      ),
      el("div", { className: "profile-row" }, el("span", { className: "muted" }, "Ngày tạo:"), el("span", {}, formatDate(user?.created_at))),
      el("div", { className: "profile-row" }, el("span", { className: "muted" }, "Tổ chức:"), el("strong", {}, org?.name || "—"))
    )
  );

  wrapper.appendChild(profileCard);

  // 2. Đổi tên tổ chức (Admin / Owner only)
  if (isAdminOrOwner) {
    const orgNameInput = el("input", {
      type: "text",
      required: true,
      value: org?.name || "",
      style: { maxWidth: "400px" },
    });
    const saveOrgBtn = el("button", { type: "submit", className: "primary" }, "Lưu tên tổ chức");
    const orgErrorMsg = el("div", { className: "form-error", hidden: true });

    const orgForm = el(
      "form",
      {
        onSubmit: async (e) => {
          e.preventDefault();
          orgErrorMsg.hidden = true;
          const newName = orgNameInput.value.trim();
          if (!newName) {
            orgErrorMsg.textContent = "Tên tổ chức không được để trống.";
            orgErrorMsg.hidden = false;
            return;
          }

          saveOrgBtn.disabled = true;
          saveOrgBtn.textContent = "Đang lưu…";

          try {
            const updatedOrg = await api("/api/org", {
              method: "PATCH",
              body: { name: newName },
            });
            state.me.org = updatedOrg;
            toast("Đã đổi tên tổ chức thành công!", "ok");

            // Cập nhật tên tổ chức trên topbar
            const topbarOrg = document.getElementById("topbar-org-name");
            if (topbarOrg) topbarOrg.textContent = updatedOrg.name;
          } catch (err) {
            orgErrorMsg.textContent = err.message;
            orgErrorMsg.hidden = false;
          } finally {
            saveOrgBtn.disabled = false;
            saveOrgBtn.textContent = "Lưu tên tổ chức";
          }
        },
      },
      el("div", { className: "form-group" }, el("label", {}, "Tên doanh nghiệp / Tổ chức"), orgNameInput),
      orgErrorMsg,
      el("div", { style: { marginTop: "12px" } }, saveOrgBtn)
    );

    const orgCard = el(
      "div",
      { className: "card content-card", style: { marginTop: "24px" } },
      el("h3", { style: { marginTop: 0 } }, "Cài đặt tổ chức"),
      el("p", { className: "muted" }, "Tên tổ chức hiển thị trên các tài liệu ký và thông báo gửi đến người nhận."),
      orgForm
    );

    wrapper.appendChild(orgCard);
  }

  // 3. Đổi mật khẩu
  const currentPasswordInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Nhập mật khẩu hiện tại",
    style: { maxWidth: "400px" },
    autocomplete: "current-password",
  });
  const newPasswordInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Tối thiểu 10 ký tự",
    style: { maxWidth: "400px" },
    autocomplete: "new-password",
  });
  const confirmPasswordInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Nhập lại mật khẩu mới",
    style: { maxWidth: "400px" },
    autocomplete: "new-password",
  });

  const changePassBtn = el("button", { type: "submit", className: "primary" }, "Đổi mật khẩu");
  const passErrorMsg = el("div", { className: "form-error", hidden: true });

  const passForm = el(
    "form",
    {
      onSubmit: async (e) => {
        e.preventDefault();
        passErrorMsg.hidden = true;

        if (newPasswordInput.value.length < 10) {
          passErrorMsg.textContent = "Mật khẩu mới phải có ít nhất 10 ký tự.";
          passErrorMsg.hidden = false;
          return;
        }

        if (newPasswordInput.value !== confirmPasswordInput.value) {
          passErrorMsg.textContent = "Mật khẩu xác nhận không khớp.";
          passErrorMsg.hidden = false;
          return;
        }

        changePassBtn.disabled = true;
        changePassBtn.textContent = "Đang đổi…";

        try {
          await api("/api/auth/password", {
            method: "POST",
            body: {
              current_password: currentPasswordInput.value,
              new_password: newPasswordInput.value,
            },
          });
          toast("Đã đổi mật khẩu thành công! Vui lòng đăng nhập lại.", "ok", 5000);
          state.me = null;
          location.hash = "#/login";
        } catch (err) {
          passErrorMsg.textContent = err.message;
          passErrorMsg.hidden = false;
          changePassBtn.disabled = false;
          changePassBtn.textContent = "Đổi mật khẩu";
        }
      },
    },
    el("div", { className: "form-group" }, el("label", {}, "Mật khẩu hiện tại"), currentPasswordInput),
    el("div", { className: "form-group" }, el("label", {}, "Mật khẩu mới (tối thiểu 10 ký tự)"), newPasswordInput),
    el("div", { className: "form-group" }, el("label", {}, "Xác nhận mật khẩu mới"), confirmPasswordInput),
    passErrorMsg,
    el("div", { style: { marginTop: "12px" } }, changePassBtn)
  );

  const passCard = el(
    "div",
    { className: "card content-card", style: { marginTop: "24px" } },
    el("h3", { style: { marginTop: 0 } }, "Bảo mật & Mật khẩu"),
    el("p", { className: "muted" }, "Sau khi đổi mật khẩu, mọi phiên đăng nhập trên các thiết bị khác sẽ tự động đăng xuất."),
    passForm
  );

  wrapper.appendChild(passCard);
}
