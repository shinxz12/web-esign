/**
 * Màn hình xác thực: Đăng nhập, Đăng ký, Quên mật khẩu, Đặt lại mật khẩu, Nhận lời mời.
 */

import { api, el, state, toast } from "./api.js";

/**
 * Màn hình Đăng nhập
 */
export function renderLogin(container) {
  container.replaceChildren();

  const emailInput = el("input", {
    type: "email",
    required: true,
    placeholder: "ten@congty.vn",
    autocomplete: "username",
  });
  const passwordInput = el("input", {
    type: "password",
    required: true,
    placeholder: "••••••••",
    autocomplete: "current-password",
  });
  const submitBtn = el("button", { type: "submit", className: "primary full-width" }, "Đăng nhập");
  const errorMsg = el("div", { className: "form-error", hidden: true });

  const form = el(
    "form",
    {
      className: "auth-form",
      onSubmit: async (e) => {
        e.preventDefault();
        errorMsg.hidden = true;
        submitBtn.disabled = true;
        submitBtn.textContent = "Đang xử lý…";

        try {
          const res = await api("/api/auth/login", {
            method: "POST",
            body: {
              email: emailInput.value.trim(),
              password: passwordInput.value,
            },
          });
          state.me = res;
          state.csrfToken = res.csrf_token;
          toast(`Xin chào, ${res.user.name}!`, "ok");
          location.hash = "#/documents";
        } catch (err) {
          errorMsg.textContent = err.message;
          errorMsg.hidden = false;
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = "Đăng nhập";
        }
      },
    },
    el("div", { className: "form-group" }, el("label", {}, "Email công việc"), emailInput),
    el("div", { className: "form-group" }, el("label", {}, "Mật khẩu"), passwordInput),
    errorMsg,
    submitBtn
  );

  const links = el("div", { className: "auth-links" });

  if (state.config?.signup_enabled) {
    links.appendChild(
      el(
        "p",
        {},
        "Chưa có tài khoản tổ chức? ",
        el("a", { href: "#/register" }, "Đăng ký ngay")
      )
    );
  }

  if (state.config?.email_enabled) {
    links.appendChild(
      el("p", {}, el("a", { href: "#/forgot" }, "Quên mật khẩu?"))
    );
  }

  const card = el(
    "div",
    { className: "auth-card" },
    el("div", { className: "auth-header" },
      el("h2", {}, "Đăng nhập Web Signer"),
      el("p", { className: "muted" }, "Nền tảng ký hợp đồng điện tử doanh nghiệp")
    ),
    form,
    links
  );

  container.appendChild(el("div", { className: "auth-container" }, card));
  setTimeout(() => emailInput.focus(), 50);
}

/**
 * Màn hình Đăng ký
 */
export function renderRegister(container) {
  container.replaceChildren();

  if (!state.config?.signup_enabled) {
    container.appendChild(
      el(
        "div",
        { className: "auth-container" },
        el(
          "div",
          { className: "auth-card" },
          el("h2", {}, "Đăng ký tài khoản"),
          el("p", { className: "muted" }, "Máy chủ này hiện không mở đăng ký tự do."),
          el("p", {}, el("a", { href: "#/login", className: "button primary" }, "Quay lại Đăng nhập"))
        )
      )
    );
    return;
  }

  const orgInput = el("input", {
    type: "text",
    required: true,
    placeholder: "Công ty Cổ phần ABC",
  });
  const nameInput = el("input", {
    type: "text",
    required: true,
    placeholder: "Nguyễn Văn A",
    autocomplete: "name",
  });
  const emailInput = el("input", {
    type: "email",
    required: true,
    placeholder: "a.nguyen@congty.vn",
    autocomplete: "email",
  });
  const passwordInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Tối thiểu 10 ký tự",
    autocomplete: "new-password",
  });
  const submitBtn = el("button", { type: "submit", className: "primary full-width" }, "Tạo tài khoản tổ chức");
  const errorMsg = el("div", { className: "form-error", hidden: true });

  const form = el(
    "form",
    {
      className: "auth-form",
      onSubmit: async (e) => {
        e.preventDefault();
        errorMsg.hidden = true;

        if (passwordInput.value.length < 10) {
          errorMsg.textContent = "Mật khẩu phải có độ dài từ 10 ký tự trở lên";
          errorMsg.hidden = false;
          return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Đang tạo tài khoản…";

        try {
          const res = await api("/api/auth/register", {
            method: "POST",
            body: {
              org_name: orgInput.value.trim(),
              name: nameInput.value.trim(),
              email: emailInput.value.trim(),
              password: passwordInput.value,
            },
          });
          state.me = res;
          state.csrfToken = res.csrf_token;
          toast("Đăng ký tổ chức thành công!", "ok");
          location.hash = "#/documents";
        } catch (err) {
          errorMsg.textContent = err.message;
          errorMsg.hidden = false;
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = "Tạo tài khoản tổ chức";
        }
      },
    },
    el("div", { className: "form-group" }, el("label", {}, "Tên doanh nghiệp / Tổ chức"), orgInput),
    el("div", { className: "form-group" }, el("label", {}, "Họ và tên của bạn"), nameInput),
    el("div", { className: "form-group" }, el("label", {}, "Email công việc"), emailInput),
    el("div", { className: "form-group" }, el("label", {}, "Mật khẩu"), passwordInput),
    errorMsg,
    submitBtn
  );

  const card = el(
    "div",
    { className: "auth-card" },
    el("div", { className: "auth-header" },
      el("h2", {}, "Đăng ký Web Signer"),
      el("p", { className: "muted" }, "Khởi tạo tổ chức mới với gói Miễn phí")
    ),
    form,
    el(
      "div",
      { className: "auth-links" },
      el("p", {}, "Đã có tài khoản? ", el("a", { href: "#/login" }, "Đăng nhập"))
    )
  );

  container.appendChild(el("div", { className: "auth-container" }, card));
  setTimeout(() => orgInput.focus(), 50);
}

/**
 * Màn hình Quên mật khẩu
 */
export function renderForgot(container) {
  container.replaceChildren();

  if (!state.config?.email_enabled) {
    container.appendChild(
      el(
        "div",
        { className: "auth-container" },
        el(
          "div",
          { className: "auth-card" },
          el("h2", {}, "Quên mật khẩu"),
          el("p", { className: "muted" }, "Chức năng gửi email chưa được kích hoạt trên hệ thống."),
          el("p", {}, el("a", { href: "#/login", className: "button primary" }, "Quay lại Đăng nhập"))
        )
      )
    );
    return;
  }

  const emailInput = el("input", {
    type: "email",
    required: true,
    placeholder: "ten@congty.vn",
  });
  const submitBtn = el("button", { type: "submit", className: "primary full-width" }, "Gửi liên kết khôi phục");
  const errorMsg = el("div", { className: "form-error", hidden: true });
  const successMsg = el("div", { className: "form-success", hidden: true });

  const form = el(
    "form",
    {
      className: "auth-form",
      onSubmit: async (e) => {
        e.preventDefault();
        errorMsg.hidden = true;
        successMsg.hidden = true;
        submitBtn.disabled = true;
        submitBtn.textContent = "Đang gửi…";

        try {
          await api("/api/auth/forgot", {
            method: "POST",
            body: { email: emailInput.value.trim() },
          });
          successMsg.textContent =
            "Nếu email đã đăng ký trên hệ thống, chúng tôi đã gửi liên kết đặt lại mật khẩu. Vui lòng kiểm tra hộp thư.";
          successMsg.hidden = false;
          form.querySelector(".form-group").hidden = true;
          submitBtn.hidden = true;
        } catch (err) {
          errorMsg.textContent = err.message;
          errorMsg.hidden = false;
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = "Gửi liên kết khôi phục";
        }
      },
    },
    el("div", { className: "form-group" }, el("label", {}, "Email đã đăng ký"), emailInput),
    errorMsg,
    successMsg,
    submitBtn
  );

  const card = el(
    "div",
    { className: "auth-card" },
    el("div", { className: "auth-header" },
      el("h2", {}, "Quên mật khẩu"),
      el("p", { className: "muted" }, "Nhập email của bạn để nhận liên kết đặt lại mật khẩu")
    ),
    form,
    el(
      "div",
      { className: "auth-links" },
      el("p", {}, el("a", { href: "#/login" }, "← Quay lại Đăng nhập"))
    )
  );

  container.appendChild(el("div", { className: "auth-container" }, card));
  setTimeout(() => emailInput.focus(), 50);
}

/**
 * Màn hình Đặt lại mật khẩu qua token
 */
export function renderReset(container, query = {}) {
  container.replaceChildren();
  const token = query.t;

  if (!token) {
    container.appendChild(
      el(
        "div",
        { className: "auth-container" },
        el(
          "div",
          { className: "auth-card" },
          el("h2", {}, "Đặt lại mật khẩu"),
          el("p", { className: "form-error" }, "Liên kết không hợp lệ hoặc thiếu mã xác thực (token)."),
          el("p", {}, el("a", { href: "#/login", className: "button primary" }, "Đến trang Đăng nhập"))
        )
      )
    );
    return;
  }

  const passwordInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Tối thiểu 10 ký tự",
  });
  const confirmInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Nhập lại mật khẩu mới",
  });
  const submitBtn = el("button", { type: "submit", className: "primary full-width" }, "Cập nhật mật khẩu");
  const errorMsg = el("div", { className: "form-error", hidden: true });

  const form = el(
    "form",
    {
      className: "auth-form",
      onSubmit: async (e) => {
        e.preventDefault();
        errorMsg.hidden = true;

        if (passwordInput.value.length < 10) {
          errorMsg.textContent = "Mật khẩu phải có độ dài từ 10 ký tự trở lên";
          errorMsg.hidden = false;
          return;
        }

        if (passwordInput.value !== confirmInput.value) {
          errorMsg.textContent = "Mật khẩu xác nhận không trùng khớp";
          errorMsg.hidden = false;
          return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Đang lưu…";

        try {
          await api("/api/auth/reset", {
            method: "POST",
            body: {
              token,
              password: passwordInput.value,
            },
          });
          toast("Đặt lại mật khẩu thành công! Vui lòng đăng nhập.", "ok");
          location.hash = "#/login";
        } catch (err) {
          errorMsg.textContent = err.message;
          errorMsg.hidden = false;
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = "Cập nhật mật khẩu";
        }
      },
    },
    el("div", { className: "form-group" }, el("label", {}, "Mật khẩu mới"), passwordInput),
    el("div", { className: "form-group" }, el("label", {}, "Xác nhận mật khẩu mới"), confirmInput),
    errorMsg,
    submitBtn
  );

  const card = el(
    "div",
    { className: "auth-card" },
    el("div", { className: "auth-header" },
      el("h2", {}, "Đặt lại mật khẩu"),
      el("p", { className: "muted" }, "Tạo mật khẩu an toàn mới cho tài khoản của bạn")
    ),
    form
  );

  container.appendChild(el("div", { className: "auth-container" }, card));
  setTimeout(() => passwordInput.focus(), 50);
}

/**
 * Màn hình Nhận lời mời tham gia tổ chức
 */
export async function renderInvite(container, query = {}) {
  container.replaceChildren();
  const token = query.t;

  if (!token) {
    container.appendChild(
      el(
        "div",
        { className: "auth-container" },
        el(
          "div",
          { className: "auth-card" },
          el("h2", {}, "Lời mời tham gia"),
          el("p", { className: "form-error" }, "Liên kết không hợp lệ hoặc thiếu mã lời mời."),
          el("p", {}, el("a", { href: "#/login", className: "button primary" }, "Đến trang Đăng nhập"))
        )
      )
    );
    return;
  }

  const loading = el(
    "div",
    { className: "auth-container" },
    el("div", { className: "auth-card" }, el("p", { className: "muted" }, "Đang kiểm tra thông tin lời mời…"))
  );
  container.appendChild(loading);

  let inviteInfo = null;
  try {
    inviteInfo = await api(`/api/auth/invite/${encodeURIComponent(token)}`);
  } catch (err) {
    container.replaceChildren(
      el(
        "div",
        { className: "auth-container" },
        el(
          "div",
          { className: "auth-card" },
          el("h2", {}, "Lời mời tham gia"),
          el("p", { className: "form-error" }, err.message),
          el("p", {}, el("a", { href: "#/login", className: "button primary" }, "Đến trang Đăng nhập"))
        )
      )
    );
    return;
  }

  const nameInput = el("input", {
    type: "text",
    required: true,
    value: inviteInfo.name || "",
    placeholder: "Họ và tên của bạn",
  });
  const passwordInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Tối thiểu 10 ký tự",
  });
  const confirmInput = el("input", {
    type: "password",
    required: true,
    placeholder: "Nhập lại mật khẩu",
  });
  const submitBtn = el("button", { type: "submit", className: "primary full-width" }, "Tham gia tổ chức");
  const errorMsg = el("div", { className: "form-error", hidden: true });

  const form = el(
    "form",
    {
      className: "auth-form",
      onSubmit: async (e) => {
        e.preventDefault();
        errorMsg.hidden = true;

        if (passwordInput.value.length < 10) {
          errorMsg.textContent = "Mật khẩu phải có độ dài từ 10 ký tự trở lên";
          errorMsg.hidden = false;
          return;
        }

        if (passwordInput.value !== confirmInput.value) {
          errorMsg.textContent = "Mật khẩu xác nhận không trùng khớp";
          errorMsg.hidden = false;
          return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Đang tham gia…";

        try {
          const res = await api("/api/auth/accept-invite", {
            method: "POST",
            body: {
              token,
              name: nameInput.value.trim(),
              password: passwordInput.value,
            },
          });
          state.me = res;
          state.csrfToken = res.csrf_token;
          toast("Chào mừng bạn gia nhập tổ chức!", "ok");
          location.hash = "#/documents";
        } catch (err) {
          errorMsg.textContent = err.message;
          errorMsg.hidden = false;
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = "Tham gia tổ chức";
        }
      },
    },
    el(
      "div",
      { className: "invite-badge-box" },
      el("div", { className: "muted" }, "Bạn được mời tham gia tổ chức:"),
      el("div", { className: "invite-org-name" }, inviteInfo.org_name),
      el("div", { className: "muted" }, `Email tài khoản: ${inviteInfo.email}`)
    ),
    el("div", { className: "form-group" }, el("label", {}, "Họ và tên"), nameInput),
    el("div", { className: "form-group" }, el("label", {}, "Mật khẩu mới"), passwordInput),
    el("div", { className: "form-group" }, el("label", {}, "Xác nhận mật khẩu"), confirmInput),
    errorMsg,
    submitBtn
  );

  const card = el(
    "div",
    { className: "auth-card" },
    el("div", { className: "auth-header" },
      el("h2", {}, "Tham gia tổ chức"),
      el("p", { className: "muted" }, "Hoàn tất thông tin cá nhân và thiết lập mật khẩu")
    ),
    form
  );

  container.replaceChildren(el("div", { className: "auth-container" }, card));
  setTimeout(() => (inviteInfo.name ? passwordInput.focus() : nameInput.focus()), 50);
}
