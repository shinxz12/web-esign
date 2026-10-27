/**
 * Web Signer Dashboard — Single Page Application (SPA)
 * Router, Bootstrapping, Layout Shell, và Điều hướng Hash.
 */

import { api, el, ROLE_LABELS, state, toast } from "./dashboard/api.js";
import {
  renderForgot,
  renderInvite,
  renderLogin,
  renderRegister,
  renderReset,
} from "./dashboard/auth.js";
import { renderDocumentsList, renderNewDocument } from "./dashboard/docs.js";
import { renderDraftEditor } from "./dashboard/editor.js";
import { renderSentDoc } from "./dashboard/viewer.js";
import { renderDevelopers } from "./dashboard/developers.js";
import { renderMembers } from "./dashboard/members.js";
import { renderBilling } from "./dashboard/billing.js";
import { renderAccount } from "./dashboard/account.js";

const appRoot = document.getElementById("app");

/**
 * Phân tích URL Hash thành route, params và query params
 */
function parseHash() {
  const hash = window.location.hash.slice(1) || "/";
  const [pathPart, queryPart] = hash.split("?");

  const query = {};
  if (queryPart) {
    const params = new URLSearchParams(queryPart);
    for (const [k, v] of params.entries()) {
      query[k] = v;
    }
  }

  const segments = pathPart.split("/").filter(Boolean);
  return { pathPart, segments, query };
}

/**
 * Điều hướng Router
 */
async function handleRouting() {
  const { pathPart, segments, query } = parseHash();
  const route = segments[0] || "";

  // 1. Kiểm tra xác thực và Route Guard
  const isAuthRoute = ["login", "register", "forgot", "reset", "invite"].includes(route);

  if (!state.me) {
    if (!isAuthRoute) {
      window.location.hash = "#/login";
      return;
    }
  } else {
    // Đã đăng nhập nhưng truy cập màn hình auth
    if (isAuthRoute) {
      window.location.hash = "#/documents";
      return;
    }
    // Mặc định root -> #/documents
    if (!route) {
      window.location.hash = "#/documents";
      return;
    }
  }

  // 2. Cập nhật Layout Shell (Topbar & Sidebar)
  updateShellLayout(isAuthRoute);

  const mainArea = document.getElementById("main-content");
  if (!mainArea) return;

  // 3. Render View tương ứng
  if (route === "login") {
    renderLogin(mainArea);
  } else if (route === "register") {
    renderRegister(mainArea);
  } else if (route === "forgot") {
    renderForgot(mainArea);
  } else if (route === "reset") {
    renderReset(mainArea, query);
  } else if (route === "invite") {
    renderInvite(mainArea, query);
  } else if (route === "documents") {
    if (segments[1] === "new") {
      renderNewDocument(mainArea);
    } else if (segments[1]) {
      const docId = segments[1];
      // Kiểm tra trạng thái tài liệu để render draft editor hoặc sent doc viewer
      try {
        const doc = await api(`/v1/documents/${docId}`);
        if (doc.status === "draft") {
          renderDraftEditor(mainArea, docId);
        } else {
          renderSentDoc(mainArea, docId);
        }
      } catch (err) {
        mainArea.replaceChildren(
          el(
            "div",
            { className: "card content-card", style: { margin: "24px auto", maxWidth: "600px", textAlign: "center" } },
            el("h3", {}, "Không tìm thấy tài liệu"),
            el("p", { className: "form-error" }, err.message),
            el("a", { href: "#/documents", className: "button primary" }, "Quay lại danh sách")
          )
        );
      }
    } else {
      renderDocumentsList(mainArea, query.status || "", query.q || "");
    }
  } else if (route === "developers") {
    renderDevelopers(mainArea);
  } else if (route === "members") {
    renderMembers(mainArea);
  } else if (route === "billing") {
    renderBilling(mainArea);
  } else if (route === "account") {
    renderAccount(mainArea);
  } else {
    // Route không xác định -> về #/documents
    window.location.hash = "#/documents";
  }

  // Cập nhật active link trên sidebar
  updateActiveNavLink(route);
}

/**
 * Xây dựng hoặc cập nhật cấu trúc Shell (Header + Sidebar + Main)
 */
function updateShellLayout(isAuthRoute) {
  if (isAuthRoute) {
    if (!document.getElementById("auth-shell")) {
      appRoot.replaceChildren(
        el("div", { id: "auth-shell", className: "auth-shell" },
          el("main", { id: "main-content", className: "auth-main" })
        )
      );
    }
    return;
  }

  // Nếu chưa có dashboard shell thì tạo mới
  if (!document.getElementById("dashboard-shell")) {
    const org = state.me?.org;
    const user = state.me?.user;
    const role = user?.role || "member";
    const isMember = role === "member";

    // Topbar
    const brand = el("a", { href: "#/documents", className: "brand" }, "Web Signer");
    const orgBadge = el(
      "span",
      { id: "topbar-org-name", className: "topbar-org-badge" },
      org?.name || "Tổ chức"
    );

    const userRoleBadge = el(
      "span",
      { className: `badge ${role === "owner" ? "badge-owner" : role === "admin" ? "badge-completed" : "badge-draft"}` },
      ROLE_LABELS[role] || role
    );

    const userNameSpan = el("span", { className: "topbar-user-name" }, user?.name || user?.email || "");

    const logoutBtn = el(
      "button",
      {
        className: "button small",
        onClick: async () => {
          try {
            await api("/api/auth/logout", { method: "POST" });
          } catch {}
          state.me = null;
          state.csrfToken = "";
          toast("Đã đăng xuất.", "ok");
          window.location.hash = "#/login";
        },
      },
      "Đăng xuất"
    );

    const topbar = el(
      "header",
      { className: "topbar" },
      el("div", { className: "topbar-left" }, brand, orgBadge),
      el("div", { className: "topbar-right" }, userNameSpan, userRoleBadge, logoutBtn)
    );

    // Sidebar navigation
    const navDocs = el(
      "a",
      { href: "#/documents", className: "sidebar-nav-item", dataset: { route: "documents" } },
      el("span", { className: "nav-icon" }, "📄"),
      el("span", {}, "Tài liệu")
    );

    const navDev = el(
      "a",
      { href: "#/developers", className: "sidebar-nav-item", dataset: { route: "developers" }, hidden: isMember },
      el("span", { className: "nav-icon" }, "⚡"),
      el("span", {}, "Nhà phát triển")
    );

    const navMembers = el(
      "a",
      { href: "#/members", className: "sidebar-nav-item", dataset: { route: "members" } },
      el("span", { className: "nav-icon" }, "👥"),
      el("span", {}, "Thành viên")
    );

    const navBilling = el(
      "a",
      { href: "#/billing", className: "sidebar-nav-item", dataset: { route: "billing" } },
      el("span", { className: "nav-icon" }, "💳"),
      el("span", {}, "Gói & sử dụng")
    );

    const navAccount = el(
      "a",
      { href: "#/account", className: "sidebar-nav-item", dataset: { route: "account" } },
      el("span", { className: "nav-icon" }, "⚙️"),
      el("span", {}, "Tài khoản")
    );

    const sidebar = el(
      "aside",
      { className: "dashboard-sidebar" },
      el("nav", { className: "sidebar-nav" }, navDocs, navDev, navMembers, navBilling, navAccount)
    );

    const mainContent = el("main", { id: "main-content", className: "dashboard-main" });

    const layout = el(
      "div",
      { id: "dashboard-shell", className: "dashboard-layout" },
      topbar,
      el("div", { className: "dashboard-body" }, sidebar, mainContent)
    );

    appRoot.replaceChildren(layout);
  }
}

/**
 * Cập nhật class active cho navigation link đang chọn
 */
function updateActiveNavLink(currentRoute) {
  const items = document.querySelectorAll(".sidebar-nav-item");
  for (const item of items) {
    const route = item.dataset.route;
    item.classList.toggle("active", route === currentRoute);
  }
}

/**
 * Khởi động ứng dụng (Bootstrap)
 */
async function boot() {
  appRoot.replaceChildren(
    el("div", { className: "boot-splash" },
      el("div", { className: "boot-logo" }, "Web Signer"),
      el("div", { className: "muted" }, "Đang khởi tạo ứng dụng…")
    )
  );

  // 1. Nạp cấu hình công khai
  try {
    state.config = await api("/api/config");
  } catch (err) {
    console.error("Không thể nạp config:", err);
  }

  // 2. Kiểm tra phiên đăng nhập hiện tại
  try {
    const me = await api("/api/auth/me");
    state.me = me;
    state.csrfToken = me.csrf_token;
  } catch (err) {
    state.me = null;
    state.csrfToken = "";
  }

  // 3. Lắng nghe thay đổi hash
  window.addEventListener("hashchange", handleRouting);

  // 4. Kích hoạt định tuyến ban đầu
  handleRouting();
}

// Khởi chạy khi DOM sẵn sàng
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
