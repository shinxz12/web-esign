/**
 * Quản lý Gói dịch vụ & Lịch sử sử dụng (#/billing)
 * Thống kê hạn mức tháng này, lịch sử sử dụng, và so sánh các gói dịch vụ.
 */

import { api, el, showModal, state, toast } from "./api.js";

export async function renderBilling(container) {
  container.replaceChildren();

  const heading = el("h2", { className: "page-title" }, "Gói dịch vụ & Sử dụng");
  const subtext = el(
    "p",
    { className: "muted" },
    "Theo dõi hạn mức sử dụng tài liệu và chữ ký trong tháng của tổ chức."
  );

  const contentArea = el("div", { className: "billing-content" });
  container.append(el("div", { className: "page-header" }, el("div", {}, heading, subtext)), contentArea);

  contentArea.appendChild(el("div", { className: "loading-state" }, "Đang tải dữ liệu gói và mức sử dụng…"));

  try {
    const [usageData, allPlans] = await Promise.all([
      api("/v1/usage"),
      api("/api/plans"),
    ]);

    contentArea.replaceChildren();

    const plan = usageData.plan;
    const currentDocs = usageData.documents || 0;
    const currentSigs = usageData.signatures || 0;
    const maxDocs = plan.documents_per_month;
    const isUnlimitedDocs = maxDocs === null;

    let docPercent = 0;
    if (!isUnlimitedDocs && maxDocs > 0) {
      docPercent = Math.min(100, Math.round((currentDocs / maxDocs) * 100));
    }

    // 1. Thẻ tổng quan tháng hiện tại
    const currentPlanCard = el(
      "div",
      { className: "card billing-card" },
      el("div", { className: "billing-card-header" },
        el("div", {},
          el("span", { className: "badge badge-completed" }, "Gói hiện tại"),
          el("h3", { style: { margin: "8px 0 4px" } }, plan.name)
        ),
        el(
          "button",
          {
            className: "button primary",
            onClick: () => contactUpgrade(plan),
          },
          "Liên hệ để nâng cấp"
        )
      ),

      el(
        "div",
        { className: "usage-meters-grid" },
        // Meter 1: Tài liệu
        el(
          "div",
          { className: "meter-box" },
          el("div", { className: "meter-label muted" }, `Tài liệu đã tạo (Tháng ${usageData.period})`),
          el(
            "div",
            { className: "meter-numbers" },
            el("span", { className: "meter-used" }, String(currentDocs)),
            el("span", { className: "meter-limit muted" }, ` / ${isUnlimitedDocs ? "Không giới hạn" : `${maxDocs} tài liệu`}`)
          ),
          !isUnlimitedDocs
            ? el(
                "div",
                { className: "progress-bar-bg" },
                el("div", {
                  className: `progress-bar-fill ${docPercent > 90 ? "danger" : docPercent > 75 ? "warn" : ""}`,
                  style: { width: `${docPercent}%` },
                })
              )
            : null
        ),

        // Meter 2: Chữ ký
        el(
          "div",
          { className: "meter-box" },
          el("div", { className: "meter-label muted" }, `Lượt ký số hoàn tất (Tháng ${usageData.period})`),
          el(
            "div",
            { className: "meter-numbers" },
            el("span", { className: "meter-used" }, String(currentSigs)),
            el("span", { className: "meter-limit muted" }, " chữ ký")
          ),
          el("div", { className: "table-subtext muted", style: { marginTop: "14px" } }, "Được ghi nhận khi các bên hoàn tất ký PAdES")
        )
      ),

      // Giới hạn chi tiết của gói
      el(
        "div",
        { className: "plan-limits-summary", style: { marginTop: "20px" } },
        el("h4", { style: { margin: "0 0 10px" } }, "Hạn mức gói hiện tại:"),
        el(
          "div",
          { className: "limits-tags-grid" },
          el("div", { className: "limit-tag" }, el("span", { className: "muted" }, "Dung lượng tệp:"), el("strong", {}, ` ${plan.max_file_mb} MB`)),
          el("div", { className: "limit-tag" }, el("span", { className: "muted" }, "Người nhận tối đa:"), el("strong", {}, ` ${plan.max_recipients} người/tài liệu`)),
          el("div", { className: "limit-tag" }, el("span", { className: "muted" }, "Số lượng thành viên:"), el("strong", {}, ` ${plan.max_members ? `${plan.max_members} người` : "Không giới hạn"}`)),
          el("div", { className: "limit-tag" }, el("span", { className: "muted" }, "Khoá API:"), el("strong", {}, ` Tối đa ${plan.max_api_keys} khoá`)),
          el("div", { className: "limit-tag" }, el("span", { className: "muted" }, "Webhooks:"), el("strong", {}, ` Tối đa ${plan.max_webhooks} webhook`)),
          el("div", { className: "limit-tag" }, el("span", { className: "muted" }, "API Rate Limit:"), el("strong", {}, ` ${plan.api_requests_per_minute} req/phút`))
        )
      )
    );

    // 2. Lịch sử sử dụng (History table)
    const historyTableBody = el("tbody");
    const historyTable = el(
      "table",
      { className: "data-table" },
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", {}, "Kỳ (Tháng)"),
          el("th", {}, "Số tài liệu tạo mới"),
          el("th", {}, "Số chữ ký số đã thực hiện")
        )
      ),
      historyTableBody
    );

    const history = usageData.history || [];
    if (history.length === 0) {
      historyTableBody.appendChild(
        el("tr", {}, el("td", { colSpan: 3, className: "muted", style: { textAlign: "center", padding: "16px" } }, "Chưa có dữ liệu lịch sử sử dụng."))
      );
    } else {
      history.forEach((h) => {
        historyTableBody.appendChild(
          el(
            "tr",
            {},
            el("td", {}, el("strong", {}, `Tháng ${h.period}`)),
            el("td", {}, String(h.documents)),
            el("td", {}, String(h.signatures))
          )
        );
      });
    }

    const historyCard = el(
      "div",
      { className: "card billing-card", style: { marginTop: "24px" } },
      el("h3", { style: { marginTop: 0 } }, "Lịch sử sử dụng theo tháng"),
      el("div", { className: "table-responsive", style: { marginTop: "12px" } }, historyTable)
    );

    // 3. So sánh tất cả các gói dịch vụ
    const plansComparisonCard = el(
      "div",
      { className: "card billing-card", style: { marginTop: "24px" } },
      el("h3", { style: { marginTop: 0 } }, "Bảng so sánh các gói dịch vụ"),
      el("p", { className: "muted" }, "Chọn gói dịch vụ phù hợp nhất với quy mô ký kết của doanh nghiệp bạn.")
    );

    const plansGrid = el("div", { className: "plans-comparison-grid" });

    allPlans.forEach((p) => {
      const isCurrent = p.code === plan.code;
      const isPopular = p.code === "business";

      const card = el(
        "div",
        { className: `plan-card ${isCurrent ? "current" : ""} ${isPopular ? "popular" : ""}` },
        isCurrent
          ? el("div", { className: "plan-card-badge" }, "Đang sử dụng")
          : isPopular
          ? el("div", { className: "plan-card-badge popular" }, "Khuyên dùng")
          : null,
        el("h3", { className: "plan-card-name" }, p.name),
        el("div", { className: "plan-card-docs" }, p.documents_per_month ? `${p.documents_per_month} tài liệu/tháng` : "Không giới hạn tài liệu"),

        el(
          "ul",
          { className: "plan-features-list" },
          el("li", {}, `✓ Tệp tối đa ${p.max_file_mb} MB`),
          el("li", {}, `✓ Tối đa ${p.max_recipients} người nhận/tài liệu`),
          el("li", {}, `✓ ${p.max_members ? `${p.max_members} thành viên` : "Không giới hạn thành viên"}`),
          el("li", {}, `✓ ${p.max_api_keys} khoá API tích hợp`),
          el("li", {}, `✓ ${p.max_webhooks} webhook tự động`),
          el("li", {}, `✓ Tốc độ API ${p.api_requests_per_minute} req/phút`),
          el("li", {}, "✓ Chuẩn ký PAdES B-B, B-T, B-LT"),
          el("li", {}, "✓ Nhật ký kiểm toán hash-chain")
        ),

        isCurrent
          ? el("button", { className: "button full-width", disabled: true }, "Gói hiện tại")
          : el(
              "button",
              {
                className: `button full-width ${isPopular ? "primary" : ""}`,
                onClick: () => contactUpgrade(p),
              },
              "Liên hệ nâng cấp"
            )
      );

      plansGrid.appendChild(card);
    });

    plansComparisonCard.appendChild(plansGrid);

    contentArea.append(currentPlanCard, historyCard, plansComparisonCard);
  } catch (err) {
    contentArea.replaceChildren(
      el("div", { className: "form-error" }, `Lỗi khi tải thông tin gói: ${err.message}`)
    );
  }
}

function contactUpgrade(targetPlan) {
  showModal({
    title: "Liên hệ nâng cấp gói dịch vụ",
    content: el(
      "div",
      {},
      el(
        "p",
        {},
        `Bạn đang quan tâm đến gói dịch vụ `,
        el("strong", {}, targetPlan.name),
        `.`
      ),
      el(
        "p",
        { className: "muted" },
        "Vui lòng gửi email hoặc liên hệ với bộ phận hỗ trợ khách hàng của chúng tôi để được tư vấn và kích hoạt gói:"
      ),
      el(
        "div",
        { className: "contact-info-box" },
        el("div", {}, "📧 Email: ", el("a", { href: "mailto:support@websigner.vn" }, "support@websigner.vn")),
        el("div", { style: { marginTop: "6px" } }, "📞 Hotline: ", el("strong", {}, "1900 6868"))
      )
    ),
    actions: [{ label: "Đóng", primary: true }],
  });
}
