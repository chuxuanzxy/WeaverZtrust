(() => {
const state = {
  user: null,
  apps: [],
  users: [],
  groups: [],
  policies: [],
  activeLogTab: "access",
};

const titles = {
  overview: ["总览", "入口状态、授权对象与审计概况"],
  apps: ["应用管理", "配置 OA 入口域名、后端地址与代理参数"],
  users: ["用户管理", "维护本地账号与管理员权限"],
  groups: ["用户组管理", "维护灰度接入用户集合"],
  policies: ["授权配置", "按用户或用户组放行应用入口"],
  logs: ["审计日志", "查询访问、登录和管理操作记录"],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

document.addEventListener("DOMContentLoaded", () => {
  bindNavigation();
  bindForms();
  bindLogTabs();
  bindTableActions();
  $("#refreshBtn").addEventListener("click", refreshAll);
  $("#logoutBtn").addEventListener("click", logout);
  refreshAll();
});

function bindNavigation() {
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.view));
  });
  $$("[data-jump]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.logTab) showLogTab(button.dataset.logTab);
      showView(button.dataset.jump);
    });
  });
}

function bindForms() {
  $("#loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    submit.textContent = "登录中";
    try {
      const result = await api("/auth/login", { method: "POST", body: formData(form) }, { showError: false });
      state.user = result.user;
      const ok = await refreshAll({ afterLogin: true });
      if (ok) {
        form.reset();
        toast("登录成功");
      }
    } catch (error) {
      toast(parseError(error.message) === "invalid_credentials" ? "账号或密码错误" : "登录失败");
    } finally {
      submit.disabled = false;
      submit.textContent = "登录";
    }
  });

  $("#appForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formData(event.currentTarget);
    data.enabled = event.currentTarget.enabled.checked;
    data.proxy_timeout_ms = Number(data.proxy_timeout_ms || 30000);
    await api("/admin/apps", { method: "POST", body: data });
    event.currentTarget.reset();
    event.currentTarget.enabled.checked = true;
    toast("应用已保存");
    await refreshAll();
  });

  $("#userForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formData(event.currentTarget);
    data.is_admin = event.currentTarget.is_admin.checked;
    await api("/admin/users", { method: "POST", body: data });
    event.currentTarget.reset();
    toast("用户已保存");
    await refreshAll();
  });

  $("#groupForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formData(event.currentTarget);
    data.user_ids = splitIDs(data.user_ids);
    await api("/admin/groups", { method: "POST", body: data });
    event.currentTarget.reset();
    toast("用户组已保存");
    await refreshAll();
  });

  $("#policyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formData(event.currentTarget);
    data.app_id = Number(data.app_id);
    data.subject_id = Number(data.subject_id);
    await api("/admin/policies", { method: "POST", body: data });
    event.currentTarget.reset();
    toast("授权已保存");
    await refreshAll();
  });

  $("#accessFilter").addEventListener("submit", async (event) => {
    event.preventDefault();
    await loadLogs();
  });
}

function bindLogTabs() {
  $$(".tab").forEach((button) => {
    button.addEventListener("click", () => showLogTab(button.dataset.tab));
  });
}

function bindTableActions() {
  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-delete]");
    if (!button) return;
    const type = button.dataset.delete;
    const id = Number(button.dataset.id);
    const label = button.dataset.label || `${type}#${id}`;
    if (!Number.isInteger(id) || id <= 0) return;
    if (!window.confirm(`确认删除 ${label}？`)) return;
    const path = {
      app: `/admin/apps/${id}`,
      user: `/admin/users/${id}`,
      group: `/admin/groups/${id}`,
      policy: `/admin/policies/${id}`,
    }[type];
    if (!path) return;
    await api(path, { method: "DELETE" });
    toast("已删除");
    await refreshAll();
  });
}

function showView(name) {
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $$(".view").forEach((panel) => panel.classList.toggle("active", panel.dataset.viewPanel === name));
  const [title, subtitle] = titles[name] || titles.overview;
  $("#viewTitle").textContent = title;
  $("#viewSubtitle").textContent = subtitle;
}

function showLogTab(name) {
  state.activeLogTab = name;
  $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
  $$(".log-table").forEach((panel) => panel.classList.toggle("active", panel.dataset.logPanel === name));
  $("#accessFilter").style.display = name === "access" ? "grid" : "none";
}

async function refreshAll(options = {}) {
  try {
    const me = await api("/admin/me", {}, { showError: false });
    const [users, groups, apps, policies] = await Promise.all([
      api("/admin/users"),
      api("/admin/groups"),
      api("/admin/apps"),
      api("/admin/policies"),
    ]);
    state.user = me;
    state.users = users;
    state.groups = groups;
    state.apps = apps;
    state.policies = policies;
    renderCore();
    await loadLogs();
    $("#loginPanel").classList.add("hidden");
    $("#appPanel").classList.remove("hidden");
    return true;
  } catch (error) {
    $("#loginPanel").classList.remove("hidden");
    $("#appPanel").classList.add("hidden");
    $("#sessionUser").textContent = "未登录";
    if (options.afterLogin) {
      toast("登录成功但会话未生效，请检查访问域名与 Cookie 配置");
    }
    return false;
  }
}

async function loadLogs() {
  const query = new URLSearchParams();
  Object.entries(formData($("#accessFilter"))).forEach(([key, value]) => {
    if (value) query.set(key, value);
  });
  query.set("limit", "100");
  const [access, login, admin] = await Promise.all([
    api(`/admin/audit/access?${query.toString()}`),
    api("/admin/audit/login?limit=100"),
    api("/admin/audit/admin?limit=100"),
  ]);
  renderAccessLogs(access);
  renderLoginLogs(login);
  renderAdminLogs(admin);
  renderRecent(access, login);
}

function renderCore() {
  $("#sessionUser").textContent = state.user ? state.user.username : "已登录";
  $("#metricApps").textContent = state.apps.length;
  $("#metricUsers").textContent = state.users.length;
  $("#metricGroups").textContent = state.groups.length;
  $("#metricPolicies").textContent = state.policies.length;
  renderRows("#appRows", state.apps, (app) => [
    app.id,
    escapeHTML(app.name),
    escapeHTML(app.domain),
    escapeHTML(app.backend_url),
    badge(app.enabled ? "启用" : "停用", app.enabled ? "" : "warn"),
    deleteButton("app", app.id, app.name),
  ]);
  renderRows("#userRows", state.users, (user) => [
    user.id,
    escapeHTML(user.username),
    escapeHTML(user.display_name || "-"),
    badge(user.is_admin ? "管理员" : "用户", user.is_admin ? "warn" : ""),
    badge(user.status || "active"),
    user.id === state.user?.id ? `<span class="muted">当前账号</span>` : deleteButton("user", user.id, user.username),
  ]);
  renderRows("#groupRows", state.groups, (group) => [
    group.id,
    escapeHTML(group.name),
    escapeHTML((group.user_ids || []).join(", ") || "-"),
    deleteButton("group", group.id, group.name),
  ]);
  renderRows("#policyRows", state.policies, (policy) => [
    policy.id,
    policy.app_id,
    `${escapeHTML(policy.subject)}:${policy.subject_id}`,
    badge(policy.effect || "allow"),
    fmtTime(policy.created_at),
    deleteButton("policy", policy.id, `策略 ${policy.id}`),
  ]);
}

function renderRecent(access, login) {
  renderRows("#recentAccessRows", access.slice(-6).reverse(), (item) => [
    escapeHTML(item.username || "-"),
    escapeHTML(item.path || "-"),
    statusBadge(item.status_code),
    `${item.duration_ms || 0} ms`,
  ]);
  renderRows("#recentLoginRows", login.slice(-6).reverse(), (item) => [
    escapeHTML(item.username),
    escapeHTML(item.source_ip || "-"),
    resultBadge(item.result),
    fmtTime(item.created_at),
  ]);
}

function renderAccessLogs(items) {
  renderRows("#accessLogRows", items.slice().reverse(), (item) => [
    fmtTime(item.created_at),
    escapeHTML(item.username || "-"),
    escapeHTML(item.source_ip || "-"),
    escapeHTML(item.path || "-"),
    statusBadge(item.status_code),
    `${item.duration_ms || 0} ms`,
    escapeHTML([item.browser, item.os].filter(Boolean).join(" / ") || item.user_agent || "-"),
  ]);
}

function renderLoginLogs(items) {
  renderRows("#loginLogRows", items.slice().reverse(), (item) => [
    fmtTime(item.created_at),
    escapeHTML(item.username),
    escapeHTML(item.source_ip || "-"),
    resultBadge(item.result),
    escapeHTML(item.failure_reason || "-"),
  ]);
}

function renderAdminLogs(items) {
  renderRows("#adminLogRows", items.slice().reverse(), (item) => [
    fmtTime(item.created_at),
    escapeHTML(item.admin_username || "-"),
    escapeHTML(`${item.object_type || "-"}${item.object_id ? `#${item.object_id}` : ""}`),
    escapeHTML(item.action || "-"),
    escapeHTML(item.after_summary || item.before_summary || "-"),
  ]);
}

function renderRows(selector, items, mapper) {
  const tbody = $(selector);
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted">暂无数据</td></tr>`;
    return;
  }
  tbody.innerHTML = items.map((item) => `<tr>${mapper(item).map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("");
}

async function logout() {
  await api("/auth/logout", { method: "POST" }, { showError: false }).catch(() => {});
  state.user = null;
  $("#loginPanel").classList.remove("hidden");
  $("#appPanel").classList.add("hidden");
  $("#sessionUser").textContent = "未登录";
  toast("已退出");
}

async function api(path, options = {}, behavior = {}) {
  const showError = behavior.showError !== false;
  const init = { credentials: "same-origin", ...options };
  if (init.body && typeof init.body !== "string") {
    init.headers = { "Content-Type": "application/json", ...(init.headers || {}) };
    init.body = JSON.stringify(init.body);
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    const message = await response.text();
    if (showError) toast(parseError(message) || `请求失败 ${response.status}`);
    throw new Error(message || response.statusText);
  }
  if (response.status === 204) return null;
  return response.json();
}

function formData(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function splitIDs(value) {
  return String(value || "")
    .split(",")
    .map((item) => Number(item.trim()))
    .filter((item) => Number.isInteger(item) && item > 0);
}

function fmtTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString("zh-CN", { hour12: false });
}

function badge(text, tone = "") {
  return `<span class="badge ${tone}">${escapeHTML(text)}</span>`;
}

function statusBadge(code) {
  const tone = code >= 500 ? "bad" : code >= 400 ? "warn" : "";
  return badge(String(code || "-"), tone);
}

function resultBadge(result) {
  return badge(result || "-", result === "success" ? "" : "bad");
}

function deleteButton(type, id, label) {
  return `<button class="danger-btn" data-delete="${type}" data-id="${id}" data-label="${escapeHTML(label)}">删除</button>`;
}

function parseError(text) {
  try {
    return JSON.parse(text).error;
  } catch {
    return text;
  }
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

let toastTimer = null;
function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("show"), 2400);
}
})();
