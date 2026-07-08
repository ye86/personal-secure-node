"use strict";

let accessToken = "";
let selectedPath = "";
let selectedAction = "file.delete";
let currentPrefix = "";
const CHUNK_SIZE = 4 * 1024 * 1024;
const uploadKeys = new Map();

const byId = (id) => document.getElementById(id);

function formatBytes(value) {
  if (value === null || value === undefined) return "无限制";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = Number(value);
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function compactJson(value) {
  if (!value || typeof value !== "object") return "";
  const copy = {...value};
  delete copy.at;
  delete copy.event;
  return Object.keys(copy).length ? JSON.stringify(copy) : "";
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${accessToken}`);
  const response = await fetch(path, {...options, headers, cache: "no-store"});
  if (!response.ok) {
    let message = `请求失败 (${response.status})`;
    try {
      const error = await response.json();
      message = error.message || message;
    } catch (_) {}
    throw new Error(message);
  }
  return response;
}

async function jsonApi(path, method = "GET", value = undefined, extraHeaders = {}) {
  const options = {method, headers: {...extraHeaders}};
  if (value !== undefined) {
    options.body = JSON.stringify(value);
    options.headers["Content-Type"] = "application/json";
  }
  const response = await api(path, options);
  return response.json();
}

function uploadKey(file, path) {
  const identity = `${path}\n${file.name}\n${file.size}\n${file.lastModified}`;
  if (!uploadKeys.has(identity)) uploadKeys.set(identity, `web-v1-${crypto.randomUUID()}`);
  return uploadKeys.get(identity);
}

async function loadDashboard() {
  const [statusResponse, browseResponse] = await Promise.all([api("/v1/status"), api(`/v1/browse?prefix=${encodeURIComponent(currentPrefix)}`)]);
  const status = await statusResponse.json();
  const listing = await browseResponse.json();
  const files = listing.files;
  byId("file-count").textContent = String(status.live_files);
  byId("physical-size").textContent = formatBytes(status.physical_bytes);
  byId("version-count").textContent = String(status.versions);
  byId("quota-size").textContent = formatBytes(status.quota_bytes);
  const body = byId("file-list");
  body.replaceChildren();
  byId("current-path").textContent = `/${listing.prefix}`;
  byId("up").disabled = !listing.prefix;
  for (const directory of listing.directories) {
    const row = document.createElement("tr");
    const path = document.createElement("td");
    const open = document.createElement("button");
    open.type = "button"; open.className = "link-button"; open.textContent = `📁 ${directory.name}`;
    open.addEventListener("click", async () => { currentPrefix = directory.path; await loadDashboard(); });
    path.append(open); row.append(path, document.createElement("td"), document.createElement("td"), document.createElement("td")); body.append(row);
  }
  for (const file of files) {
    const row = document.createElement("tr");
    const path = document.createElement("td");
    path.textContent = file.virtual_path;
    const size = document.createElement("td");
    size.textContent = formatBytes(file.size);
    const date = document.createElement("td");
    date.textContent = file.created_at ? new Date(file.created_at).toLocaleString() : "—";
    const actions = document.createElement("td");
    const download = document.createElement("button");
    download.type = "button";
    download.className = "link-button";
    download.textContent = "下载";
    download.addEventListener("click", () => downloadFile(file.virtual_path));
    const history = document.createElement("button");
    history.type = "button";
    history.className = "link-button";
    history.textContent = "版本";
    history.addEventListener("click", () => showHistory(file.virtual_path));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "link-button danger-text";
    remove.textContent = "删除";
    remove.addEventListener("click", () => showDelete(file.virtual_path));
    const move = document.createElement("button");
    move.type = "button"; move.className = "link-button"; move.textContent = "移动";
    move.addEventListener("click", () => showMove(file.virtual_path));
    actions.append(download, history, move, remove);
    row.append(path, size, date, actions);
    body.append(row);
  }
  byId("message").textContent = `当前层级：${listing.directories.length} 个目录，${files.length} 个文件`;
  await loadConsole();
}

function renderEvents(events) {
  const body = byId("event-list");
  body.replaceChildren();
  if (!events.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.textContent = "暂无服务事件";
    row.append(cell);
    body.append(row);
    return;
  }
  for (const event of events) {
    const row = document.createElement("tr");
    const at = document.createElement("td");
    at.textContent = event.at ? new Date(event.at).toLocaleString() : "—";
    const name = document.createElement("td");
    name.textContent = event.event || "unknown";
    const detail = document.createElement("td");
    detail.textContent = compactJson(event);
    row.append(at, name, detail);
    body.append(row);
  }
}

function renderPreflight(result) {
  const panel = byId("preflight-panel");
  const list = byId("preflight-list");
  list.replaceChildren();
  for (const check of result.checks || []) {
    const item = document.createElement("li");
    item.className = check.ok ? "check-ok" : "check-failed";
    item.textContent = `${check.ok ? "✓" : "✗"} ${check.name}: ${check.message}`;
    list.append(item);
  }
  panel.hidden = false;
}

async function loadConsole() {
  try {
    const consoleData = await jsonApi("/v1/console");
    const status = consoleData.status || {};
    const storage = status.storage || {};
    const server = status.server || {};
    const lock = status.lock || {};
    byId("service-state").textContent = status.process_running ? "运行中" : status.stale_state ? "状态陈旧" : "未运行";
    byId("service-detail").textContent = lock.pid ? `PID ${lock.pid} · ${lock.started_at || "未知启动时间"}` : status.state_exists ? "存在状态文件" : "未发现运行状态";
    byId("node-url").textContent = server.node_url || (consoleData.config_exists ? "配置未提供地址" : "未初始化服务配置");
    byId("service-name").textContent = server.service_name || "—";
    byId("log-size").textContent = status.log_exists ? formatBytes(status.log_bytes) : "无日志";
    byId("event-log-size").textContent = status.event_log_exists ? `事件日志 ${formatBytes(status.event_log_bytes)}` : "无事件日志";
    byId("logical-size").textContent = formatBytes(storage.logical_bytes);
    byId("chunk-count").textContent = `${storage.chunks || 0} 个分块 · ${storage.deleted_files || 0} 个回收站文件`;
    renderEvents(consoleData.events || []);
    byId("console-message").textContent = `控制台已刷新：${new Date().toLocaleTimeString()}`;
  } catch (error) {
    byId("console-message").textContent = `控制台暂不可用：${error.message}`;
  }
}

async function showHistory(path) {
  selectedPath = path;
  byId("history-path").textContent = path;
  const versions = await jsonApi(`/v1/versions?path=${encodeURIComponent(path)}`);
  const body = byId("history-list");
  body.replaceChildren();
  for (const version of versions) {
    const row = document.createElement("tr");
    const date = document.createElement("td");
    date.textContent = new Date(version.created_at).toLocaleString();
    const size = document.createElement("td");
    size.textContent = formatBytes(version.size);
    const state = document.createElement("td");
    state.textContent = version.is_current ? "当前" : "历史";
    const action = document.createElement("td");
    if (!version.is_current) {
      const restore = document.createElement("button");
      restore.type = "button";
      restore.className = "link-button";
      restore.textContent = "恢复";
      restore.addEventListener("click", async () => {
        await jsonApi("/v1/versions/restore", "POST", {virtual_path:path, version_id:version.id});
        await loadDashboard();
        await showHistory(path);
      });
      action.append(restore);
    }
    row.append(date, size, state, action);
    body.append(row);
  }
  if (!byId("history-dialog").open) byId("history-dialog").showModal();
}

function showDelete(path) {
  showProtectedAction(path, "file.delete");
}

function showProtectedAction(path, action) {
  selectedPath = path;
  selectedAction = action;
  const purge = action === "file.purge";
  byId("delete-title").textContent = purge ? "永久清除" : "删除文件";
  byId("delete-description").textContent = purge ? "永久清除全部版本且不可撤销，需要file.purge动作令牌。" : "文件将进入回收站，需要file.delete动作令牌。";
  byId("delete-confirm").textContent = purge ? "永久清除" : "移入回收站";
  byId("delete-path").textContent = path;
  byId("action-token").value = "";
  byId("delete-message").textContent = "";
  byId("delete-dialog").showModal();
}

function showMove(path) {
  selectedPath = path; byId("move-source").textContent = path; byId("move-destination").value = path;
  byId("move-message").textContent = ""; byId("move-dialog").showModal();
}

async function showTrash() {
  const items = await jsonApi("/v1/trash");
  const body = byId("trash-list"); body.replaceChildren();
  for (const item of items) {
    const row = document.createElement("tr");
    const path = document.createElement("td"); path.textContent = item.virtual_path;
    const date = document.createElement("td"); date.textContent = new Date(item.deleted_at).toLocaleString();
    const size = document.createElement("td"); size.textContent = formatBytes(item.size);
    const actions = document.createElement("td");
    const restore = document.createElement("button"); restore.className="link-button"; restore.textContent="恢复";
    restore.addEventListener("click", async()=>{ await jsonApi("/v1/trash/restore","POST",{virtual_path:item.virtual_path}); await loadDashboard(); await showTrash(); });
    const purge = document.createElement("button"); purge.className="link-button danger-text"; purge.textContent="永久清除";
    purge.addEventListener("click",()=>showProtectedAction(item.virtual_path,"file.purge"));
    actions.append(restore,purge); row.append(path,date,size,actions); body.append(row);
  }
  if (!byId("trash-dialog").open) byId("trash-dialog").showModal();
}

async function downloadFile(path) {
  try {
    byId("message").textContent = `正在下载 ${path}`;
    const response = await api(`/v1/download?path=${encodeURIComponent(path)}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = path.split("/").pop() || "download";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    byId("message").textContent = `已下载 ${path}`;
  } catch (error) {
    byId("message").textContent = error.message;
  }
}

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  accessToken = byId("token").value.trim();
  byId("token").value = "";
  try {
    await loadDashboard();
    byId("login-message").textContent = "";
    byId("dashboard").hidden = false;
    byId("connection").textContent = "已连接";
    byId("connection").className = "status connected";
  } catch (error) {
    accessToken = "";
    byId("connection").textContent = "认证失败";
    byId("connection").className = "status disconnected";
    byId("login-message").textContent = error.message;
  }
});

byId("refresh").addEventListener("click", async () => {
  try {
    await loadDashboard();
  } catch (error) {
    byId("message").textContent = error.message;
  }
});
byId("console-refresh").addEventListener("click", loadConsole);
byId("console-preflight").addEventListener("click", async () => {
  try {
    const result = await jsonApi("/v1/console/preflight", "POST", {});
    renderPreflight(result);
    byId("console-message").textContent = result.ok ? "预检通过" : "预检发现问题";
    await loadConsole();
  } catch (error) {
    byId("console-message").textContent = error.message;
  }
});
byId("console-diagnostics").addEventListener("click", async () => {
  try {
    byId("console-message").textContent = "正在生成诊断包…";
    const result = await jsonApi("/v1/console/diagnostics", "POST", {});
    byId("console-message").textContent = `诊断包已生成：${result.path} (${formatBytes(result.bytes)})`;
    await loadConsole();
  } catch (error) {
    byId("console-message").textContent = error.message;
  }
});
byId("up").addEventListener("click", async()=>{ currentPrefix=currentPrefix.includes("/")?currentPrefix.slice(0,currentPrefix.lastIndexOf("/")):""; await loadDashboard(); });
byId("trash").addEventListener("click", showTrash);

byId("upload-file").addEventListener("change", () => {
  const file = byId("upload-file").files[0];
  if (file && !byId("upload-path").value) byId("upload-path").value = file.name;
});

byId("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = byId("upload-file").files[0];
  const path = byId("upload-path").value.trim();
  if (!file || !path) return;
  const progress = byId("upload-progress");
  const message = byId("upload-message");
  try {
    const session = await jsonApi("/v1/uploads", "POST", {
      virtual_path:path, expected_size:file.size, chunk_size:CHUNK_SIZE,
      idempotency_key:uploadKey(file, path), ttl_seconds:3600
    });
    const uploaded = new Set(session.uploaded_chunks.map((chunk) => chunk.ordinal));
    const count = Math.ceil(file.size / CHUNK_SIZE);
    for (let ordinal = 0; ordinal < count; ordinal += 1) {
      if (!uploaded.has(ordinal)) {
        const chunk = file.slice(ordinal * CHUNK_SIZE, Math.min(file.size, (ordinal + 1) * CHUNK_SIZE));
        await api(`/v1/uploads/${session.id}/chunks/${ordinal}`, {
          method:"PUT", headers:{"Content-Type":"application/octet-stream"}, body:chunk
        });
      }
      progress.value = count ? ((ordinal + 1) / count) * 100 : 100;
      message.textContent = `已上传 ${ordinal + 1}/${count} 个分块`;
    }
    await jsonApi(`/v1/uploads/${session.id}/commit`, "POST", {});
    progress.value = 100;
    message.textContent = `已保存 ${path}`;
    await loadDashboard();
  } catch (error) {
    message.textContent = error.message;
  }
});

byId("history-close").addEventListener("click", () => byId("history-dialog").close());
byId("delete-close").addEventListener("click", () => byId("delete-dialog").close());
byId("move-close").addEventListener("click", () => byId("move-dialog").close());
byId("trash-close").addEventListener("click", () => byId("trash-dialog").close());
byId("move-confirm").addEventListener("click", async()=>{
  try { await jsonApi("/v1/files/move","POST",{source:selectedPath,destination:byId("move-destination").value.trim()}); byId("move-dialog").close(); await loadDashboard(); }
  catch(error){ byId("move-message").textContent=error.message; }
});
byId("delete-confirm").addEventListener("click", async () => {
  const actionToken = byId("action-token").value.trim();
  if (!actionToken) return;
  try {
    const endpoint = selectedAction === "file.purge" ? "/v1/trash/purge" : "/v1/files/delete";
    await jsonApi(endpoint, "POST", {virtual_path:selectedPath}, {"X-PSN-Action-Token":actionToken});
    byId("action-token").value = "";
    byId("delete-dialog").close();
    await loadDashboard();
    if (selectedAction === "file.purge" && byId("trash-dialog").open) await showTrash();
  } catch (error) {
    byId("delete-message").textContent = error.message;
  }
});
