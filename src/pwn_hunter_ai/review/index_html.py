from __future__ import annotations

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PwnHunter Review</title>
  <style>
    :root {
      --bg: #f3efe6;
      --panel: #fdfaf3;
      --panel-2: #fff;
      --accent: #0e6b62;
      --accent-muted: #deeee8;
      --danger: #8f2d2d;
      --danger-bg: #f9e7e7;
      --text: #1f2523;
      --muted: #5b6561;
      --border: #d8d2c6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 15% -20%, #fff, transparent 45%),
        linear-gradient(135deg, #f8f3e8, #e9f2ee 65%);
      min-height: 100vh;
    }
    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 360px;
      min-height: 100vh;
      gap: 18px;
      padding: 18px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      overflow: hidden;
    }
    .main {
      display: grid;
      grid-template-rows: auto 1fr;
      min-width: 0;
    }
    .header {
      padding: 18px;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(130deg, #fffef9, #f2f8f5);
    }
    .title { margin: 0; font-size: 24px; }
    .subtitle { margin: 4px 0 0; color: var(--muted); }
    #repo-meta { margin-top: 10px; color: var(--muted); font-size: 13px; }
    .repo-meta-row {
      margin-top: 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
    }
    .repo-meta-text {
      color: var(--muted);
      font-size: 13px;
    }
    .repo-link-btn {
      display: inline-block;
      text-decoration: none;
      background: #0f5f56;
      color: #fff;
      border-radius: 8px;
      padding: 5px 10px;
      font-size: 12px;
      border: 1px solid #0b4b44;
    }
    .repo-link-btn:hover {
      background: #0c5149;
    }
    .repo-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }
    .attack-btn {
      display: inline-block;
      background: #7b2d2d;
      color: #fff;
      border-radius: 8px;
      padding: 5px 10px;
      font-size: 12px;
      border: 1px solid #5f2222;
      cursor: pointer;
    }
    .attack-btn:hover {
      background: #672525;
    }
    #risk-container {
      overflow: auto;
      padding: 14px;
      display: grid;
      gap: 14px;
      align-content: start;
    }
    .risk {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      display: grid;
      gap: 10px;
    }
    .risk-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
    }
    .badge {
      font-size: 12px;
      border-radius: 999px;
      padding: 4px 10px;
      background: var(--accent-muted);
      color: #0b524b;
      border: 1px solid #b9d8cf;
      white-space: nowrap;
    }
    .badge.bad { background: var(--danger-bg); border-color: #e4bbbb; color: var(--danger); }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; }
    .chip {
      font-size: 12px;
      background: #f2f1ec;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 4px 10px;
    }
    .ai-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 8px;
    }
    .field {
      background: #f7f5ef;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
    }
    .field strong { display: block; margin-bottom: 4px; font-size: 12px; color: #41504a; }
    .workflow-btn {
      background: #114f49;
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 8px 10px;
      font-size: 13px;
      cursor: pointer;
    }
    .workflow-btn:hover { background: #0d443f; }
    pre {
      margin: 0;
      border-radius: 8px;
      padding: 10px;
      background: #0f1718;
      color: #e4f1ef;
      overflow: auto;
      min-height: 260px;
      max-height: 560px;
      border: 1px solid #2b4341;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre;
    }
    .yaml-comment { color: #86a18e; }
    .yaml-key { color: #89d3ff; }
    .yaml-bool { color: #ffb86c; }
    .yaml-number { color: #ffd580; }
    .yaml-string { color: #b8f7b1; }
    .yaml-dash { color: #f9a8d4; }
    .yaml-anchor { color: #d7a6ff; }
    .yaml-punc { color: #c5d1d8; }
    .yaml-error { color: #ff9e9e; font-style: italic; }
    .yaml-loading { color: #d0e8e5; font-style: italic; }
    .yaml-placeholder { color: #9ec8c2; }
    .yaml-title {
      font-size: 12px;
      color: #5e7a73;
      margin: 2px 0 6px 0;
    }
    .sidebar {
      display: grid;
      grid-template-rows: auto 1fr;
      min-width: 0;
    }
    .side-head {
      padding: 14px;
      border-bottom: 1px solid var(--border);
      font-weight: 600;
    }
    .repo-summary {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      display: grid;
      gap: 8px;
      background: #f6f3eb;
    }
    .repo-summary-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }
    .summary-card {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fff;
      padding: 8px;
    }
    .summary-label {
      display: block;
      font-size: 11px;
      color: #4f5f59;
      margin-bottom: 4px;
    }
    .summary-value {
      font-size: 18px;
      font-weight: 700;
      color: #243330;
      line-height: 1;
    }
    .side-controls {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      background: #f6f3eb;
    }
    .side-controls label {
      font-size: 12px;
      color: #4f5f59;
    }
    .side-controls select,
    .side-controls button {
      font: inherit;
      font-size: 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fff;
      color: #243330;
      padding: 5px 8px;
    }
    .side-controls select {
      min-width: 0;
      max-width: 100%;
    }
    .side-controls button {
      cursor: pointer;
      min-width: 44px;
    }
    .filter-stats {
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
      font-size: 12px;
      color: #4f5f59;
      background: #f6f3eb;
    }
    #repo-list {
      margin: 0;
      padding: 10px;
      list-style: none;
      overflow: auto;
      display: grid;
      gap: 8px;
      align-content: start;
    }
    .repo-item {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px;
      cursor: pointer;
      transition: transform 120ms ease;
    }
    .repo-item.safe {
      background: #edf8f1;
      border-color: #b7d8c1;
    }
    .repo-item.repo-vulnerable {
      background: #dff5df;
      border-color: #8fcf93;
    }
    .repo-item.secret-token-vulnerable {
      background: #0f4f2a;
      border-color: #08351c;
      color: #f2fff5;
    }
    .repo-item.secret-token-vulnerable .repo-meta,
    .repo-item.secret-token-vulnerable .review-reason-note,
    .repo-item.secret-token-vulnerable .repo-error-note {
      color: #d6f5dc;
    }
    .repo-item.vulnerable {
      background: #fbeeee;
      border-color: #e4bcbc;
    }
    .repo-item.review {
      background: #fff7e8;
      border-color: #e6c890;
    }
    .repo-item.neutral {
      background: #f5f6f5;
      border-color: #d6d9d7;
    }
    .repo-item:hover { transform: translateY(-1px); }
    .repo-item.active {
      border-color: #2c8e7c;
      box-shadow: inset 0 0 0 1px #2c8e7c;
    }
    .repo-name {
      font-size: 13px;
      font-weight: 600;
      word-break: break-word;
      margin-bottom: 6px;
    }
    .repo-meta {
      color: var(--muted);
      font-size: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .repo-stats {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .mini-pill {
      font-size: 11px;
      border-radius: 999px;
      padding: 2px 7px;
      border: 1px solid var(--border);
      background: #f6f4ee;
      color: #2d3a36;
    }
    .mini-pill.vuln {
      background: #fbe7e7;
      border-color: #e2b6b6;
      color: #7b2424;
    }
    .mini-pill.safe {
      background: #eaf6ee;
      border-color: #b8d6bf;
      color: #2a5b39;
    }
    .mini-pill.review {
      background: #fff3de;
      border-color: #e5c58a;
      color: #78530e;
    }
    .mini-pill.error {
      background: #3d1515;
      border-color: #5d2525;
      color: #ffe1e1;
    }
    .repo-error-note {
      margin-top: 6px;
      font-size: 12px;
      color: #7b2424;
      background: #fff0f0;
      border: 1px solid #e7c3c3;
      border-radius: 8px;
      padding: 6px 8px;
    }
    .review-reason-note {
      margin-top: 6px;
      font-size: 12px;
      color: #734f13;
      background: #fff5e4;
      border: 1px solid #ead1a2;
      border-radius: 8px;
      padding: 6px 8px;
      white-space: pre-wrap;
    }
    .repo-error-banner {
      margin-top: 10px;
      padding: 9px 12px;
      border-radius: 9px;
      border: 1px solid #e4c0c0;
      background: #fff2f2;
      color: #6f2323;
      font-size: 13px;
      white-space: pre-wrap;
    }
    .attack-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 8px;
    }
    .attack-panel {
      border: 1px solid var(--border);
      border-radius: 9px;
      background: #faf8f2;
      padding: 9px;
      display: grid;
      gap: 6px;
    }
    .attack-panel.error {
      background: #fff1f1;
      border-color: #e5bcbc;
    }
    .attack-status-line {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .attack-status {
      display: inline-block;
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 12px;
      border: 1px solid #c3d2cd;
      background: #edf4f1;
      color: #1d4a40;
    }
    .attack-status.vulnerable_confirmed {
      background: #fde9e9;
      border-color: #e5bebe;
      color: #8b2b2b;
    }
    .attack-status.human_review_required {
      background: #fff3de;
      border-color: #e8c992;
      color: #7c540b;
    }
    .attack-status.not_vulnerable_after_execution {
      background: #e9f6ee;
      border-color: #b6d8c0;
      color: #2b613d;
    }
    .attack-status.execution_error,
    .attack-status.blocked_preparation_error {
      background: #3a1515;
      border-color: #582222;
      color: #ffe8e8;
    }
    .attack-reason {
      margin: 0;
      font-size: 12px;
      color: #44544f;
      white-space: pre-wrap;
    }
    .verification-pill {
      display: inline-block;
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 12px;
      border: 1px solid #c4d1cb;
      background: #edf5f1;
      color: #214a41;
    }
    .hookbin-panel {
      border: 1px solid #cfdad5;
      border-radius: 9px;
      background: #f7fbf9;
      padding: 9px;
      display: grid;
      gap: 7px;
    }
    .hookbin-logs {
      margin: 0;
      min-height: 64px;
      max-height: 220px;
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.35;
      font-size: 12px;
    }
    .patch-panel {
      border: 1px solid #d4cdbf;
      border-radius: 9px;
      background: #fbf8f1;
      padding: 9px;
      display: grid;
      gap: 7px;
    }
    .patch-panel details {
      display: grid;
      gap: 8px;
    }
    .patch-panel summary {
      cursor: pointer;
      font-weight: 600;
      color: #33413d;
    }
    .patch-logs {
      margin: 0;
      min-height: 96px;
      max-height: 320px;
      overflow: auto;
      white-space: pre;
      line-height: 1.35;
      font-size: 12px;
    }
    .dialog-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(8, 10, 10, 0.45);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 18px;
      z-index: 1000;
    }
    .dialog-backdrop.hidden {
      display: none;
    }
    .dialog-panel {
      width: min(860px, 96vw);
      background: #fffefb;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      display: grid;
      gap: 10px;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.2);
    }
    .dialog-title {
      font-size: 18px;
      margin: 0;
    }
    .dialog-subtitle {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      word-break: break-word;
    }
    .dialog-command {
      margin: 0;
      min-height: 132px;
      max-height: 320px;
    }
    .dialog-actions {
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }
    .dialog-copy-btn,
    .dialog-close-btn {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 6px 10px;
      font-size: 12px;
      cursor: pointer;
      background: #fff;
    }
    .dialog-copy-btn {
      background: #145f55;
      color: #fff;
      border-color: #0f4a43;
    }
    .dialog-status {
      font-size: 12px;
      color: #445650;
      min-height: 16px;
    }
    @media (max-width: 980px) {
      .layout {
        grid-template-columns: minmax(0, 1fr);
      }
      .sidebar { order: -1; max-height: 40vh; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <section class="panel main">
      <div class="header">
        <h1 class="title">AI Risk Review Console</h1>
        <p class="subtitle">Validate each AI finding with workflow context and a reviewer-focused summary.</p>
        <div id="repo-meta">Loading repositories...</div>
      </div>
      <div id="risk-container"></div>
    </section>
    <aside class="panel sidebar">
      <div class="side-head">Repositories</div>
      <div class="repo-summary">
        <div class="repo-summary-grid">
          <div class="summary-card">
            <span class="summary-label">Vulnerable</span>
            <span class="summary-value" id="summary-vulnerable">0</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Not Vulnerable</span>
            <span class="summary-value" id="summary-not-vulnerable">0</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Total</span>
            <span class="summary-value" id="summary-total">0</span>
          </div>
        </div>
      </div>
      <div class="side-controls">
        <label for="sort-key">Sort</label>
        <select id="sort-key">
          <option value="stars">Stars</option>
          <option value="vulnerabilities">Vulnerabilities</option>
          <option value="name">Name</option>
        </select>
        <label for="review-filter">Filter</label>
        <select id="review-filter">
          <option value="all">All</option>
          <option value="needs_human_review">Needs Human Review</option>
          <option value="has_security_source">Has Security Source (hosted/act)</option>
          <option value="mismatch">Mismatch (repo vs act)</option>
          <option value="hookbin_empty_string">Hookbin Empty String</option>
          <option value="hookbin_not_empty_string">Hookbin Not Empty String</option>
          <option value="hookbin_missing_field">Hookbin Missing Field</option>
        </select>
        <button id="sort-order" type="button" title="Toggle ascending/descending">Desc</button>
      </div>
      <div id="filter-stats" class="filter-stats">Filter: All | 0 repositories (0,00% of total)</div>
      <ul id="repo-list"></ul>
    </aside>
  </div>
  <div id="attack-dialog" class="dialog-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="attack-dialog-title">
    <div class="dialog-panel">
      <h2 id="attack-dialog-title" class="dialog-title">Attack Command</h2>
      <p id="attack-dialog-subtitle" class="dialog-subtitle"></p>
      <pre id="attack-command" class="dialog-command"></pre>
      <div id="attack-dialog-status" class="dialog-status"></div>
      <div class="dialog-actions">
        <button id="attack-copy-btn" class="dialog-copy-btn" type="button">Copy</button>
        <button id="attack-close-btn" class="dialog-close-btn" type="button">Close</button>
      </div>
    </div>
  </div>
<script>
let repositories = [];
let selectedIndex = 0;
let sortKey = "stars";
let sortDirection = "desc";
let reviewFilter = "all";
let activeAttackCommand = "";
const percentFormatter = new Intl.NumberFormat("de-DE", {
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function highlightYaml(content) {
  function highlightYamlValue(value) {
    return value.replace(
      /(&[A-Za-z0-9_-]+|\*[A-Za-z0-9_-]+|"(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*'|\\b(?:true|false|null)\\b|-?\\b\\d+(?:\\.\\d+)?\\b)/g,
      (token) => {
        if (token.startsWith("&") || token.startsWith("*")) {
          return "<span class='yaml-anchor'>" + token + "</span>";
        }
        if (token.startsWith('"') || token.startsWith("'")) {
          return "<span class='yaml-string'>" + token + "</span>";
        }
        if (/^(true|false|null)$/.test(token)) {
          return "<span class='yaml-bool'>" + token + "</span>";
        }
        return "<span class='yaml-number'>" + token + "</span>";
      }
    );
  }

  const lines = content.split("\n");
  return lines.map((line) => {
    const escaped = escapeHtml(line);
    if (escaped.trim().startsWith("#")) {
      return "<span class='yaml-comment'>" + escaped + "</span>";
    }
    const commentIndex = escaped.indexOf(" #");
    const codePart = commentIndex >= 0 ? escaped.slice(0, commentIndex) : escaped;
    const commentPart = commentIndex >= 0 ? escaped.slice(commentIndex + 1) : "";

    let rendered = codePart;
    let dashPrefix = "";
    const dashMatch = rendered.match(/^(\s*-\s+)(.*)$/);
    if (dashMatch) {
      dashPrefix = "<span class='yaml-dash'>" + dashMatch[1] + "</span>";
      rendered = dashMatch[2];
    }

    const keyValueMatch = rendered.match(/^(\s*[^:#\n][^:#\n]*?)(:\s*)(.*)$/);
    if (keyValueMatch) {
      const key = keyValueMatch[1];
      const sep = keyValueMatch[2];
      const value = keyValueMatch[3];
      rendered =
        dashPrefix +
        "<span class='yaml-key'>" + key + "</span>" +
        "<span class='yaml-punc'>" + sep + "</span>" +
        highlightYamlValue(value);
    } else {
      rendered = dashPrefix + highlightYamlValue(rendered);
    }

    if (commentPart) {
      return rendered + "<span class='yaml-comment'>#" + commentPart + "</span>";
    }
    return rendered;
  }).join("\n");
}

async function requestJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("HTTP " + response.status + " for " + url);
  }
  return await response.json();
}

async function loadRepositories() {
  const payload = await requestJson("/api/repositories");
  repositories = payload.repositories || [];
  renderRepositorySummary();
  renderRepositoryList();
  if (repositories.length > 0) {
    await selectRepository(0);
  } else {
    document.getElementById("repo-meta").textContent = "No repositories in input.";
  }
}

function renderRepositorySummary() {
  const total = repositories.length;
  const vulnerable = repositories.reduce(
    (count, repository) => count + (repository.has_vulnerable_risk ? 1 : 0),
    0
  );
  const notVulnerable = total - vulnerable;
  const vulnerableNode = document.getElementById("summary-vulnerable");
  const notVulnerableNode = document.getElementById("summary-not-vulnerable");
  const totalNode = document.getElementById("summary-total");
  if (vulnerableNode) {
    vulnerableNode.textContent = String(vulnerable);
  }
  if (notVulnerableNode) {
    notVulnerableNode.textContent = String(notVulnerable);
  }
  if (totalNode) {
    totalNode.textContent = String(total);
  }
}

function renderRepositoryList() {
  const container = document.getElementById("repo-list");
  container.innerHTML = "";
  const sorted = repositories
    .filter((repository) => matchesReviewFilter(repository))
    .sort((left, right) => compareRepositories(left, right));
  renderFilterStats(sorted.length);
  if (sorted.length === 0) {
    const item = document.createElement("li");
    item.className = "repo-item neutral";
    item.innerHTML = "<div class='repo-name'>No repositories match this filter.</div>";
    container.appendChild(item);
    return;
  }
  sorted.forEach((repository) => {
    const item = document.createElement("li");
    let statusClass = " neutral";
    if (repository.vulnerable_with_secret_or_write_gh_token === true) {
      statusClass = " secret-token-vulnerable";
    } else if (
      repository.vulnerable_with_secret_or_write_gh_token === false &&
      repository.has_vulnerable_risk
    ) {
      statusClass = " repo-vulnerable";
    } else if (Number(repository.error_count || 0) > 0 || Number(repository.vulnerable_count || 0) > 0) {
      statusClass = " vulnerable";
    } else if (Number(repository.needs_review_count || 0) > 0) {
      statusClass = " review";
    } else if (Number(repository.not_vulnerable_count || 0) > 0) {
      statusClass = " safe";
    }
    item.className = "repo-item" + statusClass + (repository.index === selectedIndex ? " active" : "");
    item.onclick = () => selectRepository(repository.index);
    const stats = [
      "<span class='mini-pill vuln'>Confirmed: " + Number(repository.vulnerable_count || 0) + "</span>",
      "<span class='mini-pill review'>Review: " + Number(repository.needs_review_count || 0) + "</span>",
      "<span class='mini-pill safe'>Safe: " + Number(repository.not_vulnerable_count || 0) + "</span>",
    ];
    const reviewFocus = repository.review_focus || {};
    if (Number(repository.error_count || 0) > 0) {
      stats.push("<span class='mini-pill error'>Errors: " + Number(repository.error_count || 0) + "</span>");
    }
    if (reviewFocus.mismatch) {
      stats.push("<span class='mini-pill review'>Mismatch</span>");
    }
    if (reviewFocus.has_security_source) {
      stats.push("<span class='mini-pill safe'>Has Source</span>");
    }
    if (reviewFocus.hookbin_empty_string) {
      stats.push("<span class='mini-pill review'>Hookbin Empty</span>");
    }
    if (reviewFocus.hookbin_missing_field) {
      stats.push("<span class='mini-pill review'>Hookbin Missing</span>");
    }
    const reviewReasons = Array.isArray(repository.review_reasons) ? repository.review_reasons : [];
    const showReviewReasonNote = Number(repository.needs_review_count || 0) > 1 && reviewReasons.length > 0;
    item.innerHTML = [
      "<div class='repo-name'>" + escapeHtml(repository.name) + "</div>",
      "<div class='repo-meta'><span>Risks: " + repository.risk_count + " | Stars: " + (repository.stars ?? "-") + "</span><span class='repo-stats'>" + stats.join("") + "</span></div>",
      showReviewReasonNote
        ? "<div class='review-reason-note'>Marked for review because: " + escapeHtml(reviewReasons.join(" | ")) + "</div>"
        : "",
      repository.error ? "<div class='repo-error-note'>Repository error: " + escapeHtml(String(repository.error)) + "</div>" : ""
    ].join("");
    container.appendChild(item);
  });
}

function matchesReviewFilter(repository) {
  if (reviewFilter === "all") {
    return true;
  }
  const reviewFocus = repository.review_focus || {};
  if (reviewFilter === "needs_human_review") {
    return !!reviewFocus.needs_human_review;
  }
  if (reviewFilter === "mismatch") {
    return !!reviewFocus.mismatch;
  }
  if (reviewFilter === "has_security_source") {
    return !!reviewFocus.has_security_source;
  }
  if (reviewFilter === "hookbin_empty_string") {
    return !!reviewFocus.hookbin_empty_string;
  }
  if (reviewFilter === "hookbin_not_empty_string") {
    return !!reviewFocus.hookbin_not_empty_string;
  }
  if (reviewFilter === "hookbin_missing_field") {
    return !!reviewFocus.hookbin_missing_field;
  }
  return true;
}

function renderFilterStats(visibleCount) {
  const statsNode = document.getElementById("filter-stats");
  const filterSelectNode = document.getElementById("review-filter");
  if (!statsNode) {
    return;
  }
  const totalCount = repositories.length;
  const selectedLabel =
    filterSelectNode && filterSelectNode.selectedOptions && filterSelectNode.selectedOptions[0]
      ? filterSelectNode.selectedOptions[0].textContent
      : "All";
  const percentage = totalCount > 0
    ? percentFormatter.format((visibleCount / totalCount) * 100)
    : percentFormatter.format(0);
  statsNode.textContent =
    "Filter: " + (selectedLabel || "All") +
    " | " + String(visibleCount) + " repositories (" + percentage + "% of total)";
}

function getSortedVisibleRepositories() {
  return repositories
    .filter((repository) => matchesReviewFilter(repository))
    .sort((left, right) => compareRepositories(left, right));
}

function compareRepositories(left, right) {
  let result = 0;
  if (sortKey === "name") {
    result = (left.name || "").localeCompare(right.name || "");
  } else if (sortKey === "stars") {
    result = Number(left.stars || 0) - Number(right.stars || 0);
  } else {
    result = Number(left.vulnerable_count || 0) - Number(right.vulnerable_count || 0);
  }
  if (result === 0) {
    result = (left.name || "").localeCompare(right.name || "");
  }
  return sortDirection === "asc" ? result : -result;
}

async function selectRepository(index) {
  selectedIndex = index;
  renderRepositoryList();
  const payload = await requestJson("/api/repository?index=" + index);
  renderRepository(payload.repository);
  fetch("/api/prefetch?from=" + index).catch(() => {});
}

async function selectFirstVisibleRepositoryIfNeeded() {
  const visible = getSortedVisibleRepositories();
  if (visible.length === 0) {
    document.getElementById("repo-meta").textContent = "No repositories in current filter.";
    document.getElementById("risk-container").innerHTML = "";
    return;
  }
  const hasCurrent = visible.some((repository) => repository.index === selectedIndex);
  if (hasCurrent) {
    await selectRepository(selectedIndex);
    return;
  }
  await selectRepository(visible[0].index);
}

function renderRepository(repository) {
  const repoMeta = document.getElementById("repo-meta");
  const repoUrl = "https://github.com/" + encodeURIComponent(repository.name || "").replace(/%2F/g, "/");
  const verdictCounts = repository.verdict_counts || {};
  const metaText =
    (repository.name || "") + "  |  Risks: " + repository.risks.length +
    "  |  Stars: " + (repository.stars ?? "-") +
    "  |  Confirmed: " + Number(verdictCounts.vulnerable || 0) +
    "  |  Review: " + Number(verdictCounts.needs_review || 0) +
    "  |  Safe: " + Number(verdictCounts.not_vulnerable || 0) +
    "  |  Errors: " + Number(verdictCounts.error || 0) +
    "  |  Created: " + (repository.repository_creation_date ?? "-") +
    (
      typeof repository.vulnerable_commit_hash === "string" &&
      repository.vulnerable_commit_hash.length > 0
        ? "  |  Vulnerable Commit: " + repository.vulnerable_commit_hash
        : ""
    );
  repoMeta.innerHTML =
    "<div class='repo-meta-row'>" +
      "<span class='repo-meta-text'>" + escapeHtml(metaText) + "</span>" +
      "<span class='repo-actions'>" +
        "<a class='repo-link-btn' href='" + repoUrl + "' target='_blank' rel='noopener noreferrer'>GitHub</a>" +
        "<button class='attack-btn' id='attack-btn' type='button' data-index='" + repository.index + "'>Attack</button>" +
      "</span>" +
    "</div>";
  if (repository.error) {
    repoMeta.innerHTML += "<div class='repo-error-banner'>Repository error: " + escapeHtml(String(repository.error)) + "</div>";
  }
  const attackButton = document.getElementById("attack-btn");
  if (attackButton) {
    attackButton.addEventListener("click", async () => {
      await prepareAttackCommand(repository.index);
    });
  }

  const container = document.getElementById("risk-container");
  container.innerHTML = "";

  repository.risks.forEach((risk) => {
    const riskNode = document.createElement("article");
    riskNode.className = "risk";
    const vulnerable = !!(risk.ai_analysis && risk.ai_analysis.vulnerable);
    const attackSummary = risk.attack_summary || null;
    const attackPanel = renderAttackPanel(attackSummary, risk.attack_processed_time);
    const triggerChips = (risk.triggers || []).map((trigger) => "<span class='chip'>" + escapeHtml(trigger) + "</span>").join("");
    const workflowButtons = (risk.workflows || []).map((workflow, index) => {
      const label = workflow.path + "@" + workflow.ref + (workflow.cache_status === "loaded" ? " (cached)" : "");
      return "<button class='workflow-btn' data-repo='" + encodeURIComponent(workflow.repo_name) + "' data-ref='" + encodeURIComponent(workflow.ref) + "' data-path='" + encodeURIComponent(workflow.path) + "' data-target='wf-" + risk.risk_index + "-" + index + "'>" + escapeHtml(label) + "</button><div class='yaml-title'>" + escapeHtml(workflow.repo_name + ":" + workflow.path + "@" + workflow.ref) + "</div><pre id='wf-" + risk.risk_index + "-" + index + "'><span class='yaml-placeholder'>Workflow not loaded yet.</span></pre>";
    }).join("");

    riskNode.innerHTML = [
      "<div class='risk-head'><strong>" + escapeHtml(risk.issue_type || "Risk") + "</strong>",
      "<span class='badge " + (vulnerable ? "bad" : "") + "'>" + escapeHtml(risk.human_summary.verdict) + " (" + escapeHtml(risk.human_summary.confidence) + ")</span></div>",
      "<div class='chips'>" + triggerChips + "</div>",
      "<div class='ai-grid'>",
      "<div class='field'><strong>Why</strong>" + escapeHtml(risk.human_summary.why) + "</div>",
      "<div class='field'><strong>Impact</strong>" + escapeHtml(risk.human_summary.impact) + "</div>",
      "<div class='field'><strong>Review Steps</strong>" + escapeHtml(risk.human_summary.review_steps) + "</div>",
      "<div class='field'><strong>Initial Workflow</strong>" + escapeHtml(risk.initial_workflow || "-") + "</div>",
      "</div>",
      attackPanel,
      "<div class='chips'><span class='chip'>Attack Complexity: " + escapeHtml(risk.attack_complexity || "-") + "</span><span class='chip'>Sink: " + escapeHtml(risk.sink || "-") + "</span></div>",
      workflowButtons || "<div class='field'>No workflow file references found in gato-x-path.</div>"
    ].join("");

    container.appendChild(riskNode);
  });

  container.querySelectorAll(".workflow-btn").forEach((button) => {
    const repo = button.dataset.repo;
    const ref = button.dataset.ref;
    const path = button.dataset.path;
    const targetId = button.dataset.target;
    const preNode = document.getElementById(targetId);
    if (!repo || !ref || !path || !preNode) {
      return;
    }

    const loadWorkflow = async () => {
      preNode.innerHTML = "<span class='yaml-loading'>Loading...</span>";
      try {
        const payload = await requestJson(
          "/api/workflow?repo=" + repo + "&ref=" + ref + "&path=" + path
        );
        if (payload.status === "loaded") {
          preNode.innerHTML = highlightYaml(payload.content || "");
        } else {
          preNode.innerHTML = "<span class='yaml-error'>Error: " + escapeHtml(payload.error || "Unknown error") + "</span>";
        }
      } catch (error) {
        preNode.innerHTML = "<span class='yaml-error'>Request failed: " + escapeHtml(String(error)) + "</span>";
      }
    };

    button.addEventListener("click", async () => {
      await loadWorkflow();
    });

    // Load workflow content automatically on first render.
    loadWorkflow().catch(() => {});
  });
}

function renderAttackPanel(attackSummary, attackProcessedTime) {
  if (!attackSummary) {
    return "<div class='attack-panel'><div class='attack-reason'>Attack result not available for this risk.</div></div>";
  }
  const statusRaw = attackSummary.status ? String(attackSummary.status) : "unknown";
  const statusClass = escapeHtml(statusRaw.toLowerCase().replace(/[^a-z0-9_-]+/g, "_"));
  const isError = !!(attackSummary.error_class || statusRaw.includes("error"));
  const fields = [
    "<div class='field'><strong>Attempts</strong>" + escapeHtml(String(attackSummary.attempt_count ?? "-")) + "</div>",
    "<div class='field'><strong>Run ID</strong>" + escapeHtml(String(attackSummary.execution_run_id ?? "-")) + "</div>",
    "<div class='field'><strong>Evidence</strong>" + escapeHtml(String(attackSummary.execution_evidence_source ?? "-")) + "</div>",
    "<div class='field'><strong>Confirmed by</strong>" + escapeHtml(String(attackSummary.security_report_verification_label || "Not confirmed")) + "</div>",
    "<div class='field'><strong>Probe</strong>" + escapeHtml(String(attackSummary.probe_status ?? "-")) + "</div>",
    "<div class='field'><strong>Token Perms</strong>" + escapeHtml(String(attackSummary.permissions_classification ?? "-")) + "</div>",
    "<div class='field'><strong>Processed</strong>" + escapeHtml(String(attackProcessedTime || "-")) + "</div>"
  ];
  if (typeof attackSummary.exploit_job === "string" && attackSummary.exploit_job.length > 0) {
    fields.push("<div class='field'><strong>Exploit Job</strong>" + escapeHtml(attackSummary.exploit_job) + "</div>");
  }
  if (attackSummary.pull_request_url) {
    const prUrl = String(attackSummary.pull_request_url);
    const safePrUrl = /^https?:\/\//.test(prUrl) ? encodeURI(prUrl) : "#";
    fields.push("<div class='field'><strong>PR</strong><a href='" + safePrUrl + "' target='_blank' rel='noopener noreferrer'>" + escapeHtml(prUrl) + "</a></div>");
  }
  if (attackSummary.error_class || attackSummary.failure_fingerprint || attackSummary.error_stage) {
    fields.push(
      "<div class='field'><strong>Error Details</strong>" +
      "class=" + escapeHtml(String(attackSummary.error_class || "-")) +
      ", stage=" + escapeHtml(String(attackSummary.error_stage || "-")) +
      ", fingerprint=" + escapeHtml(String(attackSummary.failure_fingerprint || "-")) +
      "</div>"
    );
  }
  const hasHookbinUrl = typeof attackSummary.hookbin_url === "string" && attackSummary.hookbin_url.length > 0;
  const hasHookbinLogs = typeof attackSummary.hookbin_logs === "string" && attackSummary.hookbin_logs.length > 0;
  const hasExploitPatch = typeof attackSummary.exploit_patch === "string" && attackSummary.exploit_patch.length > 0;
  let hookbinPanel = "";
  if (hasHookbinUrl || hasHookbinLogs) {
    const safeHookbinUrl = hasHookbinUrl && /^https?:\/\//.test(attackSummary.hookbin_url)
      ? encodeURI(String(attackSummary.hookbin_url))
      : "#";
    hookbinPanel = [
      "<div class='hookbin-panel'>",
      "<strong>Hookbin Logs</strong>",
      hasHookbinUrl
        ? "<div class='field'><strong>Hookbin URL</strong><a href='" + safeHookbinUrl + "' target='_blank' rel='noopener noreferrer'>" + escapeHtml(String(attackSummary.hookbin_url)) + "</a></div>"
        : "",
      "<pre class='hookbin-logs'>" + escapeHtml(String(attackSummary.hookbin_logs || "No Hookbin log content captured.")) + "</pre>",
      "</div>"
    ].join("");
  }
  let patchPanel = "";
  if (hasExploitPatch) {
    patchPanel = [
      "<div class='patch-panel'>",
      "<details>",
      "<summary>Exploit Patch</summary>",
      "<pre class='patch-logs'>" + escapeHtml(String(attackSummary.exploit_patch)) + "</pre>",
      "</details>",
      "</div>",
    ].join("");
  }
  return [
    "<div class='attack-panel " + (isError ? "error" : "") + "'>",
    "<div class='attack-status-line'><strong>Attack Execution</strong><span class='attack-status " + statusClass + "'>" + escapeHtml(statusRaw || "unknown") + "</span><span class='verification-pill'>" + escapeHtml(String(attackSummary.security_report_verification_label || "Not confirmed")) + "</span></div>",
    "<p class='attack-reason'>" + escapeHtml(String(attackSummary.reason || "No reason provided.")) + "</p>",
    "<div class='attack-grid'>" + fields.join("") + "</div>",
    hookbinPanel,
    patchPanel,
    "</div>"
  ].join("");
}

function setAttackDialogStatus(message) {
  const statusNode = document.getElementById("attack-dialog-status");
  if (statusNode) {
    statusNode.textContent = message;
  }
}

function openAttackDialog(repositoryName, command) {
  const dialogNode = document.getElementById("attack-dialog");
  const subtitleNode = document.getElementById("attack-dialog-subtitle");
  const commandNode = document.getElementById("attack-command");
  if (!dialogNode || !subtitleNode || !commandNode) {
    return;
  }
  subtitleNode.textContent = "Prepared command for " + repositoryName;
  commandNode.textContent = command;
  dialogNode.classList.remove("hidden");
}

function closeAttackDialog() {
  const dialogNode = document.getElementById("attack-dialog");
  if (!dialogNode) {
    return;
  }
  dialogNode.classList.add("hidden");
  setAttackDialogStatus("");
}

async function copyTextToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.setAttribute("readonly", "");
  textArea.style.position = "absolute";
  textArea.style.left = "-9999px";
  document.body.appendChild(textArea);
  textArea.select();
  document.execCommand("copy");
  document.body.removeChild(textArea);
}

async function prepareAttackCommand(index) {
  setAttackDialogStatus("Preparing single-repository input file...");
  try {
    const payload = await requestJson("/api/attack-command?index=" + index);
    activeAttackCommand = payload.command || "";
    openAttackDialog(payload.repository || "repository", activeAttackCommand);
    try {
      await copyTextToClipboard(activeAttackCommand);
      setAttackDialogStatus("Command copied to clipboard.");
    } catch (copyError) {
      setAttackDialogStatus("Command ready. Clipboard copy failed: " + String(copyError));
    }
  } catch (error) {
    activeAttackCommand = "";
    openAttackDialog("repository", "");
    setAttackDialogStatus("Failed to prepare attack command: " + String(error));
  }
}

loadRepositories().catch((error) => {
  document.getElementById("repo-meta").textContent = "Failed to load data: " + error;
});

const sortKeySelect = document.getElementById("sort-key");
const sortOrderButton = document.getElementById("sort-order");
const reviewFilterSelect = document.getElementById("review-filter");
if (sortKeySelect && sortOrderButton) {
  sortKeySelect.addEventListener("change", () => {
    sortKey = sortKeySelect.value || "stars";
    renderRepositoryList();
  });
  sortOrderButton.addEventListener("click", () => {
    sortDirection = sortDirection === "asc" ? "desc" : "asc";
    sortOrderButton.textContent = sortDirection === "asc" ? "Asc" : "Desc";
    renderRepositoryList();
  });
}
if (reviewFilterSelect) {
  reviewFilterSelect.addEventListener("change", async () => {
    reviewFilter = reviewFilterSelect.value || "all";
    renderRepositoryList();
    await selectFirstVisibleRepositoryIfNeeded();
  });
}

const attackDialog = document.getElementById("attack-dialog");
const attackCloseButton = document.getElementById("attack-close-btn");
const attackCopyButton = document.getElementById("attack-copy-btn");
if (attackDialog) {
  attackDialog.addEventListener("click", (event) => {
    if (event.target === attackDialog) {
      closeAttackDialog();
    }
  });
}
if (attackCloseButton) {
  attackCloseButton.addEventListener("click", () => {
    closeAttackDialog();
  });
}
if (attackCopyButton) {
  attackCopyButton.addEventListener("click", async () => {
    if (!activeAttackCommand) {
      setAttackDialogStatus("No command available to copy.");
      return;
    }
    try {
      await copyTextToClipboard(activeAttackCommand);
      setAttackDialogStatus("Command copied to clipboard.");
    } catch (error) {
      setAttackDialogStatus("Clipboard copy failed: " + String(error));
    }
  });
}
</script>
</body>
</html>
"""
