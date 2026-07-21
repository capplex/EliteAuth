
const config = window.ELITEAUTH_CONFIG || null;
let supabaseClient = null;

function initializeSupabase() {
  if (supabaseClient) return supabaseClient;
  if (!window.supabase?.createClient) {
    throw new Error("The authentication library failed to load. Refresh the page and try again.");
  }
  if (!config?.supabaseUrl || !config?.supabasePublishableKey) {
    throw new Error("EliteAuth authentication is not configured correctly.");
  }
  supabaseClient = window.supabase.createClient(
    config.supabaseUrl,
    config.supabasePublishableKey,
    { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true } }
  );
  return supabaseClient;
}

// Public landing and donation pages do not need Supabase.
if (window.supabase?.createClient && config?.supabaseUrl && config?.supabasePublishableKey) {
  initializeSupabase();
}

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let dashboardApplications = [];
let generatedLicenses = [];
let generatedLicensesPage = 1;
let generatedLicensesPageSize = 50;
let dashboardLicenses = [];
let licensesPage = 1;
let licensesPageSize = 25;
const ELITEAUTH_SIGNING_PUBLIC_KEY = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
const ELITEAUTH_SIGNING_KEY_ID = "eliteauth-ed25519-2026-01";

function setMessage(element, message, type = "info") {
  if (!element) return;
  element.textContent = message;
  element.dataset.type = type;
  element.hidden = !message;
}

function friendlyError(error) {
  if (!error) return "Something went wrong.";
  const message = error.message || String(error);
  if (message.toLowerCase().includes("invalid login")) return "Incorrect email or password.";
  if (message.toLowerCase().includes("email not confirmed")) return "Verify your email before signing in.";
  return message;
}

async function getSession() {
  const { data, error } = await supabaseClient.auth.getSession();
  if (error) throw error;
  return data.session;
}

async function requireSession() {
  const session = await getSession();
  if (!session) {
    window.location.replace("login.html");
    return null;
  }
  return session;
}

async function redirectIfSignedIn() {
  const session = await getSession();
  if (session) window.location.replace("dashboard.html");
}

async function registerUser(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const message = $("#authMessage");
  const displayName = form.displayName.value.trim();
  const email = form.email.value.trim();
  const password = form.password.value;

  if (password.length < 8) {
    setMessage(message, "Password must be at least 8 characters.", "error");
    return;
  }

  button.disabled = true;
  button.textContent = "Creating account…";
  setMessage(message, "");

  const { data, error } = await supabaseClient.auth.signUp({
    email,
    password,
    options: {
      data: { display_name: displayName },
      emailRedirectTo: `${window.location.origin}/dashboard.html`
    }
  });

  button.disabled = false;
  button.textContent = "Create account →";

  if (error) {
    setMessage(message, friendlyError(error), "error");
    return;
  }

  if (data.session) {
    window.location.href = "dashboard.html";
  } else {
    setMessage(message, "Account created. Check your email and click the verification link.", "success");
    form.reset();
  }
}

async function loginUser(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const message = $("#authMessage");
  button.disabled = true;
  button.textContent = "Signing in…";
  setMessage(message, "");

  try {
    initializeSupabase();
    const { data, error } = await supabaseClient.auth.signInWithPassword({
      email: form.email.value.trim(),
      password: form.password.value
    });

    if (error) throw error;
    if (!data?.session) throw new Error("Sign-in succeeded but no session was created. Please try again.");
    window.location.replace("dashboard.html");
  } catch (error) {
    setMessage(message, friendlyError(error), "error");
  } finally {
    button.disabled = false;
    button.textContent = "Sign in →";
  }
}

async function logout() {
  await supabaseClient.auth.signOut();
  window.location.replace("login.html");
}

function getLicenseAlphabet(charset = "alphanumeric", letterCase = "upper", excludeAmbiguous = true) {
  let alphabet = charset === "letters"
    ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    : charset === "numbers"
      ? "0123456789"
      : "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  if (excludeAmbiguous) {
    alphabet = alphabet.replace(/[O0I1L]/g, "");
  }

  if (letterCase === "lower") alphabet = alphabet.toLowerCase();
  return alphabet || "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
}

function generateLicenseKey(application) {
  const prefix = String(application.license_prefix || "").trim();
  const groups = Math.min(10, Math.max(1, Number(application.key_groups) || 4));
  const charsPerGroup = Math.min(16, Math.max(2, Number(application.chars_per_group) || 4));
  const separator = application.key_separator ?? "-";
  const alphabet = getLicenseAlphabet(
    application.key_charset || "alphanumeric",
    application.key_case || "upper",
    application.exclude_ambiguous !== false
  );

  const randomBlock = () => {
    const bytes = new Uint32Array(charsPerGroup);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, value => alphabet[value % alphabet.length]).join("");
  };

  const parts = Array.from({ length: groups }, randomBlock);
  if (prefix) parts.unshift(application.key_case === "lower" ? prefix.toLowerCase() : prefix.toUpperCase());
  return parts.join(separator);
}

function updateLicenseFormatPreview() {
  const prefix = $("#licensePrefix");
  const groups = $("#keyGroups");
  const chars = $("#charsPerGroup");
  const separator = $("#keySeparator");
  const charset = $("#keyCharset");
  const letterCase = $("#keyCase");
  const exclude = $("#excludeAmbiguous");
  const preview = $("#licenseFormatPreview");
  if (!preview || !prefix || !groups || !chars || !separator || !charset || !letterCase || !exclude) return;

  const sample = generateLicenseKey({
    license_prefix: prefix.value.trim(),
    key_groups: Number(groups.value),
    chars_per_group: Number(chars.value),
    key_separator: separator.value,
    key_charset: charset.value,
    key_case: letterCase.value,
    exclude_ambiguous: exclude.checked
  });
  preview.textContent = sample;
}

async function loadApplications() {
  const { data, error } = await supabaseClient
    .from("applications")
    .select("id,owner_id,app_id,name,version,enabled,enforce_integrity,integrity_sha256,license_prefix,key_groups,chars_per_group,key_separator,key_charset,key_case,exclude_ambiguous,created_at")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
}

async function loadLicenses(applicationIds) {
  if (!applicationIds.length) return [];

  // Supabase projects commonly cap a single response at 1,000 rows.
  // Fetch every license in batches so the Licenses page, counters,
  // search, filters, and pagination work for the full account.
  const pageSize = 1000;
  const allLicenses = [];
  let from = 0;

  while (true) {
    const { data, error } = await supabaseClient
      .from("licenses")
      .select("id,key,status,hwid,activated_at,expires_at,duration_seconds,created_at,application_id,applications(name)")
      .in("application_id", applicationIds)
      .order("created_at", { ascending: false })
      .range(from, from + pageSize - 1);

    if (error) throw error;

    const batch = data || [];
    allLicenses.push(...batch);

    if (batch.length < pageSize) break;
    from += pageSize;
  }

  return allLicenses;
}


async function loadSessions(applicationIds) {
  if (!applicationIds.length) return [];
  const { data, error } = await supabaseClient
    .from("license_sessions")
    .select("id,hwid,created_at,expires_at,revoked_at,application_id,licenses(key),applications(name)")
    .in("application_id", applicationIds)
    .order("created_at", { ascending: false })
    .limit(100);
  if (error) {
    console.warn(error.message);
    return [];
  }
  return data || [];
}

async function loadSecurityEvents(applicationIds) {
  if (!applicationIds.length) return [];
  const { data, error } = await supabaseClient
    .from("security_events")
    .select("id,event_type,details,created_at,application_id,applications(name),licenses(key)")
    .in("application_id", applicationIds)
    .order("created_at", { ascending: false })
    .limit(100);
  if (error) {
    console.warn(error.message);
    return [];
  }
  return data || [];
}

function switchDashboardTab(tab) {
  const validTabs = ["overview", "applications", "licenses", "users", "sessions", "webhooks", "audit", "support"];
  if (!validTabs.includes(tab)) tab = "overview";
  $$("[data-dashboard-tab]").forEach(button => button.classList.toggle("active", button.dataset.dashboardTab === tab));
  $$("[data-dashboard-view]").forEach(view => view.classList.toggle("active", view.dataset.dashboardView === tab));
  const labels = {
    overview: ["Overview", "Your EliteAuth workspace at a glance."],
    applications: ["Applications", "Manage software projects and integration IDs."],
    licenses: ["Licenses", "Generate and control customer license keys."],
    users: ["Users", "View machines currently bound to licenses."],
    sessions: ["Sessions", "Monitor authentication sessions issued by your API."],
    webhooks: ["Webhooks", "Send signed authentication events to your server."],
    audit: ["Audit logs", "Review recent activity across your workspace."],
    support: ["Support EliteAuth", "Optional cryptocurrency donations. EliteAuth remains free and unlimited."]
  };
  $("#pageTitle").textContent = labels[tab][0];
  $("#pageSubtitle").textContent = labels[tab][1];
  history.replaceState(null, "", `#${tab}`);
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "Never";
}

function formatLicenseDuration(seconds) {
  if (seconds == null) return "Lifetime";
  const value = Number(seconds);
  if (value % 31536000 === 0) return `${value / 31536000} year${value === 31536000 ? "" : "s"}`;
  if (value % 2592000 === 0) return `${value / 2592000} month${value === 2592000 ? "" : "s"}`;
  if (value % 604800 === 0) return `${value / 604800} week${value === 604800 ? "" : "s"}`;
  if (value % 86400 === 0) return `${value / 86400} day${value === 86400 ? "" : "s"}`;
  if (value % 3600 === 0) return `${value / 3600} hour${value === 3600 ? "" : "s"}`;
  return `${Math.round(value / 60)} minute${value === 60 ? "" : "s"}`;
}

function bindDynamicDashboardButtons() {
  $$("[data-license-id]").forEach(button => {
    button.onclick = () => toggleLicense(button.dataset.licenseId, button.dataset.status);
  });
  $$("[data-reset-link-license]").forEach(button => {
    button.onclick = () => createHwidResetLink(button.dataset.resetLinkLicense);
  });
  $$("[data-approve-request]").forEach(button => {
    button.onclick = () => approveHwidRequest(button.dataset.approveRequest);
  });
  $$("[data-reject-request]").forEach(button => {
    button.onclick = () => rejectHwidRequest(button.dataset.rejectRequest);
  });
  $$("[data-delete-application]").forEach(button => {
    button.onclick = () => deleteApplication(button.dataset.deleteApplication, button.dataset.applicationName);
  });
  $$("[data-integrity-application]").forEach(button => {
    button.onclick = () => updateApplicationIntegrity(button.dataset.integrityApplication, button.dataset.integrityHash || "");
  });
  $$("[data-copy-generated-key]").forEach(button => {
    button.onclick = () => copySingleGeneratedLicense(button.dataset.copyGeneratedKey, button);
  });
}


const DASHBOARD_APP_ICON = `<svg class="dashboard-icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M3 9h18M9 9v12"/></svg>`;
function renderFullDashboard(apps, licenses, requests, sessions, securityEvents = []) {
  $("#applicationsTable").innerHTML = apps.length
    ? apps.map(app => `<tr>
        <td><strong>${escapeHtml(app.name)}</strong></td>
        <td><code>${escapeHtml(app.app_id || "Run updated SQL")}</code></td>
        <td>${escapeHtml(app.version || "1.0.0")}</td>
        <td><code>${escapeHtml((app.license_prefix || "") + (app.key_separator || "-") + "X".repeat(app.chars_per_group || 4))}…</code></td>
        <td><span class="request-status ${app.enforce_integrity ? "approved" : "pending"}">${app.enforce_integrity ? "Enforced" : "Optional"}</span>${app.enforce_integrity && app.integrity_sha256 ? `<small class="table-subtext"><code>${escapeHtml(app.integrity_sha256.slice(0, 12))}…</code></small>` : ""}</td>
        <td>${formatDate(app.created_at)}</td>
        <td><div class="table-actions"><button class="link-button" type="button" data-integrity-application="${app.id}" data-integrity-hash="${escapeHtml(app.integrity_sha256 || "")}">Integrity</button><button class="danger-button" type="button" data-delete-application="${app.id}" data-application-name="${escapeHtml(app.name)}">Delete</button></div></td>
      </tr>`).join("")
    : `<tr><td colspan="7" class="table-empty">No applications yet.</td></tr>`;

  dashboardLicenses = licenses;
  renderLicensePage();

  const users = licenses.filter(item => item.hwid);
  $("#usersTable").innerHTML = users.length
    ? users.map(item => `<tr>
        <td><code>${escapeHtml(item.key)}</code></td>
        <td>${escapeHtml(item.applications?.name || "Application")}</td>
        <td><code class="truncate-code">${escapeHtml(item.hwid)}</code></td>
        <td><span class="request-status ${item.status === "active" ? "approved" : "rejected"}">${escapeHtml(item.status)}</span></td>
        <td>${item.expires_at ? formatDate(item.expires_at) : "Lifetime"}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="table-empty">No activated users yet.</td></tr>`;

  $("#sessionsTable").innerHTML = sessions.length
    ? sessions.map(item => {
        const active = !item.revoked_at && new Date(item.expires_at) > new Date();
        return `<tr>
          <td>${escapeHtml(item.applications?.name || "Application")}</td>
          <td><code>${escapeHtml(item.licenses?.key || "—")}</code></td>
          <td><code class="truncate-code">${escapeHtml(item.hwid)}</code></td>
          <td>${formatDate(item.created_at)}</td>
          <td>${formatDate(item.expires_at)}</td>
          <td><span class="request-status ${active ? "approved" : "rejected"}">${active ? "Active" : "Expired"}</span></td>
        </tr>`;
      }).join("")
    : `<tr><td colspan="6" class="table-empty">No API sessions yet.</td></tr>`;

  const audit = [];
  apps.forEach(item => audit.push({ time: item.created_at, title: "Application created", detail: item.name }));
  licenses.forEach(item => audit.push({ time: item.created_at, title: "License generated", detail: `${item.key} · ${item.applications?.name || "Application"}` }));
  requests.forEach(item => audit.push({ time: item.requested_at, title: `HWID reset ${item.status}`, detail: item.licenses?.key || "License" }));
  securityEvents.forEach(item => audit.push({
    time: item.created_at,
    title: `Security: ${String(item.event_type || "event").replaceAll("_", " ")}`,
    detail: `${item.applications?.name || "Application"}${item.licenses?.key ? ` · ${item.licenses.key}` : ""}`
  }));
  audit.sort((a, b) => new Date(b.time) - new Date(a.time));
  $("#auditList").innerHTML = audit.length
    ? audit.map(item => `<div class="audit-item"><span class="audit-dot"></span><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.detail)}</p><small>${formatDate(item.time)}</small></div></div>`).join("")
    : `<div class="empty-state">No activity yet.</div>`;

  bindDynamicDashboardButtons();
}

function getFilteredDashboardLicenses() {
  const query = $("#licensesSearch")?.value.trim().toLowerCase() || "";
  const applicationId = $("#licensesApplicationFilter")?.value || "";
  return dashboardLicenses.filter(item => {
    const matchesQuery = !query || [item.key, item.hwid, item.status, item.applications?.name]
      .some(value => String(value || "").toLowerCase().includes(query));
    const matchesApplication = !applicationId || item.application_id === applicationId;
    return matchesQuery && matchesApplication;
  });
}

function renderLicensePage() {
  const filtered = getFilteredDashboardLicenses();
  const totalPages = Math.max(1, Math.ceil(filtered.length / licensesPageSize));
  licensesPage = Math.min(Math.max(1, licensesPage), totalPages);
  const startIndex = (licensesPage - 1) * licensesPageSize;
  const pageItems = filtered.slice(startIndex, startIndex + licensesPageSize);

  const list = $("#licensesFullList");
  if (list) {
    list.innerHTML = pageItems.length
      ? pageItems.map(item => `<div class="license full-license">
          <div><code>${escapeHtml(item.key)}</code><small>${escapeHtml(item.applications?.name || "Application")} · ${item.hwid ? "Activated" : "Not activated"} · ${item.hwid ? (item.expires_at ? `Expires ${formatDate(item.expires_at)}` : "Lifetime") : (item.duration_seconds ? `Starts on first activation (${formatLicenseDuration(item.duration_seconds)})` : "Lifetime")}</small></div>
          <div class="license-actions"><button class="link-button" data-reset-link-license="${item.id}">Reset link</button><button class="status-button ${item.status}" data-license-id="${item.id}" data-status="${item.status}">${item.status === "active" ? "Active" : "Disabled"}</button></div>
        </div>`).join("")
      : `<div class="empty-state">No licenses match your filters.</div>`;
  }

  const first = filtered.length ? startIndex + 1 : 0;
  const last = Math.min(startIndex + pageItems.length, filtered.length);
  if ($("#licensesPageLabel")) $("#licensesPageLabel").textContent = `Page ${licensesPage} of ${totalPages}`;
  if ($("#licensesRange")) $("#licensesRange").textContent = `Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${filtered.length.toLocaleString()}`;
  if ($("#licensesPrevious")) $("#licensesPrevious").disabled = licensesPage <= 1;
  if ($("#licensesNext")) $("#licensesNext").disabled = licensesPage >= totalPages;
  bindDynamicDashboardButtons();
}


async function createApplication(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const name = form.applicationName.value.trim();
  const session = await getSession();
  if (!session || !name) return;

  const groups = Number(form.keyGroups.value);
  const charsPerGroup = Number(form.charsPerGroup.value);

  if (!Number.isInteger(groups) || groups < 1 || groups > 10) {
    alert("Random groups must be between 1 and 10.");
    return;
  }
  if (!Number.isInteger(charsPerGroup) || charsPerGroup < 2 || charsPerGroup > 16) {
    alert("Characters per group must be between 2 and 16.");
    return;
  }

  const enforceIntegrity = Boolean(form.enforceIntegrity?.checked);
  const integritySha256 = form.integritySha256?.value.trim().toLowerCase() || "";
  if (enforceIntegrity && !/^[a-f0-9]{64}$/.test(integritySha256)) {
    alert("Enter the 64-character SHA-256 hash of the approved application build.");
    form.integritySha256?.focus();
    return;
  }

  const { data, error } = await supabaseClient.rpc("create_application_with_credentials", {
    name_input: name,
    prefix_input: form.licensePrefix.value.trim().slice(0, 20),
    groups_input: groups,
    chars_input: charsPerGroup,
    separator_input: form.keySeparator.value,
    charset_input: form.keyCharset.value,
    case_input: form.keyCase.value,
    exclude_ambiguous_input: form.excludeAmbiguous.checked,
    version_input: form.applicationVersion?.value.trim() || "1.0.0",
    enforce_integrity_input: Boolean(form.enforceIntegrity?.checked),
    integrity_sha256_input: form.enforceIntegrity?.checked
      ? form.integritySha256.value.trim().toLowerCase()
      : null
  });
  if (error) {
    alert(friendlyError(error));
    return;
  }
  const credentials = Array.isArray(data) ? data[0] : data;
  if (credentials) {
    showApplicationCredentials(credentials);
  }

  form.reset();
  form.licensePrefix.value = "ENMNT";
  form.keyGroups.value = "4";
  form.charsPerGroup.value = "4";
  form.keySeparator.value = "-";
  form.keyCharset.value = "alphanumeric";
  form.keyCase.value = "upper";
  form.excludeAmbiguous.checked = true;
  if (form.enforceIntegrity) form.enforceIntegrity.checked = false;
  if (form.integritySha256) {
    form.integritySha256.value = "";
    form.integritySha256.disabled = true;
  }
  updateLicenseFormatPreview();
  closeModal("applicationModal");
  await refreshDashboard();
}

async function createLicense(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const applicationId = form.applicationId.value;
  const durationAmount = Number(form.durationAmount.value);
  const durationUnit = form.durationUnit.value;
  const quantity = Number(form.licenseQuantity.value);
  if (!applicationId) return;

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 1000) {
    alert("Enter a quantity between 1 and 1,000.");
    return;
  }

  if (durationUnit !== "lifetime" && (!Number.isInteger(durationAmount) || durationAmount < 1 || durationAmount > 99999)) {
    alert("Enter a whole duration number between 1 and 99,999.");
    return;
  }

  let durationSeconds = null;
  if (durationUnit !== "lifetime") {
    const secondsPerUnit = {
      minutes: 60,
      hours: 60 * 60,
      days: 24 * 60 * 60,
      weeks: 7 * 24 * 60 * 60,
      months: 30 * 24 * 60 * 60,
      years: 365 * 24 * 60 * 60
    };
    if (!secondsPerUnit[durationUnit]) throw new Error("Invalid duration unit.");
    durationSeconds = durationAmount * secondsPerUnit[durationUnit];
  }

  const application = dashboardApplications.find(app => app.id === applicationId);
  if (!application) {
    alert("Select a valid application.");
    return;
  }

  const generatedKeys = new Set();
  while (generatedKeys.size < quantity) generatedKeys.add(generateLicenseKey(application));

  const rows = [...generatedKeys].map(key => ({
    application_id: applicationId,
    key,
    status: "active",
    duration_seconds: durationSeconds,
    hwid: null,
    activated_at: null,
    expires_at: null
  }));

  const submitButton = form.querySelector('button[type="submit"]');
  const originalText = submitButton?.textContent || "Generate licenses";
  if (submitButton) {
    submitButton.disabled = true;
    submitButton.textContent = `Generating ${quantity.toLocaleString()}…`;
  }

  const { error } = await supabaseClient.from("licenses").insert(rows);

  if (submitButton) {
    submitButton.disabled = false;
    submitButton.textContent = originalText;
  }

  if (error) {
    alert(friendlyError(error));
    return;
  }

  generatedLicenses = [...generatedKeys];
  generatedLicensesPage = 1;
  const searchInput = $("#generatedLicensesSearch");
  if (searchInput) searchInput.value = "";
  renderGeneratedLicenses();

  closeModal("licenseModal");
  openModal("generatedLicensesModal");
  await refreshDashboard();
}

function getFilteredGeneratedLicenses() {
  const query = $("#generatedLicensesSearch")?.value.trim().toLowerCase() || "";
  return query
    ? generatedLicenses.filter(key => key.toLowerCase().includes(query))
    : generatedLicenses;
}

function renderGeneratedLicenses() {
  const filtered = getFilteredGeneratedLicenses();
  const totalPages = Math.max(1, Math.ceil(filtered.length / generatedLicensesPageSize));
  generatedLicensesPage = Math.min(Math.max(1, generatedLicensesPage), totalPages);

  const startIndex = (generatedLicensesPage - 1) * generatedLicensesPageSize;
  const pageItems = filtered.slice(startIndex, startIndex + generatedLicensesPageSize);
  const list = $("#generatedLicensesList");
  const count = $("#generatedLicensesCount");
  const pageLabel = $("#generatedLicensesPageLabel");
  const rangeLabel = $("#generatedLicensesRange");
  const previous = $("#generatedLicensesPrevious");
  const next = $("#generatedLicensesNext");

  if (count) count.textContent = `${generatedLicenses.length.toLocaleString()} license${generatedLicenses.length === 1 ? "" : "s"} generated`;
  if (pageLabel) pageLabel.textContent = `Page ${generatedLicensesPage} of ${totalPages}`;
  if (rangeLabel) {
    const first = filtered.length ? startIndex + 1 : 0;
    const last = Math.min(startIndex + pageItems.length, filtered.length);
    rangeLabel.textContent = `Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${filtered.length.toLocaleString()}`;
  }
  if (previous) previous.disabled = generatedLicensesPage <= 1;
  if (next) next.disabled = generatedLicensesPage >= totalPages;

  if (list) {
    list.innerHTML = pageItems.length
      ? pageItems.map(key => `<div class="generated-license-row"><code>${escapeHtml(key)}</code><button class="link-button" type="button" data-copy-generated-key="${escapeHtml(key)}">Copy</button></div>`).join("")
      : `<div class="empty-state">No licenses match your search.</div>`;
  }

  bindDynamicDashboardButtons();
}

async function copyText(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
}

async function copySingleGeneratedLicense(key, button) {
  await copyText(key);
  if (!button) return;
  const original = button.textContent;
  button.textContent = "Copied!";
  setTimeout(() => { button.textContent = original; }, 1200);
}

async function copyGeneratedLicenses() {
  if (!generatedLicenses.length) return;
  await copyText(generatedLicenses.join("\n"));
  const button = $("#copyAllGeneratedLicenses");
  if (button) {
    const original = button.textContent;
    button.textContent = "Copied all!";
    setTimeout(() => { button.textContent = original; }, 1500);
  }
}

async function copyGeneratedLicensesPage() {
  const filtered = getFilteredGeneratedLicenses();
  const startIndex = (generatedLicensesPage - 1) * generatedLicensesPageSize;
  const pageItems = filtered.slice(startIndex, startIndex + generatedLicensesPageSize);
  if (!pageItems.length) return;
  await copyText(pageItems.join("\n"));
  const button = $("#copyGeneratedLicensesPage");
  if (button) {
    const original = button.textContent;
    button.textContent = "Copied page!";
    setTimeout(() => { button.textContent = original; }, 1500);
  }
}

function downloadGeneratedLicenses(format) {
  if (!generatedLicenses.length) return;
  const isCsv = format === "csv";
  const content = isCsv
    ? `license\n${generatedLicenses.map(key => `"${key.replaceAll('"', '""')}"`).join("\n")}`
    : generatedLicenses.join("\n");
  const blob = new Blob([content], { type: isCsv ? "text/csv" : "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `eliteauth-licenses-${new Date().toISOString().slice(0, 10)}.${isCsv ? "csv" : "txt"}`;
  link.click();
  URL.revokeObjectURL(url);
}

async function updateApplicationIntegrity(id, currentHash = "") {
  const value = window.prompt(
    "Enter the approved 64-character SHA-256 build hash. Leave it blank to disable integrity enforcement.",
    currentHash
  );
  if (value === null) return;
  const hash = value.trim().toLowerCase();
  if (hash && !/^[a-f0-9]{64}$/.test(hash)) {
    alert("The build hash must be exactly 64 hexadecimal characters.");
    return;
  }
  const { error } = await supabaseClient
    .from("applications")
    .update({ enforce_integrity: Boolean(hash), integrity_sha256: hash || null })
    .eq("id", id);
  if (error) {
    alert(friendlyError(error));
    return;
  }
  await refreshDashboard();
}

async function deleteApplication(id, name) {
  if (!id) return;
  const confirmed = window.confirm(`Delete “${name || "this application"}”?\n\nThis permanently deletes the application and all of its licenses, sessions, and HWID reset data. This cannot be undone.`);
  if (!confirmed) return;

  const { error } = await supabaseClient.from("applications").delete().eq("id", id);
  if (error) {
    alert(friendlyError(error));
    return;
  }
  await refreshDashboard();
}

function updateDurationPreview() {
  const amount = $("#durationAmount");
  const unit = $("#durationUnit");
  const preview = $("#durationPreview");
  if (!amount || !unit || !preview) return;

  const lifetime = unit.value === "lifetime";
  amount.disabled = lifetime;
  amount.required = !lifetime;

  if (lifetime) {
    preview.textContent = "This license will never expire.";
  } else {
    const value = Math.max(1, Number(amount.value) || 1);
    const label = unit.options[unit.selectedIndex].text.toLowerCase();
    preview.textContent = `This license will expire ${value} ${label} after its first successful activation.`;
  }
}

function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.hidden = false;
}
function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.hidden = true;
}

async function refreshDashboard() {
  const loading = $("#dashboardLoading");
  const content = $("#dashboardContent");
  try {
    const session = await requireSession();
    if (!session) return;

    const displayName = session.user.user_metadata?.display_name || session.user.email?.split("@")[0] || "Developer";
    $$("#displayName").forEach(el => el.textContent = displayName);
    $("#accountEmail").textContent = session.user.email || "";

    const apps = await loadApplications();
    dashboardApplications = apps;
    const licenses = await loadLicenses(apps.map(app => app.id));
    const hwidRequests = await loadHwidRequests();
    const sessions = await loadSessions(apps.map(app => app.id));
    const securityEvents = await loadSecurityEvents(apps.map(app => app.id));

    $("#applicationCount").textContent = apps.length.toLocaleString();
    $("#licenseCount").textContent = licenses.length.toLocaleString();
    $("#activeLicenseCount").textContent = licenses.filter(item => item.status === "active").length.toLocaleString();
    $("#disabledLicenseCount").textContent = licenses.filter(item => item.status !== "active").length.toLocaleString();

    const appList = $("#applicationList");
    appList.innerHTML = apps.length
      ? apps.map(app => `<div class="data-row"><div class="data-row-main"><span class="data-row-icon">${DASHBOARD_APP_ICON}</span><div><strong>${escapeHtml(app.name)}</strong><small>${escapeHtml(app.license_prefix || "No prefix")} · ${app.key_groups} groups × ${app.chars_per_group} chars · ${app.enforce_integrity ? "Integrity enforced" : "Integrity optional"} · ${new Date(app.created_at).toLocaleDateString()}</small></div></div><span class="badge">Application</span></div>`).join("")
      : `<div class="empty-state">No applications yet. Create your first one.</div>`;

    const select = $("#applicationId");
    select.innerHTML = `<option value="">Select application</option>` + apps.map(app => `<option value="${app.id}">${escapeHtml(app.name)}</option>`).join("");

    const licenseApplicationFilter = $("#licensesApplicationFilter");
    if (licenseApplicationFilter) {
      const currentFilter = licenseApplicationFilter.value;
      licenseApplicationFilter.innerHTML = `<option value="">All applications</option>` + apps.map(app => `<option value="${app.id}">${escapeHtml(app.name)}</option>`).join("");
      licenseApplicationFilter.value = apps.some(app => app.id === currentFilter) ? currentFilter : "";
    }

    const licenseList = $("#licenseList");
    const recentLicenses = licenses.slice(0, 20);
    licenseList.innerHTML = recentLicenses.length
      ? recentLicenses.map(item => `
        <div class="license">
          <div>
            <code>${escapeHtml(item.key)}</code>
            <small>${escapeHtml(item.applications?.name || "Application")} · ${item.expires_at ? `Expires ${new Date(item.expires_at).toLocaleDateString()}` : "Lifetime"}</small>
          </div>
          <div class="license-actions">
            <button class="link-button" data-reset-link-license="${item.id}">Reset link</button>
            <button class="status-button ${item.status}" data-license-id="${item.id}" data-status="${item.status}">
              ${item.status === "active" ? "Active" : "Disabled"}
            </button>
          </div>
        </div>`).join("")
      : `<div class="empty-state">No licenses yet.</div>`;

    const requestList = $("#hwidRequestList");
    requestList.innerHTML = hwidRequests.length
      ? hwidRequests.map(request => `
        <div class="request-card">
          <div class="request-details">
            <strong>${escapeHtml(request.licenses?.key || "License")}</strong>
            <small>${escapeHtml(request.licenses?.applications?.name || "Application")} · Requested ${new Date(request.requested_at).toLocaleString()}</small>
            <p>${escapeHtml(request.reason || "No reason provided.")}</p>
            <span class="request-status ${request.status}">${escapeHtml(request.status)}</span>
          </div>
          ${request.status === "pending" ? `
          <div class="request-actions">
            <button class="btn btn-primary request-btn" data-approve-request="${request.id}">Approve & reset</button>
            <button class="btn btn-secondary request-btn" data-reject-request="${request.id}">Reject</button>
          </div>` : ""}
        </div>`).join("")
      : `<div class="empty-state">No HWID reset requests.</div>`;

    $$("[data-license-id]").forEach(button => {
      button.addEventListener("click", () => toggleLicense(button.dataset.licenseId, button.dataset.status));
    });
    $$("[data-reset-link-license]").forEach(button => {
      button.addEventListener("click", () => createHwidResetLink(button.dataset.resetLinkLicense));
    });
    $$("[data-approve-request]").forEach(button => {
      button.addEventListener("click", () => approveHwidRequest(button.dataset.approveRequest));
    });
    $$("[data-reject-request]").forEach(button => {
      button.addEventListener("click", () => rejectHwidRequest(button.dataset.rejectRequest));
    });

    renderFullDashboard(apps, licenses, hwidRequests, sessions, securityEvents);
    loading.hidden = true;
    content.hidden = false;
  } catch (error) {
    loading.textContent = friendlyError(error);
  }
}



function showApplicationCredentials(credentials) {
  $("#credentialOwnerId").textContent = credentials.owner_id || "";
  $("#credentialAppId").textContent = credentials.app_id || "";
  $("#credentialServerSecret").textContent = credentials.server_secret || "";
  $("#credentialApiUrl").textContent = "https://api.eliteauth.lol";
  $("#credentialSigningPublicKey").textContent = ELITEAUTH_SIGNING_PUBLIC_KEY;
  closeModal("applicationModal");
  openModal("credentialsModal");
}

function downloadIntegrationConfig() {
  const config = {
    api_url: $("#credentialApiUrl")?.textContent || "https://api.eliteauth.lol",
    owner_id: $("#credentialOwnerId")?.textContent || "",
    app_id: $("#credentialAppId")?.textContent || "",
    app_version: "1.0.0",
    response_signing: {
      algorithm: "Ed25519",
      key_id: ELITEAUTH_SIGNING_KEY_ID,
      public_key: ELITEAUTH_SIGNING_PUBLIC_KEY
    },
    anti_tamper_protocol: "eliteauth-signed-v1",
    warning: "Pin the public verification key in the SDK. Never embed the server secret in distributed client software."
  };
  const blob = new Blob([JSON.stringify(config, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "eliteauth-config.json";
  link.click();
  URL.revokeObjectURL(url);
}

function secureToken(bytes = 24) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, b => b.toString(16).padStart(2, "0")).join("");
}

async function createHwidResetLink(licenseId) {
  const token = secureToken();
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  const { error } = await supabaseClient.from("hwid_reset_links").insert({
    license_id: licenseId,
    token,
    expires_at: expires
  });

  if (error) {
    alert(friendlyError(error));
    return;
  }

  const url = `${window.location.origin}/hwid-reset.html?token=${encodeURIComponent(token)}`;
  try {
    await navigator.clipboard.writeText(url);
    alert(`Reset request link copied to clipboard.\n\n${url}`);
  } catch {
    prompt("Copy this reset request link:", url);
  }
}

async function loadHwidRequests() {
  const { data, error } = await supabaseClient
    .from("hwid_reset_requests")
    .select("id,status,reason,requested_at,resolved_at,license_id,licenses(key,hwid,applications(name))")
    .order("requested_at", { ascending: false })
    .limit(50);
  if (error) throw error;
  return data || [];
}

async function approveHwidRequest(requestId) {
  const { error } = await supabaseClient.rpc("approve_hwid_reset_request", {
    request_id_input: requestId
  });
  if (error) alert(friendlyError(error));
  else await refreshDashboard();
}

async function rejectHwidRequest(requestId) {
  const { error } = await supabaseClient.rpc("reject_hwid_reset_request", {
    request_id_input: requestId
  });
  if (error) alert(friendlyError(error));
  else await refreshDashboard();
}

async function submitPublicHwidRequest(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const message = $("#resetMessage");
  const token = new URLSearchParams(window.location.search).get("token");
  const button = form.querySelector('button[type="submit"]');

  if (!token) {
    setMessage(message, "This reset link is invalid.", "error");
    return;
  }

  button.disabled = true;
  button.textContent = "Submitting…";
  const { data, error } = await supabaseClient.rpc("submit_hwid_reset_request", {
    token_input: token,
    reason_input: form.reason.value.trim() || null
  });
  button.disabled = false;
  button.textContent = "Submit HWID reset request";

  if (error) {
    setMessage(message, friendlyError(error), "error");
    return;
  }

  setMessage(message, data || "Your request was submitted for developer approval.", "success");
  form.reset();
  form.querySelectorAll("input,textarea,button").forEach(el => el.disabled = true);
}

const ELITEAUTH_DONATION_WALLETS = {
  BTC: { name: "Bitcoin", network: "Bitcoin", address: "bc1q3v7cs83u0jzqteqxzzm7wcd85lglc782zt3xmx", scheme: "bitcoin", priceId: "bitcoin", decimals: 8 },
  ETH: { name: "Ethereum", network: "Ethereum", address: "0x30596Ead0674415c6c7c0ED243F95A59EE546A17", scheme: "ethereum", priceId: "ethereum", decimals: 8 },
  LTC: { name: "Litecoin", network: "Litecoin", address: "ltc1qje2pqcznj24qf9ja79p3jgy99p7dstqqvyyewz", scheme: "litecoin", priceId: "litecoin", decimals: 8 },
  SOL: { name: "Solana", network: "Solana", address: "EyBBWTCd5uvbD16WT9sBeXEmCZZrqbkMXsF7VKF5wP62", scheme: "solana", priceId: "solana", decimals: 8 },
  USDT: { name: "USDT", network: "Ethereum ERC-20 only", address: "0x30596Ead0674415c6c7c0ED243F95A59EE546A17", scheme: null, priceId: "tether", decimals: 2 }
};

let donationUsdPrices = null;
let donationPricePromise = null;

async function loadDonationUsdPrices(force = false) {
  if (donationUsdPrices && !force) return donationUsdPrices;
  if (donationPricePromise && !force) return donationPricePromise;

  donationPricePromise = (async () => {
    const ids = Object.values(ELITEAUTH_DONATION_WALLETS).map(wallet => wallet.priceId).join(",");
    try {
      const response = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(ids)}&vs_currencies=usd`, {
        headers: { Accept: "application/json" }
      });
      if (!response.ok) throw new Error(`Price request failed (${response.status})`);
      const data = await response.json();
      donationUsdPrices = Object.fromEntries(Object.entries(ELITEAUTH_DONATION_WALLETS).map(([coin, wallet]) => [coin, Number(data?.[wallet.priceId]?.usd || (coin === "USDT" ? 1 : 0))]));
      return donationUsdPrices;
    } catch (error) {
      console.warn("Unable to load live crypto prices", error);
      donationUsdPrices = { USDT: 1 };
      return donationUsdPrices;
    } finally {
      donationPricePromise = null;
    }
  })();

  return donationPricePromise;
}

function formatCryptoAmount(value, decimals) {
  if (!Number.isFinite(value) || value <= 0) return "";
  return value.toLocaleString("en-US", {
    minimumFractionDigits: 0,
    maximumFractionDigits: decimals,
    useGrouping: false
  });
}

function updateDonationSelection() {
  const coin = $("#donationCoin")?.value || "BTC";
  const wallet = ELITEAUTH_DONATION_WALLETS[coin];
  if (!wallet) return;
  if ($("#donationNetwork")) $("#donationNetwork").textContent = wallet.network;
  if ($("#donationAddress")) $("#donationAddress").textContent = wallet.address;
  const warning = $("#donationWarning");
  if (warning) warning.textContent = coin === "USDT"
    ? "USDT must be sent only through Ethereum ERC-20. Do not use TRC-20, BEP-20, Solana, or another network. The displayed amount is an estimate in USD."
    : `Send only ${coin} using the ${wallet.network} network. The crypto amount is a live estimate and can change before payment.`;
  prepareDonation(false);
}

async function prepareDonation(showMessage = true) {
  const coin = $("#donationCoin")?.value || "BTC";
  const wallet = ELITEAUTH_DONATION_WALLETS[coin];
  const usdAmount = Number($("#donationAmount")?.value || 0);
  const amountOutput = $("#donationPreparedAmount");
  const openButton = $("#openDonationWallet");

  if (!(usdAmount > 0)) {
    if (amountOutput) amountOutput.textContent = "Enter a USD amount";
    if (openButton) openButton.hidden = true;
    if (showMessage) setMessage($("#donationMessage"), "Enter a donation amount greater than zero in USD.", "error");
    return;
  }

  if (amountOutput) amountOutput.textContent = "Getting live price…";
  const prices = await loadDonationUsdPrices();
  const usdPrice = Number(prices?.[coin] || (coin === "USDT" ? 1 : 0));

  if (!(usdPrice > 0)) {
    if (amountOutput) amountOutput.textContent = "Live estimate unavailable";
    if (openButton) openButton.hidden = true;
    if (showMessage) setMessage($("#donationMessage"), "The live exchange rate could not be loaded. Please try again shortly.", "error");
    return;
  }

  const cryptoAmount = usdAmount / usdPrice;
  const formattedAmount = formatCryptoAmount(cryptoAmount, wallet.decimals);
  const amountText = `${formattedAmount} ${coin}`;
  if (amountOutput) amountOutput.textContent = amountText;

  if (openButton) {
    if (wallet.scheme && coin !== "USDT") {
      openButton.href = `${wallet.scheme}:${wallet.address}?amount=${encodeURIComponent(formattedAmount)}`;
      openButton.hidden = false;
    } else {
      openButton.hidden = true;
    }
  }

  if (showMessage) {
    setMessage($("#donationMessage"), `Estimated donation: $${usdAmount.toFixed(2)} USD ≈ ${amountText}. Verify the final amount in your wallet before sending.`, "success");
  }
}

async function copyDonationValue(selector, label) {
  const value = $(selector)?.textContent?.trim();
  if (!value || value === "Enter a USD amount" || value === "Getting live price…" || value === "Live estimate unavailable") return;
  try {
    await navigator.clipboard.writeText(value.replace(/\s+(BTC|ETH|LTC|SOL|USDT)$/i, ""));
    setMessage($("#donationMessage"), `${label} copied.`, "success");
  } catch {
    prompt(`Copy ${label.toLowerCase()}:`, value);
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[char]));
}

document.addEventListener("DOMContentLoaded", async () => {
  const protectedPage = ["login", "register", "dashboard", "hwid-reset"].includes(document.body.dataset.page);
  if (protectedPage) {
    try {
      initializeSupabase();
    } catch (error) {
      setMessage($("#authMessage"), friendlyError(error), "error");
      console.error(error);
      return;
    }
  }

  const menu = $("#menuBtn");
  const links = $("#navLinks");
  if (menu && links) {
    const setMenuOpen = (open) => {
      links.classList.toggle("open", open);
      menu.setAttribute("aria-expanded", String(open));
      menu.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    };

    menu.addEventListener("click", () => setMenuOpen(!links.classList.contains("open")));
    links.querySelectorAll("a").forEach(link => link.addEventListener("click", () => setMenuOpen(false)));
    document.addEventListener("click", event => {
      if (!links.classList.contains("open")) return;
      if (!links.contains(event.target) && !menu.contains(event.target)) setMenuOpen(false);
    });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && links.classList.contains("open")) {
        setMenuOpen(false);
        menu.focus();
      }
    });
    window.addEventListener("resize", () => {
      if (window.innerWidth > 920) setMenuOpen(false);
    });
  }

  const revealElements = $$(".reveal");
  if (revealElements.length) {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) {
      revealElements.forEach(element => element.classList.add("is-visible"));
    } else {
      const revealObserver = new IntersectionObserver(entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            revealObserver.unobserve(entry.target);
          }
        });
      }, { threshold: 0.12, rootMargin: "0px 0px -35px" });
      revealElements.forEach(element => revealObserver.observe(element));
    }
  }

  if (document.body.dataset.page === "login") {
    await redirectIfSignedIn();
    $("#loginForm")?.addEventListener("submit", loginUser);
  }

  if (document.body.dataset.page === "register") {
    await redirectIfSignedIn();
    $("#registerForm")?.addEventListener("submit", registerUser);
  }

  if (document.body.dataset.page === "hwid-reset") {
    $("#hwidResetForm")?.addEventListener("submit", submitPublicHwidRequest);
  }


  if (document.body.dataset.page === "donate") {
    $("#donationCoin")?.addEventListener("change", updateDonationSelection);
    $("#donationAmount")?.addEventListener("input", () => prepareDonation(false));
    $("#prepareDonation")?.addEventListener("click", () => prepareDonation(true));
    $("#copyDonationAddress")?.addEventListener("click", () => copyDonationValue("#donationAddress", "Wallet address"));
    $("#copyDonationAmount")?.addEventListener("click", () => copyDonationValue("#donationPreparedAmount", "Donation amount"));
    updateDonationSelection();
  }

  if (document.body.dataset.page === "dashboard") {
    $("#logoutButton")?.addEventListener("click", logout);
    $$("[data-dashboard-tab]").forEach(button => button.addEventListener("click", () => switchDashboardTab(button.dataset.dashboardTab)));
    $$("[data-open]").forEach(button => button.addEventListener("click", () => openModal(button.dataset.open)));
    $("#refreshSessions")?.addEventListener("click", refreshDashboard);
    $("#generateWebhookSecret")?.addEventListener("click", () => { $("#webhookSecret").value = secureToken(24); });
    $("#saveWebhook")?.addEventListener("click", () => {
      const message = $("#webhookMessage");
      message.textContent = $("#webhookUrl").value
        ? "Webhook settings saved. Worker delivery configuration is the next backend step."
        : "Enter a webhook URL first.";
    });
    $("#donationCoin")?.addEventListener("change", updateDonationSelection);
    $("#donationAmount")?.addEventListener("input", () => prepareDonation(false));
    $("#prepareDonation")?.addEventListener("click", () => prepareDonation(true));
    $("#copyDonationAddress")?.addEventListener("click", () => copyDonationValue("#donationAddress", "Wallet address"));
    $("#copyDonationAmount")?.addEventListener("click", () => copyDonationValue("#donationPreparedAmount", "Donation amount"));
    updateDonationSelection();
    switchDashboardTab(location.hash.replace("#", "") || "overview");
    $("#openApplicationModal")?.addEventListener("click", () => openModal("applicationModal"));
    $("#downloadIntegrationConfig")?.addEventListener("click", downloadIntegrationConfig);
    $("#openLicenseModal")?.addEventListener("click", () => openModal("licenseModal"));
    $$("[data-close-modal]").forEach(button => button.addEventListener("click", () => closeModal(button.dataset.closeModal)));
    $("#applicationForm")?.addEventListener("submit", createApplication);
    ["licensePrefix","keyGroups","charsPerGroup","keySeparator","keyCharset","keyCase","excludeAmbiguous"].forEach(id => {
      document.getElementById(id)?.addEventListener(id === "licensePrefix" || id === "keyGroups" || id === "charsPerGroup" ? "input" : "change", updateLicenseFormatPreview);
    });
    const enforceIntegrity = $("#enforceIntegrity");
    const integritySha256 = $("#integritySha256");
    enforceIntegrity?.addEventListener("change", () => {
      if (!integritySha256) return;
      integritySha256.disabled = !enforceIntegrity.checked;
      if (enforceIntegrity.checked) integritySha256.focus();
    });
    updateLicenseFormatPreview();
    $("#licenseForm")?.addEventListener("submit", createLicense);
    $("#licensesSearch")?.addEventListener("input", () => { licensesPage = 1; renderLicensePage(); });
    $("#licensesApplicationFilter")?.addEventListener("change", () => { licensesPage = 1; renderLicensePage(); });
    $("#licensesPageSize")?.addEventListener("change", event => { licensesPageSize = Number(event.target.value) || 25; licensesPage = 1; renderLicensePage(); });
    $("#licensesPrevious")?.addEventListener("click", () => { licensesPage -= 1; renderLicensePage(); });
    $("#licensesNext")?.addEventListener("click", () => { licensesPage += 1; renderLicensePage(); });
    $("#copyAllGeneratedLicenses")?.addEventListener("click", copyGeneratedLicenses);
    $("#copyGeneratedLicensesPage")?.addEventListener("click", copyGeneratedLicensesPage);
    $("#generatedLicensesSearch")?.addEventListener("input", () => { generatedLicensesPage = 1; renderGeneratedLicenses(); });
    $("#generatedLicensesPageSize")?.addEventListener("change", event => { generatedLicensesPageSize = Number(event.target.value) || 50; generatedLicensesPage = 1; renderGeneratedLicenses(); });
    $("#generatedLicensesPrevious")?.addEventListener("click", () => { generatedLicensesPage -= 1; renderGeneratedLicenses(); });
    $("#generatedLicensesNext")?.addEventListener("click", () => { generatedLicensesPage += 1; renderGeneratedLicenses(); });
    $("#downloadGeneratedLicensesTxt")?.addEventListener("click", () => downloadGeneratedLicenses("txt"));
    $("#downloadGeneratedLicensesCsv")?.addEventListener("click", () => downloadGeneratedLicenses("csv"));
    $("#durationAmount")?.addEventListener("input", updateDurationPreview);
    $("#durationUnit")?.addEventListener("change", updateDurationPreview);
    updateDurationPreview();
    await refreshDashboard();
  }
});

if (supabaseClient) {
  supabaseClient.auth.onAuthStateChange((event) => {
    if (event === "SIGNED_OUT" && document.body.dataset.page === "dashboard") {
      window.location.replace("login.html");
    }
  });
}

const ELITEAUTH_SDK_EXAMPLES = {
  csharp: {
    language: "C#",
    path: "sdk/csharp/EliteAuthClient.cs",
    code: `using EliteAuth;

using var auth = new EliteAuthClient(
    "https://api.eliteauth.lol",
    "YOUR_APP_ID",
    "1.0.0",
    "APP_BUILD_SHA256"
);

var result = await auth.ActivateAsync(licenseKey, hwid);
if (!result.Success) throw new Exception(result.Error);

// Verifies the Ed25519 signature and rotates the one-time challenge.
var session = await auth.CheckSessionAsync(hwid);`
  },
  cpp: {
    language: "C++",
    path: "sdk/cpp/eliteauth.hpp",
    code: `#include "eliteauth.hpp"

EliteAuth::Client auth(
    "https://api.eliteauth.lol",
    "YOUR_APP_ID",
    "1.0.0",
    "APP_BUILD_SHA256"
);

auto result = auth.activate(licenseKey, hwid);
if (!result.success) throw std::runtime_error(result.error);

auto session = auth.check_session(hwid);`
  },
  python: {
    language: "Python",
    path: "sdk/python/eliteauth.py",
    code: `from eliteauth import EliteAuthClient

auth = EliteAuthClient(
    "https://api.eliteauth.lol",
    "YOUR_APP_ID",
    "1.0.0",
    integrity_sha256="APP_BUILD_SHA256",
)

result = auth.activate(license_key, hwid)
if not result.success:
    raise RuntimeError(result.error)

session = auth.check_session(hwid)`
  },
  javascript: {
    language: "JavaScript",
    path: "sdk/javascript/eliteauth.js",
    code: `import { EliteAuthClient } from "./eliteauth.js";

const auth = new EliteAuthClient(
  "https://api.eliteauth.lol",
  "YOUR_APP_ID",
  "1.0.0",
  { integritySha256: "APP_BUILD_SHA256" }
);

const result = await auth.activate(licenseKey, hwid);
if (!result.success) throw new Error(result.error);

const session = await auth.checkSession(hwid);`
  },
  typescript: {
    language: "TypeScript",
    path: "sdk/typescript/eliteauth.ts",
    code: `import { EliteAuthClient } from "./eliteauth";

const auth = new EliteAuthClient({
  apiUrl: "https://api.eliteauth.lol",
  appId: "YOUR_APP_ID",
  version: "1.0.0",
  integritySha256: "APP_BUILD_SHA256"
});

const result = await auth.activate(licenseKey, hwid);
if (!result.success) throw new Error(result.error);

const session = await auth.checkSession(hwid);`
  },
  java: {
    language: "Java",
    path: "sdk/java/EliteAuthClient.java",
    code: `EliteAuthClient auth = new EliteAuthClient(
    "https://api.eliteauth.lol",
    "YOUR_APP_ID",
    "1.0.0",
    "APP_BUILD_SHA256"
);

var result = auth.activate(licenseKey, hwid);
if (!result.success()) throw new IllegalStateException(result.error());

var session = auth.checkSession(hwid);`
  },
  go: {
    language: "Go",
    path: "sdk/go/eliteauth.go",
    code: `auth, err := eliteauth.NewClient(
    "https://api.eliteauth.lol",
    "YOUR_APP_ID",
    "1.0.0",
    "APP_BUILD_SHA256",
)
if err != nil { log.Fatal(err) }

result, err := auth.Activate(ctx, licenseKey, hwid)
if err != nil || !result.Success { log.Fatal(result.Error) }

session, err := auth.CheckSession(ctx, hwid)`
  },
  rust: {
    language: "Rust",
    path: "sdk/rust/src/lib.rs",
    code: `let mut auth = EliteAuthClient::new(
    "https://api.eliteauth.lol",
    "YOUR_APP_ID",
    "1.0.0",
    Some("APP_BUILD_SHA256".into()),
)?;

let result = auth.activate(&license_key, &hwid).await?;
if !result.success { return Err(result.error.unwrap_or_default().into()); }

let session = auth.check_session(&hwid).await?;`
  }
};

function initializeSdkTabs() {
  const buttons = $$('[data-sdk]');
  const language = $("#sdkLanguage");
  const path = $("#sdkPath");
  const code = $("#sdkCode");
  const example = $("#sdkExample");
  if (!buttons.length || !language || !path || !code || !example) return;

  const selectSdk = (key, focus = false) => {
    const sdk = ELITEAUTH_SDK_EXAMPLES[key];
    if (!sdk) return;
    language.textContent = sdk.language;
    path.textContent = sdk.path;
    code.textContent = sdk.code;
    example.setAttribute("aria-label", `${sdk.language} SDK example`);

    buttons.forEach(button => {
      const selected = button.dataset.sdk === key;
      button.classList.toggle("active", selected);
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
      if (selected && focus) button.focus();
    });
  };

  buttons.forEach((button, index) => {
    button.addEventListener("click", () => selectSdk(button.dataset.sdk));
    button.addEventListener("keydown", event => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      let nextIndex = index;
      if (event.key === "ArrowLeft") nextIndex = (index - 1 + buttons.length) % buttons.length;
      if (event.key === "ArrowRight") nextIndex = (index + 1) % buttons.length;
      if (event.key === "Home") nextIndex = 0;
      if (event.key === "End") nextIndex = buttons.length - 1;
      selectSdk(buttons[nextIndex].dataset.sdk, true);
    });
  });

  const initial = buttons.find(button => button.classList.contains("active"))?.dataset.sdk || "javascript";
  selectSdk(initial);
}

document.addEventListener("DOMContentLoaded", initializeSdkTabs);
