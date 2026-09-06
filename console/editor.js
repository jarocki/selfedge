/* SelfEdge console editor. Zero third-party code by default.
 *
 * OPTIONAL richer editor (from the awesome-wysiwyg list): vendor EasyMDE locally
 *   npm i easymde && cp node_modules/easymde/dist/easymde.min.* console/vendor/
 * then add to editor.html:  <link href="/assets/vendor/easymde.min.css" …>
 *                           <script src="/assets/vendor/easymde.min.js"></script>
 * If window.EasyMDE exists, the hook at the bottom upgrades the textarea.
 * Publishing safety does NOT depend on the editor: the server renders and
 * verifies everything regardless of how the markdown was written.
 */
const token = document.body.dataset.token;
history.replaceState(null, "", location.pathname); // drop ?token= from the URL bar

const $ = (s) => document.querySelector(s);
const status = (msg, cls = "") => { const el = $("#status"); el.textContent = msg; el.className = cls; };

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Console-Token": token, ...(opts.headers || {}) } });
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = j.error + (j.problems ? ": " + j.problems.join("; ") : ""); } catch {}
    throw new Error(detail);
  }
  return res.headers.get("content-type")?.includes("json") ? res.json() : res.text();
}

let current = null;
let dirty = false;

// ---------------- pages ----------------
async function loadPages() {
  const { pages, layouts } = await api("/api/pages");
  const ul = $("#pages"); ul.innerHTML = "";
  for (const p of pages) {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.textContent = p;
    b.addEventListener("click", () => openPage(p));
    li.appendChild(b); ul.appendChild(li);
  }
  const sel = $("#layout"); sel.innerHTML = "";
  for (const l of layouts) { const o = document.createElement("option"); o.value = o.textContent = l; sel.appendChild(o); }
  if (pages.length) openPage(pages[0]);
}

async function openPage(name) {
  if (dirty && !confirm("Discard unsaved changes?")) return;
  const { markdown } = await api("/api/page/" + name);
  current = name; dirty = false;
  $("#md").value = markdown;
  document.querySelectorAll("#pages button").forEach((b) => b.classList.toggle("active", b.textContent === name));
  syncLayoutFromDoc(); preview(); status("editing " + name);
}

// ---------------- layout <-> frontmatter ----------------
function syncLayoutFromDoc() {
  const m = $("#md").value.match(/^---[\s\S]*?\blayout\s*:\s*(\w+)[\s\S]*?---/);
  if (m) $("#layout").value = m[1];
}
$("#layout").addEventListener("change", () => {
  const ta = $("#md"); const v = $("#layout").value;
  if (/^---[\s\S]*?---/.test(ta.value)) {
    ta.value = /\blayout\s*:/.test(ta.value.split("---")[1] || "")
      ? ta.value.replace(/(\blayout\s*:\s*)\w+/, "$1" + v)
      : ta.value.replace(/^---\r?\n/, "---\nlayout: " + v + "\n");
  } else {
    ta.value = "---\nlayout: " + v + "\n---\n\n" + ta.value;
  }
  markDirty();
});

// ---------------- toolbar ----------------
function insertAtLineStart(prefix) {
  const ta = $("#md"); const { selectionStart: s } = ta;
  const lineStart = ta.value.lastIndexOf("\n", s - 1) + 1;
  ta.setRangeText(prefix, lineStart, lineStart); ta.focus(); markDirty();
}
function wrapSelection(mark) {
  const ta = $("#md"); const { selectionStart: s, selectionEnd: e } = ta;
  const sel = ta.value.slice(s, e) || "text";
  ta.setRangeText(mark + sel + mark, s, e, "select"); ta.focus(); markDirty();
}
document.querySelectorAll("#toolbar [data-md]").forEach((b) =>
  b.addEventListener("click", () => insertAtLineStart(b.dataset.md)));
document.querySelectorAll("#toolbar [data-wrap]").forEach((b) =>
  b.addEventListener("click", () => wrapSelection(b.dataset.wrap)));
$("#btn-link").addEventListener("click", () => {
  const url = prompt("Link address (https://…):", "https://");
  if (!url) return;
  const ta = $("#md"); const { selectionStart: s, selectionEnd: e } = ta;
  const sel = ta.value.slice(s, e) || "link text";
  ta.setRangeText("[" + sel + "](" + url + ")", s, e, "select"); ta.focus(); markDirty();
});

// ---------------- preview (server-rendered, sandboxed) ----------------
let previewTimer = null;
function preview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    try {
      const { frame } = await api("/api/preview", { method: "POST", body: $("#md").value });
      $("#preview").src = frame;
    } catch (e) { status("preview: " + e.message, "err"); }
  }, 400);
}
function markDirty() { dirty = true; status("unsaved changes"); preview(); }
$("#md").addEventListener("input", markDirty);

// ---------------- save / publish ----------------
async function save() {
  if (!current) return;
  await api("/api/page/" + current, { method: "PUT", body: $("#md").value });
  dirty = false; status("saved ✓", "ok");
}
$("#btn-save").addEventListener("click", () => save().catch((e) => status(e.message, "err")));
$("#btn-publish").addEventListener("click", async () => {
  try {
    await save();
    const r = await api("/api/publish", {
      method: "POST", body: JSON.stringify({ page: current }),
      headers: { "Content-Type": "application/json" },
    });
    status("published " + r.published + " ✓", "ok");
  } catch (e) { status("publish refused — " + e.message, "err"); }
});
window.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); save().catch((x) => status(x.message, "err")); }
});
window.addEventListener("beforeunload", (e) => { if (dirty) e.preventDefault(); });

// ---------------- optional EasyMDE upgrade ----------------
if (window.EasyMDE) {
  const mde = new window.EasyMDE({ element: $("#md"), autoDownloadFontAwesome: false, spellChecker: false, status: false });
  mde.codemirror.on("change", () => { $("#md").value = mde.value(); markDirty(); });
}

loadPages().catch((e) => status(e.message, "err"));
