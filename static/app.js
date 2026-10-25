// Plain JS frontend for the secure storage app
const $ = (id) => document.getElementById(id);
const ALGOS = ["aes", "des", "rc4"];
let items = {}; // id -> item from /api/items

// Escape text before putting it into innerHTML (filenames are user input)
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const kb = (n) => (n / 1024).toFixed(1) + " KB";

// fetch wrapper: throws the server's error message on non-2xx
async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `${res.status} ${res.statusText}`);
  }
  return res;
}

// Show a message (errors in red via CSS)
function say(text) { $("msg").textContent = text; }

// Decide which section to show based on login state
async function refresh() {
  try {
    const { username } = await (await api("/api/me")).json();
    $("who").textContent = username;
    $("auth").hidden = true;
    $("main").hidden = false;
    await loadItems();
  } catch {
    $("auth").hidden = false;
    $("main").hidden = true;
  }
}

// Login or register depending on which button submitted the form
$("authForm").onsubmit = async (e) => {
  e.preventDefault();
  const action = e.submitter.value;
  const body = JSON.stringify(Object.fromEntries(new FormData(e.target)));
  try {
    await api(`/api/${action}`, { method: "POST", headers: { "Content-Type": "application/json" }, body });
    say(action === "register" ? "Register berhasil, silakan login." : "");
    if (action === "login") await refresh();
  } catch (err) { say(err.message); }
};

$("logout").onclick = async () => { await api("/api/logout", { method: "POST" }); say(""); refresh(); };

// Upload a Blob/File as a given kind
async function upload(kind, file) {
  const fd = new FormData();
  fd.append("kind", kind);
  fd.append("file", file);
  await api("/api/items", { method: "POST", body: fd });
  await loadItems();
}

// Private data form -> JSON file -> encrypted like any other file
$("profileForm").onsubmit = async (e) => {
  e.preventDefault();
  const json = JSON.stringify(Object.fromEntries(new FormData(e.target)), null, 2);
  try { await upload("profile", new File([json], "profile.json", { type: "application/json" })); say("Data pribadi tersimpan."); }
  catch (err) { say(err.message); }
};

// File upload form
$("uploadForm").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try { await upload(fd.get("kind"), fd.get("file")); say("File tersimpan."); e.target.reset(); }
  catch (err) { say(err.message); }
};

// Render the items table
async function loadItems() {
  const list = await (await api("/api/items")).json();
  items = Object.fromEntries(list.map((i) => [i.id, i]));
  $("items").innerHTML = list.map((i) => `
    <tr>
      <td>${i.id}</td><td>${esc(i.kind)}</td><td>${esc(i.filename)}</td><td>${kb(i.size)}</td>
      ${ALGOS.map((a) => `<td>${kb(i.ciphers[a].ct_size)}<br>${i.ciphers[a].enc_ms.toFixed(2)} ms</td>`).join("")}
      <td>
        <select data-algo="${i.id}">${ALGOS.map((a) => `<option>${a}</option>`).join("")}</select>
        <button data-act="view" data-id="${i.id}">Lihat</button>
        <button data-act="cipher" data-id="${i.id}">Ciphertext</button>
        <button data-act="bench" data-id="${i.id}">Benchmark x10</button>
      </td>
    </tr>`).join("");
}

// One click handler for all row buttons
$("items").onclick = (e) => {
  const { act, id } = e.target.dataset;
  if (!act) return;
  const algo = document.querySelector(`[data-algo="${id}"]`).value;
  const run = { view: () => view(id, algo), cipher: () => showCipher(id), bench: () => bench(id, 10) }[act];
  run().catch((err) => say(err.message));
};

// Download + decrypt with one algorithm and display it
async function view(id, algo) {
  const res = await api(`/api/items/${id}/download?algo=${algo}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const item = items[id];
  let content;
  if (item.mime.startsWith("image/")) content = `<img src="${url}">`;
  else if (item.mime.startsWith("video/")) content = `<video src="${url}" controls></video>`;
  else if (item.mime === "application/json") content = `<pre>${esc(await blob.text())}</pre>`;
  else content = `<a href="${url}" download="${esc(item.filename)}">Download ${esc(item.filename)}</a>`;
  $("output").innerHTML = `<p>Item ${id} didekripsi dengan <b>${algo.toUpperCase()}</b> dalam
    ${res.headers.get("X-Decrypt-Ms")} ms (server).</p>${content}`;
}

// Show what is actually stored in the DB for each algorithm
async function showCipher(id) {
  const c = items[id].ciphers;
  $("output").innerHTML = `<p>Ciphertext item ${id} (ukuran asli ${items[id].size} byte):</p>
    <table><tr><th>Algo</th><th>IV / nonce (hex)</th><th>Ukuran ciphertext</th><th>24 byte pertama (hex)</th><th>Enkripsi</th></tr>
    ${ALGOS.map((a) => `<tr><td>${a.toUpperCase()}</td><td><code>${c[a].iv}</code></td><td>${c[a].ct_size} byte</td>
      <td><code>${c[a].preview}</code></td><td>${c[a].enc_ms.toFixed(3)} ms</td></tr>`).join("")}</table>`;
}

// Download the item n times per algorithm and average the timings
async function bench(id, n) {
  $("output").textContent = "Benchmark berjalan...";
  const rows = [];
  for (const algo of ALGOS) {
    let server = 0, total = 0, buf;
    for (let k = 0; k < n; k++) {
      const t0 = performance.now();
      const res = await api(`/api/items/${id}/download?algo=${algo}`);
      buf = await res.arrayBuffer();
      total += performance.now() - t0;
      server += parseFloat(res.headers.get("X-Decrypt-Ms"));
    }
    // SHA-256 of the decrypted result proves all algorithms return identical plaintext
    const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", buf))]
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    rows.push({ algo, server: server / n, total: total / n, hash });
  }
  const same = rows.every((r) => r.hash === rows[0].hash);
  $("output").innerHTML = `<p>Benchmark item ${id} (${kb(items[id].size)}), ${n}x download per algoritma:</p>
    <table><tr><th>Algo</th><th>Rata-rata dekripsi (server)</th><th>Rata-rata total download</th><th>SHA-256 hasil</th></tr>
    ${rows.map((r) => `<tr><td>${r.algo.toUpperCase()}</td><td>${r.server.toFixed(3)} ms</td>
      <td>${r.total.toFixed(2)} ms</td><td><code>${r.hash.slice(0, 16)}…</code></td></tr>`).join("")}</table>
    <p>Hasil dekripsi ketiga algoritma ${same ? "IDENTIK ✔" : "BERBEDA ✘ (bug!)"}</p>`;
}

refresh();
