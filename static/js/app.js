"use strict";

const COLORS = {
  Open: "#ff5a5a", WEP: "#ff9f43", WPA: "#f6c945",
  WPA2: "#38e1b0", WPA3: "#4aa3ff", bluetooth: "#b07aff",
};

// Fuentes de ubicación derivadas de PPI-GPS (fix real de la captura).
const GPS_SOURCES = new Set(["best-signal", "centroid"]);
const isOsintLoc = (loc) => loc && !GPS_SOURCES.has(loc.source);

const state = {
  data: null,
  tab: "wifi",
  filter: "",
  selected: null,        // addr
  markers: {},           // addr -> leaflet marker
  track: null,           // active polyline layer
  layer: null,           // markers layergroup
};

let map;

function initMap() {
  map = L.map("map", { zoomControl: true, attributionControl: true })
         .setView([40.4168, -3.7038], 15);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "&copy; OpenStreetMap &copy; CARTO",
    maxZoom: 20,
  }).addTo(map);
  state.layer = L.layerGroup().addTo(map);
  addLegend();
}

function addLegend() {
  const el = document.createElement("div");
  el.className = "legend";
  el.innerHTML = `
    <div class="lrow"><span class="dot" style="background:${COLORS.Open}"></span>Abierta</div>
    <div class="lrow"><span class="dot" style="background:${COLORS.WEP}"></span>WEP</div>
    <div class="lrow"><span class="dot" style="background:${COLORS.WPA2}"></span>WPA/WPA2</div>
    <div class="lrow"><span class="dot" style="background:${COLORS.WPA3}"></span>WPA3</div>
    <div class="lrow"><span class="dot" style="background:${COLORS.bluetooth}"></span>Bluetooth</div>
    <div class="lrow"><span class="dot ring"></span>Ubicación OSINT (geowifi)</div>`;
  document.querySelector(".mapwrap").appendChild(el);
}

function colorFor(d) {
  return d.kind === "bluetooth" ? COLORS.bluetooth : (COLORS[d.encryption] || "#8892a8");
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function rssiPct(rssi) {
  if (rssi == null) return 0;
  return Math.max(0, Math.min(100, Math.round((rssi + 100) * (100 / 70))));
}

// ---------- data loading ----------

async function upload(file) {
  showLoading(true);
  const fd = new FormData();
  fd.append("file", file);
  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "Error desconocido");
    onData(json);
  } catch (e) {
    banner(e.message, true);
  } finally {
    showLoading(false);
  }
}

async function loadSample() {
  showLoading(true);
  try {
    const res = await fetch("/api/sample");
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "No hay ejemplo");
    onData(json);
  } catch (e) {
    banner(e.message, true);
  } finally {
    showLoading(false);
  }
}

function onData(json) {
  state.data = json;
  state.selected = null;
  document.getElementById("dropzone").classList.add("hidden");
  renderStats(json.meta);
  document.getElementById("wifiCount").textContent = json.meta.wifi_count;
  document.getElementById("btCount").textContent = json.meta.bluetooth_count;

  if (!json.meta.has_gps) {
    banner("La captura no contiene coordenadas GPS (etiquetas PPI-GPS). Se listan " +
           "las redes y dispositivos, pero no pueden situarse en el mapa. Captura con " +
           "GPS (Kismet / airodump-ng con GPSd) para geolocalizar.", false);
  } else {
    document.getElementById("banner").classList.add("hidden");
  }
  renderMarkers();
  renderList();
  updateGeowifiBtn();
  if (json.meta.bounds) {
    const b = json.meta.bounds;
    map.fitBounds([[b.min_lat, b.min_lon], [b.max_lat, b.max_lon]], { padding: [60, 60] });
  }
}

function renderStats(m) {
  const bar = document.getElementById("statsBar");
  bar.classList.remove("hidden");
  bar.innerHTML = `
    <div class="stat"><b>${m.filename}</b></div>
    <div class="stat"><b>${m.packet_count}</b><span>paquetes</span></div>
    <div class="stat"><b>${m.wifi_count}</b><span>redes WiFi</span></div>
    <div class="stat"><b>${m.bluetooth_count}</b><span>dispositivos BT</span></div>
    <div class="stat"><b>${m.located_count}</b><span>geolocalizados</span></div>
    <div class="stat"><b>${m.gps_points}</b><span>fixes GPS</span></div>`;
}

function banner(msg, isErr) {
  const el = document.getElementById("banner");
  el.textContent = msg;
  el.className = "banner" + (isErr ? " err" : "");
}

function showLoading(on) {
  document.getElementById("loading").classList.toggle("hidden", !on);
}

// ---------- rendering ----------

function currentList() {
  const arr = state.tab === "wifi" ? state.data.wifi : state.data.bluetooth;
  const f = state.filter.toLowerCase();
  if (!f) return arr;
  return arr.filter(d =>
    (d.name || "").toLowerCase().includes(f) ||
    d.addr.toLowerCase().includes(f) ||
    (d.encryption || "").toLowerCase().includes(f) ||
    (d.vendor || "").toLowerCase().includes(f));
}

function renderMarkers() {
  state.layer.clearLayers();
  state.markers = {};
  const all = [...state.data.wifi, ...state.data.bluetooth];
  for (const d of all) {
    if (!d.location) continue;
    const osint = isOsintLoc(d.location);
    const marker = L.circleMarker([d.location.lat, d.location.lon], {
      radius: 8, weight: 2,
      color: osint ? colorFor(d) : "#0b0f17",
      dashArray: osint ? "3,3" : null,
      fillColor: colorFor(d),
      fillOpacity: osint ? 0.3 : 0.95,
    });
    marker.bindPopup(popupHtml(d));
    marker.on("click", () => select(d.addr, d.kind, false));
    marker.addTo(state.layer);
    state.markers[d.addr] = marker;
  }
}

function popupHtml(d) {
  const label = d.kind === "wifi"
    ? `${d.encryption} · canal ${d.channel ?? "?"}`
    : `Bluetooth LE · ${d.device_type || ""}`;
  const osint = isOsintLoc(d.location)
    ? `<br><i style="color:${COLORS.WPA}">📍 ubicación OSINT (geowifi), no GPS</i>` : "";
  return `<b>${escapeHtml(d.name || "(sin nombre)")}</b><br>${d.addr}<br>${label}<br>RSSI ${d.best_signal ?? "?"} dBm${osint}`;
}

function renderList() {
  const list = document.getElementById("list");
  const items = currentList();
  if (!items.length) {
    list.innerHTML = `<div class="empty">Sin resultados.</div>`;
    return;
  }
  items.sort((a, b) => (b.best_signal ?? -999) - (a.best_signal ?? -999));
  list.innerHTML = "";
  for (const d of items) {
    const div = document.createElement("div");
    div.className = "item" + (d.addr === state.selected ? " active" : "") + (d.location ? "" : " nogps");
    const sub = d.kind === "wifi"
      ? `${d.addr} · ${d.vendor || "?"}`
      : `${d.addr} · ${d.vendor || "?"}`;
    const badge = d.kind === "wifi" ? (d.encryption || "?") : "BLE";
    div.innerHTML = `
      <span class="dot" style="background:${colorFor(d)}"></span>
      <div class="meta">
        <div class="name">${escapeHtml(d.name || "(sin nombre)")}</div>
        <div class="sub">${escapeHtml(sub)}</div>
      </div>
      <span class="badge">${escapeHtml(badge)}</span>`;
    div.onclick = () => select(d.addr, d.kind, true);
    list.appendChild(div);
  }
}

function findDevice(addr, kind) {
  const arr = kind === "wifi" ? state.data.wifi : state.data.bluetooth;
  return arr.find(d => d.addr === addr);
}

function select(addr, kind, fromList) {
  // switch tab if selecting from a marker of the other kind
  if (kind !== state.tab) {
    state.tab = kind;
    syncTabs();
  }
  state.selected = addr;
  renderList();
  const d = findDevice(addr, kind);
  if (!d) return;
  renderDetail(d);

  if (state.track) { map.removeLayer(state.track); state.track = null; }
  if (d.location) {
    map.panTo([d.location.lat, d.location.lon]);
    const m = state.markers[addr];
    if (m) m.openPopup();
    if (d.sightings && d.sightings.length > 1) {
      const pts = d.sightings.map(s => [s.lat, s.lon]);
      state.track = L.polyline(pts, { color: colorFor(d), weight: 2, dashArray: "4,4", opacity: .7 }).addTo(map);
    }
  }
}

function renderDetail(d) {
  const el = document.getElementById("detail");
  el.classList.remove("hidden");
  const rows = [];
  const push = (k, v) => rows.push(`<div class="drow"><span class="k">${k}</span><span class="v">${v}</span></div>`);

  const color = colorFor(d);
  if (d.kind === "wifi") {
    push("BSSID", `<code>${d.addr}</code>`);
    push("Cifrado", `<span class="tag" style="background:${color}22;color:${color}">${d.encryption}</span>`);
    push("Canal", d.channel ?? "—");
    push("Fabricante", d.vendor || "—");
  } else {
    push("Dirección", `<code>${d.addr}</code>`);
    push("Tipo", d.device_type || "BLE");
    push("Fabricante", d.vendor || "—");
  }
  const pct = rssiPct(d.best_signal);
  push("Señal máx.", `${d.best_signal ?? "—"} dBm
        <div class="rssi-bar"><i style="width:${pct}%;background:${color}"></i></div>`);
  push("Paquetes", d.packets);
  push("Avistamientos GPS", (d.sightings || []).length);
  push("Primer visto", fmtTime(d.first_seen));
  push("Último visto", fmtTime(d.last_seen));
  if (d.location) {
    push("Posición", `${d.location.lat.toFixed(6)}, ${d.location.lon.toFixed(6)}`);
    const src = d.location.source;
    let method = src === "best-signal" ? "Mayor señal (GPS)"
               : src === "centroid" ? "Centroide (GPS)"
               : `geowifi · ${d.location.module || "OSINT"}`;
    push("Método", method);
    if (isOsintLoc(d.location)) {
      if (d.location.accuracy) push("Precisión", `~${d.location.accuracy} m`);
      push("Aviso", `<span style="color:${COLORS.WPA}">Dato OSINT de base pública, no un fix GPS</span>`);
    }
    const g = `${d.location.lat},${d.location.lon}`;
    push("Mapa", `<a href="https://www.google.com/maps?q=${g}" target="_blank" rel="noopener" style="color:var(--accent-2)">Google Maps ↗</a>`);
  } else {
    push("Posición", "<i>sin GPS</i>");
  }

  el.innerHTML = `
    <div class="dhead">
      <button class="close" onclick="closeDetail()">×</button>
      <h3>${escapeHtml(d.name || "(sin nombre)")}</h3>
      <div class="dsub">${d.kind === "wifi" ? "Red WiFi" : "Dispositivo Bluetooth"}</div>
    </div>
    ${rows.join("")}`;
}

function closeDetail() {
  document.getElementById("detail").classList.add("hidden");
  state.selected = null;
  if (state.track) { map.removeLayer(state.track); state.track = null; }
  renderList();
}
window.closeDetail = closeDetail;

function syncTabs() {
  document.querySelectorAll(".tab").forEach(t =>
    t.classList.toggle("active", t.dataset.tab === state.tab));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- geowifi (geolocalización OSINT de BSSIDs) ----------

function unlocatedWifi() {
  if (!state.data) return [];
  return state.data.wifi.filter(d => !d.location);
}

function updateGeowifiBtn() {
  const btn = document.getElementById("geowifiBtn");
  const pending = unlocatedWifi().length;
  btn.hidden = pending === 0;
  btn.disabled = false;
  btn.textContent = `Geolocalizar BSSIDs (geowifi · ${pending})`;
}

function recomputeLocated() {
  const all = [...state.data.wifi, ...state.data.bluetooth];
  const coords = all.filter(d => d.location)
                    .map(d => [d.location.lat, d.location.lon]);
  state.data.meta.located_count = coords.length;
  state.data.meta.has_gps = coords.length > 0;
  renderStats(state.data.meta);
  return coords;
}

async function runGeowifi() {
  const targets = unlocatedWifi();
  if (!targets.length) return;
  const btn = document.getElementById("geowifiBtn");
  btn.disabled = true;
  btn.textContent = "Geolocalizando…";
  try {
    const res = await fetch("/api/geolocate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bssids: targets.map(d => d.addr) }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "Error en geowifi");

    const located = json.located || {};
    let applied = 0;
    for (const d of state.data.wifi) {
      const hit = located[d.addr];
      if (hit && !d.location) {
        d.location = {
          lat: hit.lat, lon: hit.lon, source: "geowifi",
          module: hit.module, accuracy: hit.accuracy,
        };
        applied++;
      }
    }

    renderMarkers();
    renderList();
    updateGeowifiBtn();
    const coords = recomputeLocated();
    if (applied && coords.length) {
      const b = coords.reduce((a, c) => ({
        mnla: Math.min(a.mnla, c[0]), mxla: Math.max(a.mxla, c[0]),
        mnlo: Math.min(a.mnlo, c[1]), mxlo: Math.max(a.mxlo, c[1]),
      }), { mnla: 90, mxla: -90, mnlo: 180, mxlo: -180 });
      map.fitBounds([[b.mnla, b.mnlo], [b.mxla, b.mxlo]], { padding: [60, 60] });
    }

    let msg = `geowifi (${json.provider || "apple"}): ${applied} de ${targets.length} `
            + `BSSIDs localizados en bases públicas (${json.queried} consultas). `
            + `Son ubicaciones OSINT, no fixes GPS de la captura.`;
    if (!applied) {
      msg = `geowifi no encontró ubicación para ninguno de los ${targets.length} `
          + `BSSIDs (${json.queried} consultas)`
          + (json.errors && json.errors.length ? `. El servicio pudo no estar accesible.` : `.`);
    }
    banner(msg, !applied);
  } catch (e) {
    banner(e.message, true);
  } finally {
    updateGeowifiBtn();
  }
}

// ---------- events ----------

function wire() {
  document.getElementById("fileInput").addEventListener("change", e => {
    if (e.target.files[0]) upload(e.target.files[0]);
  });
  document.getElementById("sampleBtn").addEventListener("click", loadSample);
  document.getElementById("geowifiBtn").addEventListener("click", runGeowifi);
  document.getElementById("filterInput").addEventListener("input", e => {
    state.filter = e.target.value; renderList();
  });
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      state.tab = tab.dataset.tab; syncTabs(); renderList();
    });
  });

  const dz = document.getElementById("dropzone");
  const mapwrap = document.querySelector(".mapwrap");
  ["dragenter", "dragover"].forEach(ev =>
    mapwrap.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("hidden"); dz.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach(ev =>
    mapwrap.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("dragover"); }));
  mapwrap.addEventListener("drop", e => {
    if (e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]);
    else if (state.data) dz.classList.add("hidden");
  });
}

initMap();
wire();
