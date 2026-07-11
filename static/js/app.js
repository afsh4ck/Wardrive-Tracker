"use strict";

const COLORS = {
  Open: "#ff5a5a", WEP: "#ff9f43", WPA: "#f6c945",
  WPA2: "#38e1b0", WPA3: "#4aa3ff", bluetooth: "#b07aff",
};

// Fuentes de ubicación derivadas del GPS del recorrido (PPI-GPS o log wardrive).
const GPS_SOURCES = new Set(["best-signal", "weighted-centroid", "centroid"]);
const isGpsLoc = (loc) => loc && GPS_SOURCES.has(loc.source);
const isTrilatLoc = (loc) => loc && loc.source === "trilateration";
// OSINT = base pública (geowifi): ni fix GPS ni triangulación local.
const isOsintLoc = (loc) => loc && !isGpsLoc(loc) && !isTrilatLoc(loc);

// Modelo de propagación para la triangulación por RSSI (log-distancia).
// REF_DBM = RSSI de referencia a 1 m; PATH_LOSS_N = exponente de pérdidas.
// Son valores fijos y aproximados: sin calibrar el emisor, la distancia
// derivada del RSSI tiene un error de escala grande (ver runGeowifi/CLAUDE.md).
const REF_DBM = -40.0;
const PATH_LOSS_N = 3.0;
const M_PER_DEG = 111320.0;

const state = {
  data: null,
  tab: "wifi",
  filter: "",
  selected: null,        // addr
  markers: {},           // addr -> leaflet marker
  track: null,           // active polyline layer
  uncert: null,          // active uncertainty circle/ellipse
  layer: null,           // markers layergroup
  mapShow: { wifi: true, bluetooth: true },   // qué tipos se pintan en el mapa
  trilatOn: false,       // triangulación por RSSI activada
  encFilter: new Set(),  // cifrados WiFi activos (vacío = todos)
  geowifiRunning: false, // hay una tanda de geowifi en curso
  geowifiStop: false,    // petición de detener la tanda
};

// Tamaño de lote para geowifi: listas grandes (miles de redes) se trocean en
// varias peticiones para no perder ninguna, mostrar progreso y poder detener
// entre lotes. Pequeño para que cada petición vuelva pronto (el caché de vecinos
// de Apple hace que muchas del lote se resuelvan sin consulta propia).
const GEOWIFI_CHUNK = 150;

const ENC_TYPES = ["Open", "WEP", "WPA", "WPA2", "WPA3"];

// Nombre a mostrar. Los dispositivos BLE a menudo no anuncian nombre (MAC
// aleatoria, privacidad); en ese caso, una etiqueta útil en vez de "(sin nombre)".
function displayName(d) {
  if (d.name) return d.name;
  if (d.kind === "bluetooth") {
    if (d.vendor && d.vendor !== "Randomized/Local") return `${d.vendor} (BLE)`;
    return `BLE ${d.addr.slice(-8)}`;
  }
  return "(sin nombre)";
}

let map;

function initMap() {
  map = L.map("map", { zoomControl: true, attributionControl: true })
         .setView([40.4168, -3.7038], 15);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "&copy; OpenStreetMap &copy; CARTO",
    maxZoom: 20,
  }).addTo(map);
  state.layer = L.layerGroup().addTo(map);
  addMapControls();
  addLegend();
}

function addMapControls() {
  const el = document.createElement("div");
  el.className = "mapctl";
  el.innerHTML = `
    <div class="grp">
      <label><input type="checkbox" id="showWifi" checked> WiFi</label>
      <label><input type="checkbox" id="showBt" checked> Bluetooth</label>
    </div>
    <div class="sep"></div>
    <label class="muted"><input type="checkbox" id="trilatToggle"> Triangular por RSSI</label>
    <div class="hint">Solo afina redes con cobertura en 2D (vueltas a la zona).
      En una recta la geometría no basta; usa geowifi.</div>`;
  document.querySelector(".mapwrap").appendChild(el);
  el.querySelector("#showWifi").addEventListener("change", e => {
    state.mapShow.wifi = e.target.checked; renderMarkers();
  });
  el.querySelector("#showBt").addEventListener("change", e => {
    state.mapShow.bluetooth = e.target.checked; renderMarkers();
  });
  el.querySelector("#trilatToggle").addEventListener("change", e => {
    toggleTrilat(e.target.checked);
  });
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
    <div class="lrow"><span class="dot ring"></span>Ubicación OSINT (geowifi)</div>
    <div class="lrow"><span class="dot ring"></span>Radio de incertidumbre (al seleccionar)</div>`;
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
  if (state.track) { map.removeLayer(state.track); state.track = null; }
  if (state.uncert) { map.removeLayer(state.uncert); state.uncert = null; }
  document.getElementById("dropzone").classList.add("hidden");
  renderStats(json.meta);
  document.getElementById("wifiCount").textContent = json.meta.wifi_count;
  document.getElementById("btCount").textContent = json.meta.bluetooth_count;

  if (!json.meta.has_gps) {
    banner("La captura no contiene coordenadas GPS (etiquetas PPI-GPS). Se listan " +
           "las redes y dispositivos, pero no pueden situarse en el mapa. Captura con " +
           "GPS (Kismet / airodump-ng con GPSd) para geolocalizar.", false);
  } else {
    banner("Las posiciones son estimaciones por proximidad (el punto de tu recorrido " +
           "donde pasaste más cerca), no la ubicación exacta del emisor: por eso caen " +
           "sobre la carretera. Selecciona un elemento para ver su radio de incertidumbre, " +
           "o usa «Geolocalizar/refinar BSSIDs» para afinarlas con geowifi.", false);
  }
  if (state.trilatOn) applyTrilat(true);
  buildEncChips();
  syncEncFilterVisibility();
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

function setGeowifiProgress(done, total, applied) {
  const box = document.getElementById("geowifiProgress");
  box.classList.remove("hidden");
  const pct = total ? Math.round(done / total * 100) : 0;
  document.getElementById("pbarFill").style.width = pct + "%";
  document.getElementById("pbarText").textContent =
    `geolocalizando ${done}/${total} (${pct}%) · ${applied} situadas`;
}

function hideGeowifiProgress() {
  document.getElementById("geowifiProgress").classList.add("hidden");
  document.getElementById("pbarFill").style.width = "0%";
}

// ---------- rendering ----------

function deviceMatches(d, f) {
  f = (f || "").toLowerCase();
  if (f) {
    const hit = (d.name || "").toLowerCase().includes(f) ||
      d.addr.toLowerCase().includes(f) ||
      (d.encryption || "").toLowerCase().includes(f) ||
      (d.vendor || "").toLowerCase().includes(f);
    if (!hit) return false;
  }
  // Filtro por cifrado: solo aplica a WiFi; los BLE no se ven afectados.
  if (d.kind === "wifi" && state.encFilter.size > 0 && !state.encFilter.has(d.encryption)) {
    return false;
  }
  return true;
}

function buildEncChips() {
  const box = document.getElementById("encFilter");
  box.innerHTML = "";
  for (const enc of ENC_TYPES) {
    const chip = document.createElement("span");
    const on = state.encFilter.has(enc);
    chip.className = "chip" + (on ? " active" : "");
    const col = COLORS[enc] || "#8892a8";
    if (on) chip.style.color = col;
    chip.innerHTML = `<span class="cdot" style="background:${col}"></span>${enc}`;
    chip.onclick = () => {
      if (state.encFilter.has(enc)) state.encFilter.delete(enc);
      else state.encFilter.add(enc);
      buildEncChips();
      renderList();
      renderMarkers();
    };
    box.appendChild(chip);
  }
}

// Los chips de cifrado solo tienen sentido en la pestaña WiFi.
function syncEncFilterVisibility() {
  document.getElementById("encFilter").classList.toggle("hidden", state.tab !== "wifi");
}

function currentList() {
  const arr = state.tab === "wifi" ? state.data.wifi : state.data.bluetooth;
  return arr.filter(d => deviceMatches(d, state.filter));
}

// Crea el marcador de un dispositivo si pasa los filtros de mapa.
function addMarker(d) {
  if (!state.mapShow[d.kind]) return;
  if (!deviceMatches(d, state.filter)) return;
  if (!d.location) return;
  const estimated = !isGpsLoc(d.location);   // geowifi o triangulación
  const marker = L.circleMarker([d.location.lat, d.location.lon], {
    radius: 8, weight: 2,
    color: estimated ? colorFor(d) : "#0b0f17",
    dashArray: estimated ? "3,3" : null,
    fillColor: colorFor(d),
    fillOpacity: estimated ? 0.3 : 0.95,
  });
  marker.bindPopup(popupHtml(d));
  marker.on("click", () => select(d.addr, d.kind, false));
  marker.addTo(state.layer);
  state.markers[d.addr] = marker;
}

// Reemplaza el marcador de un solo dispositivo (para actualizaciones incrementales,
// p. ej. geowifi por lotes) sin reconstruir todo el mapa.
function upsertMarker(d) {
  const old = state.markers[d.addr];
  if (old) { state.layer.removeLayer(old); delete state.markers[d.addr]; }
  addMarker(d);
}

function renderMarkers() {
  state.layer.clearLayers();
  state.markers = {};
  for (const d of [...state.data.wifi, ...state.data.bluetooth]) addMarker(d);
}

function popupHtml(d) {
  const label = d.kind === "wifi"
    ? `${d.encryption} · canal ${d.channel ?? "?"}`
    : `Bluetooth LE · ${d.device_type || ""}`;
  let note = "";
  if (isOsintLoc(d.location))
    note = `<br><i style="color:${COLORS.WPA}">📍 ubicación OSINT (geowifi), no GPS</i>`;
  else if (isTrilatLoc(d.location))
    note = `<br><i style="color:${COLORS.WPA}">📐 posición triangulada (RSSI), estimada</i>`;
  return `<b>${escapeHtml(displayName(d))}</b><br>${d.addr}<br>${label}<br>RSSI ${d.best_signal ?? "?"} dBm${note}`;
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
        <div class="name">${escapeHtml(displayName(d))}</div>
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
  if (state.uncert) { map.removeLayer(state.uncert); state.uncert = null; }
  if (d.location) {
    map.panTo([d.location.lat, d.location.lon]);
    const m = state.markers[addr];
    if (m) m.openPopup();
    const style = { color: colorFor(d), weight: 1, opacity: .55,
                    fillColor: colorFor(d), fillOpacity: .08, dashArray: "4,4" };
    const ell = d.location.ellipse;
    if (ell) {
      state.uncert = L.polygon(
        ellipsePoly(d.location.lat, d.location.lon, ell.a_m, ell.b_m, ell.angle_deg),
        style).addTo(map);
    } else if (d.location.radius_m) {
      state.uncert = L.circle([d.location.lat, d.location.lon],
        { ...style, radius: d.location.radius_m }).addTo(map);
    }
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
               : src === "weighted-centroid" ? "Centroide ponderado por RSSI (GPS)"
               : src === "centroid" ? "Centroide (GPS)"
               : src === "trilateration" ? "Triangulación por RSSI"
               : `geowifi · ${d.location.module || "OSINT"}`;
    push("Método", method);
    if (isTrilatLoc(d.location) && d.location.ellipse) {
      const e = d.location.ellipse;
      push("Incertidumbre", `~${e.a_m} × ${e.b_m} m (elipse)`);
      push("Ajuste RSSI", `±${e.rms_db} dB`);
      push("Aviso", `<span style="color:${COLORS.WPA}">Estimación por propagación (modelo fijo), no exacta; el emisor puede estar dentro de la elipse</span>`);
    } else {
      const radius = d.location.radius_m || (isOsintLoc(d.location) ? d.location.accuracy : null);
      if (radius) push("Radio estimado", `~${radius} m`);
      if (isGpsLoc(d.location)) {
        push("Aviso", `<span style="color:${COLORS.WPA}">Estimación por proximidad; el emisor real puede estar dentro del radio</span>`);
      } else if (isOsintLoc(d.location)) {
        push("Aviso", `<span style="color:${COLORS.WPA}">Dato OSINT de base pública, no un fix GPS</span>`);
        if (d.gps_location) {
          push("GPS (recorrido)", `${d.gps_location.lat.toFixed(6)}, ${d.gps_location.lon.toFixed(6)}`);
        }
      }
    }
    const g = `${d.location.lat},${d.location.lon}`;
    push("Mapa", `<a href="https://www.google.com/maps?q=${g}" target="_blank" rel="noopener" style="color:var(--accent-2)">Google Maps ↗</a>`);
  } else {
    push("Posición", "<i>sin GPS</i>");
  }

  el.innerHTML = `
    <div class="dhead">
      <button class="close" onclick="closeDetail()">×</button>
      <h3>${escapeHtml(displayName(d))}</h3>
      <div class="dsub">${d.kind === "wifi" ? "Red WiFi" : "Dispositivo Bluetooth"}</div>
    </div>
    ${rows.join("")}`;
}

function closeDetail() {
  document.getElementById("detail").classList.add("hidden");
  state.selected = null;
  if (state.track) { map.removeLayer(state.track); state.track = null; }
  if (state.uncert) { map.removeLayer(state.uncert); state.uncert = null; }
  renderList();
}
window.closeDetail = closeDetail;

function syncTabs() {
  document.querySelectorAll(".tab").forEach(t =>
    t.classList.toggle("active", t.dataset.tab === state.tab));
  syncEncFilterVisibility();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- geowifi (geolocalización OSINT de BSSIDs) ----------

// BSSIDs que geowifi puede resolver o afinar: MAC no aleatoria y que aún no
// tenga una ubicación OSINT. Incluye las ya situadas por GPS (recorrido): para
// esas, geowifi sustituye el punto sobre la carretera por la posición de la base
// pública, más cercana al emisor real.
function geowifiTargets() {
  if (!state.data) return [];
  return state.data.wifi.filter(d =>
    d.vendor !== "Randomized/Local" && !isOsintLoc(d.location));
}

function updateGeowifiBtn() {
  const btn = document.getElementById("geowifiBtn");
  if (state.geowifiRunning) return;   // no tocar el botón mientras corre
  const pending = geowifiTargets().length;
  btn.hidden = pending === 0;
  btn.disabled = false;
  btn.textContent = `Geolocalizar/refinar BSSIDs (geowifi · ${pending})`;
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

// Aplica un lote de resultados de geowifi a las redes; devuelve los dispositivos
// que cambiaron (para actualizar solo esos marcadores).
function applyGeowifiResults(located) {
  const changed = [];
  for (const d of state.data.wifi) {
    const hit = located[d.addr];
    if (hit && !isOsintLoc(d.location)) {
      // Conserva el punto GPS del recorrido para poder compararlos.
      if (isGpsLoc(d.location)) d.gps_location = d.location;
      d.location = {
        lat: hit.lat, lon: hit.lon, source: "geowifi",
        module: hit.module, accuracy: hit.accuracy, radius_m: hit.accuracy || null,
      };
      changed.push(d);
    }
  }
  return changed;
}

async function runGeowifi() {
  const btn = document.getElementById("geowifiBtn");
  // Segunda pulsación mientras corre => detener tras el lote actual.
  if (state.geowifiRunning) {
    state.geowifiStop = true;
    btn.textContent = "Deteniendo…";
    return;
  }

  const addrs = geowifiTargets().map(d => d.addr);
  if (!addrs.length) return;

  state.geowifiRunning = true;
  state.geowifiStop = false;
  let applied = 0, queried = 0, done = 0, provider = "apple";
  const errors = [];
  setGeowifiProgress(0, addrs.length, 0);

  try {
    for (let i = 0; i < addrs.length && !state.geowifiStop; i += GEOWIFI_CHUNK) {
      const batch = addrs.slice(i, i + GEOWIFI_CHUNK);
      btn.textContent = `Consultando ${done}/${addrs.length}… ⏹ detener`;
      let json;
      try {
        const res = await fetch("/api/geolocate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ bssids: batch }),
        });
        json = await res.json();
        if (!res.ok) throw new Error(json.error || "Error en geowifi");
      } catch (e) {
        errors.push(e.message);
        done += batch.length;
        setGeowifiProgress(done, addrs.length, applied);
        if (!applied && errors.length >= 2) throw e;   // servicio caído: aborta
        continue;                                       // fallo puntual: sigue
      }
      provider = json.provider || provider;
      queried += json.queried || 0;
      if (json.errors && json.errors.length) errors.push(...json.errors);
      const changed = applyGeowifiResults(json.located || {});
      applied += changed.length;
      done += batch.length;

      // Actualización incremental: solo los marcadores que cambiaron (no se
      // reconstruye el mapa entero ni la lista en cada lote — clave con miles
      // de redes). La lista se refresca una vez al final.
      for (const d of changed) upsertMarker(d);
      recomputeLocated();
      setGeowifiProgress(done, addrs.length, applied);
      banner(`geowifi (${provider}): ${applied} redes situadas · ${done}/${addrs.length} `
           + `BSSIDs procesados · ${queried} peticiones…`, false);
    }

    renderList();
    if (state.selected) select(state.selected, state.tab, true);
    const coords = recomputeLocated();
    if (applied && coords.length) {
      const b = coords.reduce((a, c) => ({
        mnla: Math.min(a.mnla, c[0]), mxla: Math.max(a.mxla, c[0]),
        mnlo: Math.min(a.mnlo, c[1]), mxlo: Math.max(a.mxlo, c[1]),
      }), { mnla: 90, mxla: -90, mnlo: 180, mxlo: -180 });
      map.fitBounds([[b.mnla, b.mnlo], [b.mxla, b.mxlo]], { padding: [60, 60] });
    }

    const stopped = state.geowifiStop;
    let msg = `geowifi (${provider}): ${applied} de ${addrs.length} redes situadas `
            + `(${done} procesados, ${queried} peticiones${stopped ? ", detenido" : ""}). `
            + `Ubicaciones OSINT, no fixes GPS. Muchas MAC no están en las bases públicas.`;
    if (!applied) {
      msg = `geowifi no encontró ubicación para ninguna de las ${addrs.length} redes `
          + `(${queried} peticiones)`
          + (errors.length ? `. El servicio pudo no estar accesible.` : `.`);
    }
    banner(msg, !applied);
  } catch (e) {
    banner("geowifi: " + e.message, true);
  } finally {
    state.geowifiRunning = false;
    state.geowifiStop = false;
    hideGeowifiProgress();
    updateGeowifiBtn();
  }
}

// ---------- triangulación por RSSI (multilateración) ----------
//
// Convierte cada avistamiento en una distancia estimada por el modelo
// log-distancia (REF_DBM, PATH_LOSS_N) y busca la posición que mejor encaja
// todas las distancias (mínimos cuadrados sobre |pos - obs| = d).
//
// Límite fundamental: sobre una carretera RECTA las medidas son casi colineales
// y aparece una ambigüedad de "qué lado" que el ruido resuelve casi al azar
// (verificado numéricamente). Por eso solo se confía en el resultado cuando la
// geometría de los avistamientos es realmente 2D (`_geomSpread`); si no, se
// declina y se mantiene el centroide.

function _localFrame(sightings) {
  const pts = sightings.filter(s => s.signal != null && s.lat != null);
  if (pts.length < 5) return null;
  const lat0 = pts.reduce((a, s) => a + s.lat, 0) / pts.length;
  const lon0 = pts.reduce((a, s) => a + s.lon, 0) / pts.length;
  const mlat = M_PER_DEG, mlon = M_PER_DEG * Math.cos(lat0 * Math.PI / 180);
  return { lat0, lon0, mlat, mlon, pts };
}

// Dispersión de los puntos de observación en sus ejes principales (desv. típica
// en metros). minor grande => cobertura 2D; minor ~0 => recorrido en línea.
function _geomSpread(P) {
  const n = P.length;
  const mx = P.reduce((a, p) => a + p.x, 0) / n, my = P.reduce((a, p) => a + p.y, 0) / n;
  let sxx = 0, syy = 0, sxy = 0;
  for (const p of P) { const dx = p.x - mx, dy = p.y - my; sxx += dx * dx; syy += dy * dy; sxy += dx * dy; }
  sxx /= n; syy /= n; sxy /= n;
  const tr = sxx + syy, dd = Math.sqrt(Math.max(0, (sxx - syy) ** 2 / 4 + sxy * sxy));
  return { major: Math.sqrt(Math.max(0, tr / 2 + dd)), minor: Math.sqrt(Math.max(0, tr / 2 - dd)) };
}

function computeTrilat(device) {
  const fr = _localFrame(device.sightings || []);
  if (!fr) return { ok: false, reason: "pocos avistamientos con señal" };
  const P = fr.pts.map(s => ({
    x: (s.lon - fr.lon0) * fr.mlon, y: (s.lat - fr.lat0) * fr.mlat,
    d: Math.pow(10, (REF_DBM - s.signal) / (10 * PATH_LOSS_N)),
  }));

  const spread = _geomSpread(P);
  if (spread.minor < 20 || spread.minor / (spread.major || 1) < 0.30) {
    return { ok: false, reason: "geometría insuficiente (recorrido casi recto)" };
  }

  const cost = (px, py) => {
    let c = 0;
    for (const p of P) { const e = Math.hypot(p.x - px, p.y - py) - p.d; c += e * e; }
    return c;
  };
  let minx = Infinity, maxx = -Infinity, miny = Infinity, maxy = -Infinity;
  for (const p of P) { minx = Math.min(minx, p.x); maxx = Math.max(maxx, p.x); miny = Math.min(miny, p.y); maxy = Math.max(maxy, p.y); }
  const margin = 120; minx -= margin; maxx += margin; miny -= margin; maxy += margin;
  const G = 44; let best = { c: Infinity, x: 0, y: 0 };
  for (let i = 0; i <= G; i++) { const px = minx + (maxx - minx) * i / G;
    for (let j = 0; j <= G; j++) { const py = miny + (maxy - miny) * j / G;
      const c = cost(px, py); if (c < best.c) best = { c, x: px, y: py }; } }
  let step = Math.max(maxx - minx, maxy - miny) / G;
  for (let it = 0; it < 6; it++) {
    let imp = false; const H = 10;
    for (let i = -H; i <= H; i++) for (let j = -H; j <= H; j++) {
      const px = best.x + step * i / H, py = best.y + step * j / H;
      const c = cost(px, py); if (c < best.c) { best = { c, x: px, y: py }; imp = true; } }
    step /= 4; if (!imp) break;
  }

  const dof = Math.max(1, P.length - 2);
  const sigma2 = best.c / dof, rms = Math.sqrt(sigma2);
  const h = 2.0;
  const cxx = (cost(best.x + h, best.y) - 2 * best.c + cost(best.x - h, best.y)) / (h * h);
  const cyy = (cost(best.x, best.y + h) - 2 * best.c + cost(best.x, best.y - h)) / (h * h);
  const cxy = (cost(best.x + h, best.y + h) - cost(best.x + h, best.y - h)
             - cost(best.x - h, best.y + h) + cost(best.x - h, best.y - h)) / (4 * h * h);
  const det = cxx * cyy - cxy * cxy;
  let a = 200, b = 200, ang = 0;
  if (det > 1e-9) {
    const s = 2 * sigma2, vxx = s * cyy / det, vyy = s * cxx / det, vxy = -s * cxy / det;
    const tr = vxx + vyy, d2 = Math.sqrt(Math.max(0, (vxx - vyy) ** 2 / 4 + vxy * vxy));
    a = Math.sqrt(Math.max(0, tr / 2 + d2)); b = Math.sqrt(Math.max(0, tr / 2 - d2));
    ang = 0.5 * Math.atan2(2 * vxy, vxx - vyy) * 180 / Math.PI;
  }
  // Suelo conservador: el error de calibración (P0/n) no lo captura la Hessiana.
  a = Math.max(a, 12); b = Math.max(b, 8);
  if (rms > 9 || a > 120) {
    return { ok: false, reason: "ajuste pobre (RSSI ruidoso o mala calibración)" };
  }
  return {
    ok: true,
    lat: fr.lat0 + best.y / fr.mlat, lon: fr.lon0 + best.x / fr.mlon,
    a_m: Math.round(a * 10) / 10, b_m: Math.round(b * 10) / 10,
    angle_deg: Math.round(ang * 10) / 10, rms_db: Math.round(rms * 100) / 100,
  };
}

// Genera el polígono de una elipse (para dibujarla en Leaflet, que no trae elipses).
function ellipsePoly(lat, lon, aM, bM, angleDeg) {
  const mlat = M_PER_DEG, mlon = M_PER_DEG * Math.cos(lat * Math.PI / 180);
  const th = angleDeg * Math.PI / 180, ct = Math.cos(th), st = Math.sin(th);
  const pts = [];
  for (let k = 0; k <= 48; k++) {
    const t = k / 48 * 2 * Math.PI, ex = aM * Math.cos(t), ey = bM * Math.sin(t);
    const x = ex * ct - ey * st, y = ex * st + ey * ct;
    pts.push([lat + y / mlat, lon + x / mlon]);
  }
  return pts;
}

// Sustituye (o restaura) la ubicación de cada dispositivo por la triangulada.
// Guarda la original en `_srvloc` para poder revertir. No toca ubicaciones OSINT
// (geowifi) ni recalcula lo ya intentado.
function applyTrilat(on) {
  if (!state.data) return;
  const all = [...state.data.wifi, ...state.data.bluetooth];
  for (const d of all) {
    if (on) {
      if ("_srvloc" in d || d._trilat) continue;          // ya procesado
      if (isOsintLoc(d.location)) continue;               // respeta geowifi
      const t = computeTrilat(d);
      d._trilat = t;
      if (t.ok) {
        d._srvloc = d.location;
        d.location = {
          lat: t.lat, lon: t.lon, source: "trilateration",
          radius_m: Math.max(t.a_m, t.b_m), ellipse: t,
        };
      }
    } else {
      if ("_srvloc" in d) { d.location = d._srvloc; delete d._srvloc; }
      delete d._trilat;
    }
  }
}

function toggleTrilat(on) {
  state.trilatOn = on;
  applyTrilat(on);
  renderMarkers();
  renderList();
  updateGeowifiBtn();
  if (state.selected) select(state.selected, state.tab, true);
  const done = state.data ? [...state.data.wifi, ...state.data.bluetooth]
    .filter(d => d._trilat && d._trilat.ok).length : 0;
  if (on) {
    banner(done
      ? `Triangulación por RSSI: ${done} dispositivos con cobertura 2D reposicionados `
        + `(elipse de incertidumbre al seleccionar). El resto se queda en el centroide `
        + `por geometría insuficiente. Es una estimación por propagación, no exacta.`
      : `Ningún dispositivo tiene cobertura 2D suficiente para triangular (recorrido casi `
        + `recto). Las posiciones no cambian; para más precisión usa geowifi.`, !done);
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
    state.filter = e.target.value; renderList(); renderMarkers();
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
