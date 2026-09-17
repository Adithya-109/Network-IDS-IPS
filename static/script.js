const el = (id) => document.getElementById(id);

const statusPill = el("statusPill");
const statusText = el("statusText");
const startBtn = el("startBtn");
const stopBtn = el("stopBtn");
const clearBtn = el("clearBtn");

let lastAlertId = 0;

function fmtUptime(seconds) {
  seconds = Math.max(0, Math.floor(seconds));
  const h = String(Math.floor(seconds / 3600)).padStart(2, "0");
  const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, "0");
  const s = String(seconds % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function fmtTime(unixSeconds) {
  const d = new Date(unixSeconds * 1000);
  return d.toLocaleTimeString();
}

// --- Charts -----------------------------------------------------------

const protocolChart = new Chart(el("protocolChart"), {
  type: "doughnut",
  data: {
    labels: ["TCP", "UDP", "ICMP", "Other"],
    datasets: [
      {
        data: [0, 0, 0, 0],
        backgroundColor: ["#00e5a0", "#3aa0ff", "#ffb020", "#7d94a8"],
        borderColor: "#0d1420",
        borderWidth: 2,
      },
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: "#dce8f2", font: { size: 11 } } },
    },
  },
});

const severityChart = new Chart(el("severityChart"), {
  type: "bar",
  data: {
    labels: ["High", "Medium", "Low"],
    datasets: [
      {
        label: "Alerts",
        data: [0, 0, 0],
        backgroundColor: ["#ff4d5e", "#ffb020", "#3aa0ff"],
        borderRadius: 6,
      },
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: "#dce8f2" }, grid: { color: "#1c2b3d" } },
      y: {
        beginAtZero: true,
        ticks: { color: "#dce8f2", precision: 0 },
        grid: { color: "#1c2b3d" },
      },
    },
  },
});

// --- Polling ------------------------------------------------------------

function renderError(message) {
  const banner = el("errorBanner");
  if (message) {
    banner.textContent = message;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

async function pollStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    setRunning(data.running);
    renderError(data.error);
    el("kpiPackets").textContent = data.packet_count.toLocaleString();
    el("kpiPps").textContent = data.pps;
    el("kpiUptime").textContent = fmtUptime(data.uptime);

    el("protoTcp").textContent = data.tcp_count;
    el("protoUdp").textContent = data.udp_count;
    el("protoIcmp").textContent = data.icmp_count;
    el("protoOther").textContent = data.other_count;

    protocolChart.data.datasets[0].data = [
      data.tcp_count,
      data.udp_count,
      data.icmp_count,
      data.other_count,
    ];
    protocolChart.update("none");
  } catch (e) {
    // dashboard keeps polling silently; server may be restarting
  }
}

async function pollAlerts() {
  try {
    const res = await fetch("/api/alerts");
    const data = await res.json();
    renderAlerts(data.alerts);
    renderCounts(data.counts);
  } catch (e) {
    // ignore transient errors
  }
}

function renderCounts(counts) {
  el("kpiAlerts").textContent = counts.total;
  el("sevHigh").textContent = counts.High;
  el("sevMedium").textContent = counts.Medium;
  el("sevLow").textContent = counts.Low;

  severityChart.data.datasets[0].data = [counts.High, counts.Medium, counts.Low];
  severityChart.update("none");
}

function renderAlerts(alerts) {
  const body = el("alertsBody");

  if (!alerts.length) {
    body.innerHTML =
      '<tr class="empty-row"><td colspan="7">No alerts yet. Start monitoring to begin capture.</td></tr>';
    lastAlertId = 0;
    return;
  }

  const newestId = alerts[0].id;
  body.innerHTML = alerts
    .map((a) => {
      const isNew = a.id > lastAlertId;
      return `<tr class="${isNew ? "row-new" : ""}">
        <td>${fmtTime(a.timestamp)}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span></td>
        <td>${a.detection_type}</td>
        <td>${a.src_ip ?? "-"}</td>
        <td>${a.dst_ip ?? "-"}</td>
        <td>${a.protocol ?? "-"}</td>
        <td>${a.description ?? "-"}</td>
      </tr>`;
    })
    .join("");

  lastAlertId = newestId;
}

function setRunning(running) {
  statusPill.classList.toggle("running", running);
  statusPill.classList.toggle("stopped", !running);
  statusText.textContent = running ? "RUNNING" : "STOPPED";
  startBtn.disabled = running;
  stopBtn.disabled = !running;
}

// --- Controls -----------------------------------------------------------

startBtn.addEventListener("click", async () => {
  startBtn.disabled = true;
  await fetch("/api/start", { method: "POST" });
  pollStats();
});

stopBtn.addEventListener("click", async () => {
  stopBtn.disabled = true;
  await fetch("/api/stop", { method: "POST" });
  pollStats();
});

clearBtn.addEventListener("click", async () => {
  await fetch("/api/alerts/clear", { method: "POST" });
  lastAlertId = 0;
  pollAlerts();
});

// --- Init -----------------------------------------------------------

pollStats();
pollAlerts();
setInterval(pollStats, 1000);
setInterval(pollAlerts, 1500);
