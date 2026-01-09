import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key_change_me";

/* ---------------------------
   Security Headers (CSP)
--------------------------- */
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");

  // Allow Tailwind CDN + Chart.js CDN
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
      "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net",
      "connect-src 'self'",
      "font-src 'self' data:",
    ].join("; ")
  );

  next();
});

/* ---------------------------
   Mock Users (MVP)
--------------------------- */
const USERS = [
  {
    id: "u1",
    email: "admin@clinic.com",
    role: "CLINIC_ADMIN",
    passwordHash: bcrypt.hashSync("Clinic123!", 10),
  },
  {
    id: "u2",
    email: "dentist@clinic.com",
    role: "CLINICIAN",
    passwordHash: bcrypt.hashSync("Dentist123!", 10),
  },
  {
    id: "u3",
    email: "research@clinic.com",
    role: "RESEARCHER",
    passwordHash: bcrypt.hashSync("Research123!", 10),
  },
];

/* ---------------------------
   Mock Patients (MVP)
--------------------------- */
const PATIENTS = [
  {
    id: "P-0001",
    code: "BH-7Q2A",
    age: 32,
    gender: "F",
    status: "ACTIVE",
    treatment: "MONITORING",
    lastDataAt: "2026-01-08",
    bsi: 68,
    episodes: 22,
    trend: "IMPROVING",
  },
  {
    id: "P-0002",
    code: "BH-1K9M",
    age: 41,
    gender: "M",
    status: "ACTIVE",
    treatment: "SPLINT",
    lastDataAt: "2026-01-09",
    bsi: 74,
    episodes: 31,
    trend: "STABLE",
  },
  {
    id: "P-0003",
    code: "BH-3X5D",
    age: 28,
    gender: "F",
    status: "ACTIVE",
    treatment: "PHYSIO",
    lastDataAt: "2026-01-05",
    bsi: 82,
    episodes: 40,
    trend: "WORSENING",
  },
  {
    id: "P-0004",
    code: "BH-9N2P",
    age: 52,
    gender: "M",
    status: "ARCHIVED",
    treatment: "OTHER",
    lastDataAt: "2025-12-18",
    bsi: 44,
    episodes: 9,
    trend: "IMPROVING",
  },
];

/* ---------------------------
   Audit Log (in-memory demo)
--------------------------- */
const AUDIT = [];
function audit(event) {
  AUDIT.unshift({ id: `A-${Date.now()}`, at: new Date().toISOString(), ...event });
  if (AUDIT.length > 50) AUDIT.length = 50;
}

/* ---------------------------
   Helpers
--------------------------- */
function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const role = req.user?.role;
    if (!role) return res.status(401).json({ error: "Missing user role" });
    if (!roles.includes(role)) return res.status(403).json({ error: "Forbidden (insufficient role)" });
    next();
  };
}

function fmtRole(role) {
  if (role === "CLINIC_ADMIN") return "CLINIC ADMIN";
  if (role === "CLINICIAN") return "CLINICIAN";
  if (role === "RESEARCHER") return "RESEARCHER";
  return role;
}

function badge(text) {
  return `<span class="text-xs rounded-full bg-slate-100 px-3 py-1">${text}</span>`;
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900">
${body}
</body>
</html>`;
}

function layout(active, contentHtml) {
  return `
<div class="min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-5">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-xs text-slate-500">Brux Holter</div>
        <h1 class="text-xl font-semibold">Clinic Portal (Demo)</h1>
      </div>
      <div class="flex items-center gap-2">
        <span id="who" class="text-xs rounded-full bg-white border px-3 py-1">—</span>
        <button id="logout" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Logout</button>
      </div>
    </div>

    <div class="grid grid-cols-12 gap-4 mt-6">
      <aside class="col-span-12 md:col-span-3">
        <div class="bg-white rounded-2xl shadow p-4">
          <nav class="space-y-1">
            <a class="block rounded-xl px-4 py-3 ${active === "dashboard" ? "bg-slate-900 text-white" : "hover:bg-slate-50"}" href="/dashboard">Dashboard</a>
            <a class="block rounded-xl px-4 py-3 ${active === "patients" ? "bg-slate-900 text-white" : "hover:bg-slate-50"}" href="/patients">Patients</a>
            <a class="block rounded-xl px-4 py-3 ${active === "audit" ? "bg-slate-900 text-white" : "hover:bg-slate-50"}" href="/audit">Access Log</a>

            <div class="mt-3 border-t pt-3">
              <div class="text-xs text-slate-500 px-4 mb-2">Coming soon</div>
              <button class="w-full text-left rounded-xl px-4 py-3 bg-slate-50 text-slate-400 cursor-not-allowed" disabled>Invite User</button>
              <button class="w-full text-left rounded-xl px-4 py-3 bg-slate-50 text-slate-400 cursor-not-allowed mt-1" disabled>Export PDF</button>
            </div>
          </nav>
        </div>
      </aside>

      <main class="col-span-12 md:col-span-9">
        ${contentHtml}
      </main>
    </div>
  </div>
</div>

<script>
  const token = localStorage.getItem("bh_token");
  const user = JSON.parse(localStorage.getItem("bh_user") || "null");
  if (!token || !user) window.location.href = "/login";

  document.getElementById("who").textContent = "${badge("ROLE")}"
    .replace("ROLE", user.role) + " • " + user.email;

  document.getElementById("logout").onclick = () => {
    localStorage.removeItem("bh_token");
    localStorage.removeItem("bh_user");
    window.location.href = "/login";
  };
</script>
`;
}

/* ---------------------------
   Public
--------------------------- */
app.get("/", (req, res) => res.redirect("/login"));

app.get("/health", (req, res) => res.json({ ok: true }));

/* ---------------------------
   Auth
--------------------------- */
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const u = USERS.find((x) => x.email === String(email || "").trim());
  if (!u) return res.status(401).json({ error: "Invalid credentials" });

  const ok = bcrypt.compareSync(String(password || ""), u.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken(u);
  audit({ type: "LOGIN", by: u.email, role: u.role, detail: "User logged in" });

  res.json({ token, user: { id: u.id, email: u.email, role: u.role } });
});

/* ---------------------------
   Session API
--------------------------- */
app.get("/api/session", authRequired, (req, res) => {
  res.json({ ok: true, user: req.user });
});

/* ---------------------------
   Role demo endpoints
--------------------------- */
app.get("/api/admin-only", authRequired, requireRole("CLINIC_ADMIN"), (req, res) => {
  audit({ type: "API", by: req.user.email, role: req.user.role, detail: "GET /api/admin-only" });
  res.json({ ok: true, message: "Hello Clinic Admin 👩‍⚕️", user: req.user });
});

app.get("/api/research", authRequired, requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"), (req, res) => {
  audit({ type: "API", by: req.user.email, role: req.user.role, detail: "GET /api/research" });
  res.json({ ok: true, message: "Hello Researcher 📊", user: req.user });
});

/* ---------------------------
   Patients API
--------------------------- */
app.get(
  "/api/patients",
  authRequired,
  requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"),
  (req, res) => {
    audit({ type: "READ", by: req.user.email, role: req.user.role, detail: "List patients" });

    const status = String(req.query.status || "").toUpperCase();
    const q = String(req.query.q || "").toLowerCase();

    let rows = [...PATIENTS];
    if (status) rows = rows.filter((p) => p.status === status);
    if (q) rows = rows.filter((p) => p.id.toLowerCase().includes(q) || p.code.toLowerCase().includes(q));

    res.json({ items: rows, total: rows.length });
  }
);

app.get(
  "/api/patients/:id",
  authRequired,
  requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"),
  (req, res) => {
    const p = PATIENTS.find((x) => x.id === req.params.id);
    if (!p) return res.status(404).json({ error: "Patient not found" });

    audit({ type: "READ", by: req.user.email, role: req.user.role, detail: `Open patient ${p.id}` });
    res.json({ patient: p });
  }
);

app.get(
  "/api/patients/:id/trend",
  authRequired,
  requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"),
  (req, res) => {
    const p = PATIENTS.find((x) => x.id === req.params.id);
    if (!p) return res.status(404).json({ error: "Patient not found" });

    audit({ type: "READ", by: req.user.email, role: req.user.role, detail: `Read trend ${p.id}` });

    const nights = Array.from({ length: 14 }).map((_, i) => {
      const t = i - 7; // -7..+6
      return {
        night: `N-${14 - i}`,
        bsi: Math.max(0, Math.min(100, p.bsi + t * 2)),
        episodes: Math.max(0, Math.round(p.episodes + t)),
      };
    });

    res.json({ patient: p, nights });
  }
);

/* ---------------------------
   Audit API
--------------------------- */
app.get(
  "/api/audit",
  authRequired,
  requireRole("CLINIC_ADMIN", "RESEARCHER"),
  (req, res) => {
    res.json({ items: AUDIT.slice(0, 10) });
  }
);

/* ---------------------------
   UI: Login
--------------------------- */
app.get("/login", (req, res) => {
  res.send(
    page(
      "Brux Holter Clinic | Login",
      `
<div class="max-w-md mx-auto p-6 mt-12">
  <h1 class="text-3xl font-semibold">Clinic Login</h1>
  <p class="text-sm text-slate-500 mt-2">Secure Clinical Portal (Demo MVP)</p>

  <div class="bg-white rounded-2xl shadow p-6 mt-6">
    <label class="text-sm text-slate-600">Email</label>
    <input id="email" class="w-full border rounded-lg p-3 mt-1" placeholder="admin@clinic.com" />

    <label class="text-sm text-slate-600 mt-4 block">Password</label>
    <input id="password" type="password" class="w-full border rounded-lg p-3 mt-1" placeholder="Clinic123!" />

    <button id="btn" class="w-full bg-slate-900 text-white rounded-lg p-3 mt-5">Login</button>

    <p id="err" class="text-sm text-red-600 mt-3 hidden"></p>

    <div class="text-xs text-slate-500 mt-5">
      Demo users:
      <ul class="list-disc ml-5 mt-1">
        <li>admin@clinic.com / Clinic123!</li>
        <li>dentist@clinic.com / Dentist123!</li>
        <li>research@clinic.com / Research123!</li>
      </ul>
    </div>
  </div>
</div>

<script>
  document.getElementById("btn").onclick = async () => {
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    const r = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await r.json();
    const err = document.getElementById("err");

    if (!r.ok) {
      err.textContent = data?.error || "Login failed";
      err.classList.remove("hidden");
      return;
    }

    localStorage.setItem("bh_token", data.token);
    localStorage.setItem("bh_user", JSON.stringify(data.user));
    window.location.href = "/dashboard";
  };
</script>
`
    )
  );
});

/* ---------------------------
   UI: Dashboard
--------------------------- */
app.get("/dashboard", (req, res) => {
  const content = `
<div class="bg-white rounded-2xl shadow p-6">
  <div class="flex items-start justify-between">
    <div>
      <h2 class="text-2xl font-semibold">Dashboard</h2>
      <p class="text-sm text-slate-500 mt-1">Clinical overview (demo data)</p>
    </div>
    <div class="flex gap-2">
      <button class="rounded-lg border px-4 py-2 bg-slate-50 text-slate-400 cursor-not-allowed" disabled>Export PDF</button>
    </div>
  </div>

  <div class="grid md:grid-cols-3 gap-4 mt-6">
    <div class="bg-slate-50 rounded-2xl p-5">
      <div class="text-sm text-slate-500">Patients</div>
      <div id="kpiPatients" class="text-3xl font-semibold mt-1">—</div>
      <a href="/patients" class="text-sm underline text-slate-700 mt-2 inline-block">Open patient list</a>
    </div>
    <div class="bg-slate-50 rounded-2xl p-5">
      <div class="text-sm text-slate-500">Last Night Data</div>
      <div id="kpiLast" class="text-3xl font-semibold mt-1">—</div>
      <div class="text-xs text-slate-500 mt-2">Demo: based on latest sync date</div>
    </div>
    <div class="bg-slate-50 rounded-2xl p-5">
      <div class="text-sm text-slate-500">Alerts</div>
      <div id="kpiAlerts" class="text-3xl font-semibold mt-1">—</div>
      <div class="text-xs text-slate-500 mt-2">Demo: severity-based flags</div>
    </div>
  </div>

  <div class="bg-white rounded-2xl border p-5 mt-6">

<script>
  const token = localStorage.getItem("bh_token");
  const user = JSON.parse(localStorage.getItem("bh_user") || "null");

  document.getElementById("roleTag").textContent = user.role;

  async function call(path) {
    const r = await fetch(path, { headers: { Authorization: "Bearer " + token }});
    const data = await r.json().catch(() => ({ error: "Non-JSON response" }));
    document.getElementById("out").textContent = JSON.stringify({ status: r.status, data }, null, 2);
  }

  document.getElementById("testAdmin").onclick = () => call("/api/admin-only");
  document.getElementById("testResearch").onclick = () => call("/api/research");

  async function loadKpis() {
    const r = await fetch("/api/patients", { headers: { Authorization: "Bearer " + token }});
    const data = await r.json();
    if (!r.ok) return;

    document.getElementById("kpiPatients").textContent = data.total;

    const latest = data.items
      .map(p => p.lastDataAt)
      .sort()
      .slice(-1)[0] || "—";
    document.getElementById("kpiLast").textContent = latest;

    const alerts = data.items.filter(p => p.bsi >= 80).length;
    document.getElementById("kpiAlerts").textContent = alerts;
  }

  loadKpis();
  document.getElementById("session").textContent = JSON.stringify({ user }, null, 2);
</script>
`;
  res.send(page("Brux Holter Clinic | Dashboard", layout("dashboard", content)));
});

/* ---------------------------
   UI: Patients
--------------------------- */
app.get("/patients", (req, res) => {
  const content = `
<div class="bg-white rounded-2xl shadow p-6">
  <div class="flex items-start justify-between">
    <div>
      <h2 class="text-2xl font-semibold">Patients</h2>
      <p class="text-sm text-slate-500 mt-1">Pseudonymous patient list (demo)</p>
    </div>
    <div class="flex gap-2">
      <button class="rounded-lg border px-4 py-2 bg-slate-50 text-slate-400 cursor-not-allowed" disabled>Invite Patient</button>
      <button class="rounded-lg border px-4 py-2 bg-slate-50 text-slate-400 cursor-not-allowed" disabled>Export CSV</button>
    </div>
  </div>

  <div class="flex flex-col md:flex-row gap-3 md:items-center md:justify-between mt-6">
    <div class="flex gap-2 w-full md:w-auto">
      <input id="q" class="w-full md:w-80 rounded-lg border p-3" placeholder="Search by Patient ID or Code (e.g., P-0001 / BH-7Q2A)" />
      <select id="status" class="rounded-lg border p-3">
        <option value="">All</option>
        <option value="ACTIVE">Active</option>
        <option value="ARCHIVED">Archived</option>
      </select>
    </div>
    <div class="text-sm text-slate-500"><span id="count">0</span> patients</div>
  </div>

  <p id="err" class="text-sm text-red-600 mt-3 hidden"></p>

  <div class="overflow-auto mt-4">
    <table class="min-w-full text-sm">
      <thead>
        <tr class="text-left text-slate-500 border-b">
          <th class="py-3 pr-4">Patient ID</th>
          <th class="py-3 pr-4">Code</th>
          <th class="py-3 pr-4">Age</th>
          <th class="py-3 pr-4">Gender</th>
          <th class="py-3 pr-4">Status</th>
          <th class="py-3 pr-4">Treatment</th>
          <th class="py-3 pr-4">BSI</th>
          <th class="py-3 pr-4">Episodes</th>
          <th class="py-3 pr-4">Last Data</th>
          <th class="py-3 pr-4">Trend</th>
          <th class="py-3 pr-4"></th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div>

<script>
  const token = localStorage.getItem("bh_token");
  const err = document.getElementById("err");
  const rowsEl = document.getElementById("rows");
  const countEl = document.getElementById("count");

  function b(text){ return '<span class="text-xs rounded-full bg-slate-100 px-3 py-1">' + text + '</span>'; }

  async function load() {
    err.classList.add("hidden");
    rowsEl.innerHTML = "";

    const q = document.getElementById("q").value.trim();
    const status = document.getElementById("status").value;

    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (status) params.set("status", status);

    const r = await fetch("/api/patients?" + params.toString(), {
      headers: { Authorization: "Bearer " + token }
    });

    const data = await r.json();
    if (!r.ok) {
      err.textContent = data?.error || "Failed to load patients";
      err.classList.remove("hidden");
      return;
    }

    countEl.textContent = data.total;

    for (const p of data.items) {
      const tr = document.createElement("tr");
      tr.className = "border-b last:border-b-0";
      tr.innerHTML = \`
        <td class="py-3 pr-4 font-medium">\${p.id}</td>
        <td class="py-3 pr-4">\${p.code}</td>
        <td class="py-3 pr-4">\${p.age}</td>
        <td class="py-3 pr-4">\${p.gender}</td>
        <td class="py-3 pr-4">\${b(p.status)}</td>
        <td class="py-3 pr-4">\${b(p.treatment)}</td>
        <td class="py-3 pr-4">\${p.bsi}</td>
        <td class="py-3 pr-4">\${p.episodes}</td>
        <td class="py-3 pr-4">\${p.lastDataAt}</td>
        <td class="py-3 pr-4">\${b(p.trend)}</td>
        <td class="py-3 pr-4">
          <a class="underline" href="/patients/\${encodeURIComponent(p.id)}">View</a>
        </td>
      \`;
      rowsEl.appendChild(tr);
    }
  }

  document.getElementById("q").addEventListener("input", () => {
    clearTimeout(window.__t);
    window.__t = setTimeout(load, 250);
  });
  document.getElementById("status").addEventListener("change", load);

  load();
</script>
`;
  res.send(page("Brux Holter Clinic | Patients", layout("patients", content)));
});

/* ---------------------------
   UI: Patient Detail + Chart
--------------------------- */
app.get("/patients/:id", (req, res) => {
  const pid = req.params.id;

  const content = `
<div class="bg-white rounded-2xl shadow p-6">
  <div class="flex items-start justify-between">
    <div>
      <h2 class="text-2xl font-semibold">Patient Detail</h2>
      <p class="text-sm text-slate-500 mt-1">Clinical snapshot + trend (demo)</p>
    </div>
    <div class="flex gap-2">
      <button class="rounded-lg border px-4 py-2 bg-slate-50 text-slate-400 cursor-not-allowed" disabled>Export PDF</button>
      <a href="/patients" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Back</a>
    </div>
  </div>

  <div class="bg-white rounded-2xl border p-5 mt-6">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm text-slate-500">Patient</div>
        <div id="title" class="text-xl font-semibold mt-1">—</div>
      </div>
      <span id="badge" class="text-xs rounded-full bg-slate-100 px-3 py-1">—</span>
    </div>

    <div class="grid md:grid-cols-4 gap-4 mt-4">
      <div class="bg-slate-50 rounded-xl p-4">
        <div class="text-xs text-slate-500">BSI</div>
        <div id="bsi" class="text-2xl font-semibold mt-1">—</div>
      </div>
      <div class="bg-slate-50 rounded-xl p-4">
        <div class="text-xs text-slate-500">Episodes</div>
        <div id="episodes" class="text-2xl font-semibold mt-1">—</div>
      </div>
      <div class="bg-slate-50 rounded-xl p-4">
        <div class="text-xs text-slate-500">Last Data</div>
        <div id="last" class="text-2xl font-semibold mt-1">—</div>
      </div>
      <div class="bg-slate-50 rounded-xl p-4">
        <div class="text-xs text-slate-500">Trend</div>
        <div id="trend" class="text-2xl font-semibold mt-1">—</div>
      </div>
    </div>
  </div>

  <div class="bg-white rounded-2xl border p-5 mt-6">
    <h3 class="font-semibold">BSI Trend (last 14 nights)</h3>
    <p class="text-sm text-slate-500 mt-1">Mock series generated on the backend</p>
    <canvas id="chart" height="120" class="mt-4"></canvas>
    <pre id="err" class="text-sm text-red-600 mt-3 hidden"></pre>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
  const token = localStorage.getItem("bh_token");

  async function load() {
    const r = await fetch("/api/patients/${encodeURIComponent(pid)}/trend", {
      headers: { Authorization: "Bearer " + token }
    });
    const data = await r.json();

    if (!r.ok) {
      const err = document.getElementById("err");
      err.textContent = JSON.stringify(data, null, 2);
      err.classList.remove("hidden");
      return;
    }

    const p = data.patient;
    document.getElementById("title").textContent = p.id + " • " + p.code;
    document.getElementById("badge").textContent = p.status + " • " + p.treatment;
    document.getElementById("bsi").textContent = p.bsi;
    document.getElementById("episodes").textContent = p.episodes;
    document.getElementById("last").textContent = p.lastDataAt;
    document.getElementById("trend").textContent = p.trend;

    const ctx = document.getElementById("chart").getContext("2d");
    new Chart(ctx, {
      type: "line",
      data: {
        labels: data.nights.map(n => n.night),
        datasets: [{
          label: "BSI",
          data: data.nights.map(n => n.bsi),
          borderWidth: 2,
          tension: 0.3
        }]
      },
      options: { scales: { y: { min: 0, max: 100 } } }
    });
  }

  load();
</script>
`;
  res.send(page("Brux Holter Clinic | Patient", layout("patients", content)));
});

/* ---------------------------
   UI: Audit Log
--------------------------- */
app.get("/audit", (req, res) => {
  const content = `
<div class="bg-white rounded-2xl shadow p-6">
  <div class="flex items-start justify-between">
    <div>
      <h2 class="text-2xl font-semibold">Access Log</h2>
      <p class="text-sm text-slate-500 mt-1">Audit trail (demo)</p>
    </div>
    <button class="rounded-lg border px-4 py-2 bg-slate-50 text-slate-400 cursor-not-allowed" disabled>Export</button>
  </div>

  <p class="text-sm text-slate-500 mt-4">
    Visible to <b>Clinic Admin</b> and <b>Researcher</b> roles only (demo policy).
  </p>

  <p id="err" class="text-sm text-red-600 mt-3 hidden"></p>

  <div class="overflow-auto mt-4">
    <table class="min-w-full text-sm">
      <thead>
        <tr class="text-left text-slate-500 border-b">
          <th class="py-3 pr-4">Time</th>
          <th class="py-3 pr-4">Type</th>
          <th class="py-3 pr-4">User</th>
          <th class="py-3 pr-4">Role</th>
          <th class="py-3 pr-4">Detail</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div>

<script>
  const token = localStorage.getItem("bh_token");
  const err = document.getElementById("err");
  const rowsEl = document.getElementById("rows");

  async function load() {
    err.classList.add("hidden");
    rowsEl.innerHTML = "";

    const r = await fetch("/api/audit", {
      headers: { Authorization: "Bearer " + token }
    });

    const data = await r.json().catch(() => ({ error: "Non-JSON" }));
    if (!r.ok) {
      err.textContent = data?.error || "Forbidden";
      err.classList.remove("hidden");
      return;
    }

    for (const a of data.items) {
      const tr = document.createElement("tr");
      tr.className = "border-b last:border-b-0";
      tr.innerHTML = \`
        <td class="py-3 pr-4 whitespace-nowrap">\${a.at}</td>
        <td class="py-3 pr-4">\${a.type}</td>
        <td class="py-3 pr-4">\${a.by}</td>
        <td class="py-3 pr-4">\${a.role}</td>
        <td class="py-3 pr-4">\${a.detail}</td>
      \`;
      rowsEl.appendChild(tr);
    }
  }
  load();
</script>
`;
  res.send(page("Brux Holter Clinic | Audit", layout("audit", content)));
});

/* ---------------------------
   Start
--------------------------- */
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
