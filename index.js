import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -----------------------------
// Basic Security Headers (CSP included)
// -----------------------------
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");

  // Allow our own origin + Chart.js CDN
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
      "connect-src 'self'",
      "font-src 'self' data:",
    ].join("; ")
  );

  next();
});

// -----------------------------
// Config
// -----------------------------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// -----------------------------
// Mock Users (Replace with DB later)
// -----------------------------
const USERS = [
  // password: Clinic123!
  {
    id: "u1",
    email: "admin@clinic.com",
    role: "CLINIC_ADMIN",
    passwordHash: bcrypt.hashSync("Clinic123!", 10),
  },
  // password: Dentist123!
  {
    id: "u2",
    email: "dentist@clinic.com",
    role: "CLINICIAN",
    passwordHash: bcrypt.hashSync("Dentist123!", 10),
  },
  // password: Research123!
  {
    id: "u3",
    email: "research@clinic.com",
    role: "RESEARCHER",
    passwordHash: bcrypt.hashSync("Research123!", 10),
  },
];

// -----------------------------
// Mock Patients (MVP)
// -----------------------------
const PATIENTS = [
  {
    id: "P-0001",
    code: "BH-7Q2A",
    age: 32,
    gender: "F",
    status: "ACTIVE", // ACTIVE | ARCHIVED
    treatment: "MONITORING", // MONITORING | SPLINT | BOTOX | PHYSIO | OTHER
    lastDataAt: "2026-01-08",
    bsi: 68, // 0-100
    episodes: 22,
    trend: "IMPROVING", // IMPROVING | STABLE | WORSENING
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

// -----------------------------
// Helpers
// -----------------------------
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
  } catch (e) {
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

function page(title, bodyHtml) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900">
${bodyHtml}
</body>
</html>`;
}

// -----------------------------
// Public Routes
// -----------------------------
app.get("/", (req, res) => res.redirect("/login"));

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// -----------------------------
// Auth Routes
// -----------------------------
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const u = USERS.find((x) => x.email === String(email || "").trim());
  if (!u) return res.status(401).json({ error: "Invalid credentials" });

  const ok = bcrypt.compareSync(String(password || ""), u.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken(u);
  res.json({ token, user: { id: u.id, email: u.email, role: u.role } });
});

// -----------------------------
// Protected demo endpoints (role-based)
// -----------------------------
app.get("/api/admin-only", authRequired, requireRole("CLINIC_ADMIN"), (req, res) => {
  res.json({ ok: true, message: "Hello Clinic Admin 👩‍⚕️", user: req.user });
});

app.get("/api/clinical", authRequired, requireRole("CLINIC_ADMIN", "CLINICIAN"), (req, res) => {
  res.json({ ok: true, message: "Hello Clinician 🦷", user: req.user });
});

app.get("/api/research", authRequired, requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"), (req, res) => {
  res.json({ ok: true, message: "Hello Researcher 📊", user: req.user });
});

// -----------------------------
// Patients API (Protected)
// -----------------------------
app.get(
  "/api/patients",
  authRequired,
  requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"),
  (req, res) => {
    const status = String(req.query.status || "").toUpperCase(); // ACTIVE/ARCHIVED
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
    res.json({ patient: p });
  }
);

// Trend endpoint (this is what was 404 before)
app.get(
  "/api/patients/:id/trend",
  authRequired,
  requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"),
  (req, res) => {
    const p = PATIENTS.find((x) => x.id === req.params.id);
    if (!p) return res.status(404).json({ error: "Patient not found" });

    // Mock last 14 nights trend
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

// -----------------------------
// UI Routes (Clinic Web)
// -----------------------------
app.get("/login", (req, res) => {
  res.send(
    page(
      "Brux Holter Clinic | Login",
      `
<div class="max-w-md mx-auto p-6 mt-12">
  <h1 class="text-3xl font-semibold">Clinic Login</h1>
  <p class="text-sm text-slate-500 mt-2">Secure Clinical Portal (MVP)</p>

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

app.get("/dashboard", (req, res) => {
  res.send(
    page(
      "Brux Holter Clinic | Dashboard",
      `
<div class="max-w-6xl mx-auto p-6">
  <div class="flex items-start justify-between">
    <div>
      <h1 class="text-3xl font-semibold">Clinic Dashboard</h1>
      <p class="text-sm text-slate-500 mt-1">Secure Clinical Portal (MVP)</p>
    </div>
    <button id="logout" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Logout</button>
  </div>

  <div class="grid md:grid-cols-3 gap-4 mt-6">
    <div class="bg-white rounded-2xl shadow p-5">
      <div class="text-sm text-slate-500">Patients</div>
      <div class="text-2xl font-semibold mt-1">—</div>
      <a href="/patients" class="text-sm underline text-slate-700 mt-2 inline-block">Open patient list</a>
    </div>
    <div class="bg-white rounded-2xl shadow p-5">
      <div class="text-sm text-slate-500">Last Night Data</div>
      <div class="text-2xl font-semibold mt-1">—</div>
    </div>
    <div class="bg-white rounded-2xl shadow p-5">
      <div class="text-sm text-slate-500">Alerts</div>
      <div class="text-2xl font-semibold mt-1">—</div>
    </div>
  </div>

  <div class="bg-white rounded-2xl shadow p-5 mt-6">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-semibold">Session</h2>
      <span id="who" class="text-xs rounded-full bg-slate-100 px-3 py-1">—</span>
    </div>

    <pre id="session" class="text-sm bg-slate-50 p-4 rounded mt-4 overflow-auto"></pre>

    <div class="flex gap-3 mt-4">
      <button id="testAdmin" class="rounded-lg border px-4 py-2 bg-slate-900 text-white">Test Admin Endpoint</button>
      <button id="testResearch" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Test Research Endpoint</button>
    </div>

    <pre id="out" class="text-sm bg-slate-50 p-4 rounded mt-4 overflow-auto"></pre>
  </div>
</div>

<script>
  const token = localStorage.getItem("bh_token");
  const user = JSON.parse(localStorage.getItem("bh_user") || "null");
  if (!token || !user) window.location.href = "/login";

  document.getElementById("who").textContent = user.role + " • " + user.email;
  document.getElementById("session").textContent = JSON.stringify({ user }, null, 2);

  document.getElementById("logout").onclick = () => {
    localStorage.removeItem("bh_token");
    localStorage.removeItem("bh_user");
    window.location.href = "/login";
  };

  async function call(path) {
    const r = await fetch(path, { headers: { Authorization: "Bearer " + token }});
    const data = await r.json().catch(() => ({ error: "Non-JSON response" }));
    document.getElementById("out").textContent = JSON.stringify({ status: r.status, data }, null, 2);
  }

  document.getElementById("testAdmin").onclick = () => call("/api/admin-only");
  document.getElementById("testResearch").onclick = () => call("/api/research");
</script>
`
    )
  );
});

app.get("/patients", (req, res) => {
  res.send(
    page(
      "Brux Holter Clinic | Patients",
      `
<div class="max-w-6xl mx-auto p-6">
  <div class="flex items-center justify-between">
    <div>
      <h1 class="text-2xl font-semibold">Patients</h1>
      <p class="text-sm text-slate-500">Pseudonymous patient list (MVP)</p>
    </div>
    <div class="flex gap-2">
      <a href="/dashboard" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Back</a>
      <button id="logout" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Logout</button>
    </div>
  </div>

  <div class="bg-white rounded-2xl shadow p-5 mt-6">
    <div class="flex flex-col md:flex-row gap-3 md:items-center md:justify-between">
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

    <div class="overflow-auto mt-4">
      <table class="min-w-full text-sm">
        <thead>
          <tr class="text-left text-slate-500 border-b">
            <th class="py-3 pr-4">Patient ID</th>
            <th class="py-3 pr-4">Code</th>
            <th class="py-3 pr-4">Age</th>
            <th class="py-3 pr-4">Gender</th>
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

    <p id="err" class="text-sm text-red-600 mt-3 hidden"></p>
  </div>
</div>

<script>
  const token = localStorage.getItem("bh_token");
  const user = JSON.parse(localStorage.getItem("bh_user") || "null");
  if (!token || !user) window.location.href = "/login";

  document.getElementById("logout").onclick = () => {
    localStorage.removeItem("bh_token");
    localStorage.removeItem("bh_user");
    window.location.href = "/login";
  };

  const err = document.getElementById("err");
  const rowsEl = document.getElementById("rows");
  const countEl = document.getElementById("count");

  function badge(text) {
    return '<span class="text-xs rounded-full bg-slate-100 px-3 py-1">' + text + '</span>';
  }

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
        <td class="py-3 pr-4">\${badge(p.treatment)}</td>
        <td class="py-3 pr-4">\${p.bsi}</td>
        <td class="py-3 pr-4">\${p.episodes}</td>
        <td class="py-3 pr-4">\${p.lastDataAt}</td>
        <td class="py-3 pr-4">\${badge(p.trend)}</td>
        <td class="py-3 pr-4"><a class="underline" href="/patients/\${encodeURIComponent(p.id)}">View</a></td>
      \`;
      rowsEl.appendChild(tr);
    }
  }

  document.getElementById("q").addEventListener("input", () => {
    window.clearTimeout(window.__t);
    window.__t = window.setTimeout(load, 250);
  });
  document.getElementById("status").addEventListener("change", load);

  load();
</script>
`
    )
  );
});

app.get("/patients/:id", (req, res) => {
  res.send(
    page(
      "Brux Holter Clinic | Patient",
      `
<div class="max-w-6xl mx-auto p-6">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-semibold">Patient Detail</h1>
    <div class="flex gap-2">
      <a href="/patients" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Back</a>
      <button id="logout" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">Logout</button>
    </div>
  </div>

  <div class="bg-white rounded-2xl shadow p-5 mt-6">
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

  <div class="bg-white rounded-2xl shadow p-5 mt-6">
    <h2 class="font-semibold">BSI Trend (last 14 nights)</h2>
    <p class="text-sm text-slate-500 mt-1">Mock data for MVP</p>
    <canvas id="chart" height="120" class="mt-4"></canvas>
    <pre id="err" class="text-sm text-red-600 mt-3 hidden"></pre>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
  const token = localStorage.getItem("bh_token");
  const user = JSON.parse(localStorage.getItem("bh_user") || "null");
  if (!token || !user) window.location.href = "/login";

  document.getElementById("logout").onclick = () => {
    localStorage.removeItem("bh_token");
    localStorage.removeItem("bh_user");
    window.location.href = "/login";
  };

  async function load() {
    const r = await fetch("/api/patients/${encodeURIComponent(req.params.id)}/trend", {
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
`
    )
  );
});

// -----------------------------
// Start
// -----------------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
