import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET env var. Set it in Render Environment Variables.");
  process.exit(1);
}

// -----------------------------
// In-memory demo users (MVP)
// Replace with DB later
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
// Helpers
// -----------------------------
function signToken(user) {
  // Keep token payload minimal
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { sub, role, email, iat, exp }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const role = req.user?.role;
    if (!role || !allowedRoles.includes(role)) {
      return res.status(403).json({ error: "Forbidden (insufficient role)" });
    }
    next();
  };
}

// -----------------------------
// Public routes
// -----------------------------
app.get("/", (req, res) => {
  res.send("Brux Holter Clinic Web API is running ✅");
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});
// -----------------------------
// Simple Clinic Web UI (MVP)
// -----------------------------
function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900">
  ${body}
</body>
</html>`;
}

app.get("/login", (req, res) => {
  res.send(page("Brux Holter Clinic | Login", `
  <div class="min-h-screen flex items-center justify-center p-6">
    <div class="w-full max-w-md bg-white rounded-2xl shadow p-6">
      <h1 class="text-2xl font-semibold">Clinic Login</h1>
      <p class="text-sm text-slate-500 mt-1">Brux Holter – Clinical Portal</p>

      <div class="mt-6 space-y-3">
        <label class="block text-sm font-medium">Email</label>
        <input id="email" class="w-full rounded-lg border p-3" placeholder="admin@clinic.com" />

        <label class="block text-sm font-medium mt-2">Password</label>
        <input id="password" type="password" class="w-full rounded-lg border p-3" placeholder="••••••••" />

        <button id="btn" class="w-full mt-4 rounded-lg bg-slate-900 text-white p-3 font-medium">
          Sign in
        </button>

        <p id="err" class="text-sm text-red-600 mt-2 hidden"></p>

        <div class="mt-4 text-xs text-slate-500">
          Demo users:<br/>
          Admin: admin@clinic.com / Clinic123!<br/>
          Dentist: dentist@clinic.com / Dentist123!<br/>
          Research: research@clinic.com / Research123!
        </div>
      </div>
    </div>
  </div>

  <script>
    const err = document.getElementById("err");
    document.getElementById("btn").onclick = async () => {
      err.classList.add("hidden");
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;

      const r = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      const data = await r.json();
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
  `));
});

app.get("/dashboard", (req, res) => {
  res.send(page("Brux Holter Clinic | Dashboard", `
  <div class="max-w-5xl mx-auto p-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold">Clinic Dashboard</h1>
        <p class="text-sm text-slate-500">Secure Clinical Portal (MVP)</p>
      </div>
      <button id="logout" class="rounded-lg border px-4 py-2 bg-white hover:bg-slate-50">
        Logout
      </button>
    </div>

    <div class="grid md:grid-cols-3 gap-4 mt-6">
      <div class="bg-white rounded-2xl shadow p-5">
        <div class="text-sm text-slate-500">Patients</div>
        <div class="text-2xl font-semibold mt-1">—</div>
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
        <span id="role" class="text-xs rounded-full bg-slate-100 px-3 py-1"></span>
      </div>

      <pre id="me" class="text-xs bg-slate-50 rounded-xl p-4 mt-4 overflow-auto"></pre>

      <div class="mt-4 flex gap-2">
        <button id="adminTest" class="rounded-lg bg-slate-900 text-white px-4 py-2 text-sm">
          Test Admin Endpoint
        </button>
        <button id="researchTest" class="rounded-lg border px-4 py-2 text-sm bg-white hover:bg-slate-50">
          Test Research Endpoint
        </button>
      </div>

      <pre id="out" class="text-xs bg-slate-50 rounded-xl p-4 mt-4 overflow-auto"></pre>
    </div>
  </div>

  <script>
    const token = localStorage.getItem("bh_token");
    const user = JSON.parse(localStorage.getItem("bh_user") || "null");

    if (!token || !user) {
      window.location.href = "/login";
    }

    document.getElementById("role").textContent = user.role + " • " + user.email;

    document.getElementById("logout").onclick = () => {
      localStorage.removeItem("bh_token");
      localStorage.removeItem("bh_user");
      window.location.href = "/login";
    };

    async function call(path) {
      const r = await fetch(path, { headers: { Authorization: "Bearer " + token } });
      const data = await r.json();
      return { ok: r.ok, status: r.status, data };
    }

    (async () => {
      const me = await call("/auth/me");
      document.getElementById("me").textContent = JSON.stringify(me, null, 2);
    })();

    document.getElementById("adminTest").onclick = async () => {
      const res = await call("/api/admin-only");
      document.getElementById("out").textContent = JSON.stringify(res, null, 2);
    };

    document.getElementById("researchTest").onclick = async () => {
      const res = await call("/api/research");
      document.getElementById("out").textContent = JSON.stringify(res, null, 2);
    };
  </script>
  `));
});

// -----------------------------
// Auth routes
// -----------------------------
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  const user = USERS.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken(user);

  return res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
});

app.get("/auth/me", authRequired, (req, res) => {
  // Token payload is the session for now
  res.json({ user: req.user });
});

// Logout is client-side: delete token
app.post("/auth/logout", authRequired, (req, res) => {
  res.json({ ok: true });
});

// -----------------------------
// Protected demo endpoints (role-based)
// -----------------------------
app.get("/api/admin-only", authRequired, requireRole("CLINIC_ADMIN"), (req, res) => {
  res.json({ ok: true, message: "Hello Clinic Admin 👩‍⚕️", user: req.user });
});

app.get(
  "/api/clinical",
  authRequired,
  requireRole("CLINIC_ADMIN", "CLINICIAN"),
  (req, res) => {
    res.json({ ok: true, message: "Hello Clinician 🦷", user: req.user });
  }
);

app.get(
  "/api/research",
  authRequired,
  requireRole("CLINIC_ADMIN", "CLINICIAN", "RESEARCHER"),
  (req, res) => {
    res.json({ ok: true, message: "Hello Researcher 📊", user: req.user });
  }
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
