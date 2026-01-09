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
