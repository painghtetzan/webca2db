const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

/* ===================== CONFIG ===================== */
const port = process.env.PORT || 5000;
const secret = process.env.JWT;

if (!secret) {
  throw new Error("❌ JWT secret missing. Set JWT in environment variables.");
}

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

/* ===================== DB POOL (FAST) ===================== */
const pool = mysql.createPool(dbConfig);

/* ===================== CORS ===================== */
// Put your frontend URLs here (local + deployed)
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://educationreminder.netlify.app",
  "https://www.educationreminder.netlify.app",
];

// Allow requests with no Origin (e.g., Postman) + allowed origins
const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error("CORS not allowed for this origin: " + origin));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

/* ===================== MIDDLEWARE ===================== */
app.use(express.json());

/* ===================== HELPERS ===================== */
function signToken(userRow) {
  return jwt.sign(
    {
      userId: userRow.id,
      userName: userRow.name,
      userRole: userRow.role,
      userSchool: userRow.school,
    },
    secret,
    { expiresIn: "1h" }
  );
}

/* ===================== AUTH ===================== */
function authenticator(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) return res.status(401).json({ message: "Authentication failed" });

  try {
    const decoded = jwt.verify(token, secret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Authorization failed" });
  }
}

function requireLecturer(req, res, next) {
  if (req.user?.userRole !== "lecturer") {
    return res.status(403).json({ message: "Forbidden: Lecturer only" });
  }
  next();
}

/* ===================== HEALTH ===================== */
app.get("/", (req, res) => {
  res.json({ ok: true, message: "Backend is running" });
});

app.get("/health/db", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: rows[0] });
  } catch (e) {
    res.status(500).json({ ok: false, message: "DB not reachable", error: e.message });
  }
});

/* ===================== ROUTES ===================== */

/* ---------- GET ACTIVITIES ---------- */
app.get("/allactivities", authenticator, async (req, res) => {
  try {
    const { userSchool } = req.user;
    const [rows] = await pool.execute(
      "SELECT * FROM Information WHERE school=? ORDER BY time ASC",
      [userSchool]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error retrieving activities" });
  }
});

/* ---------- ADD ACTIVITY (LECTURER ONLY) ---------- */
app.post("/add", authenticator, requireLecturer, async (req, res) => {
  const { type, time, name, description } = req.body;
  const { userId, userSchool } = req.user;

  if (!type || !time || !name) {
    return res.status(400).json({ message: "Missing required fields: type, time, name" });
  }

  try {
    await pool.execute(
      "INSERT INTO Information (time,name,createdBy_id,school,description,type) VALUES (?,?,?,?,?,?)",
      [time, name, userId, userSchool, description || "", type]
    );
    res.status(201).json({ message: "Created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Create failed" });
  }
});

/* ---------- UPDATE (LECTURER ONLY) ---------- */
app.put("/edit/:id", authenticator, requireLecturer, async (req, res) => {
  const { time, name, description, type } = req.body;
  const { id } = req.params;

  if (!type || !time || !name) {
    return res.status(400).json({ message: "Missing required fields: type, time, name" });
  }

  try {
    const [result] = await pool.execute(
      "UPDATE Information SET time=?, name=?, description=?, type=? WHERE id=?",
      [time, name, description || "", type, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Item not found" });
    }

    res.json({ message: "Update success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Update failed" });
  }
});

/* ---------- DELETE (LECTURER ONLY) ---------- */
app.delete("/delete/:id", authenticator, requireLecturer, async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.execute("DELETE FROM Information WHERE id=?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Item not found" });
    }

    res.json({ message: "Delete success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Delete failed" });
  }
});

/* ---------- REGISTER ---------- */
app.post("/register", async (req, res) => {
  const { name, email, password, role, school } = req.body;

  if (!name || !email || !password || !role || !school) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const [rows] = await pool.execute(
      "SELECT id FROM Registeration WHERE email=?",
      [email]
    );

    if (rows.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.execute(
      "INSERT INTO Registeration (name,email,password,role,school) VALUES (?,?,?,?,?)",
      [name, email, hashedPassword, role, school]
    );

    res.status(201).json({ message: "Registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Registration failed" });
  }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    const [rows] = await pool.execute(
      "SELECT * FROM Registeration WHERE email=?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const valid = await bcrypt.compare(password, rows[0].password);
    if (!valid) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = signToken(rows[0]);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* ===================== GLOBAL ERROR HANDLER ===================== */
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({ message: err.message || "Server error" });
});

/* ===================== START ===================== */
app.listen(port, async () => {
  console.log(`✅ Server running on port ${port}`);
  try {
    await pool.query("SELECT 1");
    console.log("✅ DB connected");
  } catch (e) {
    console.log("⚠️ DB connection check failed:", e.message);
  }
});
