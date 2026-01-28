const express = require("express");
const sql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

/* ===================== PORT ===================== */
const port = process.env.PORT || 5000;

/* ===================== CORS (FIXED) ===================== */
/*
  This FIXES:
  - CORS blocked
  - OPTIONS /login 404
  - No Access-Control-Allow-Origin header
*/
const corsOptions = {
  origin: [
    "http://localhost:3000",
    "https://educationreminder.netlify.app",
    "https://www.educationreminder.netlify.app",
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // ✅ VERY IMPORTANT

/* ===================== MIDDLEWARE ===================== */
app.use(express.json());

/* ===================== DB CONFIG ===================== */
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

/* ===================== JWT ===================== */
const secret = process.env.JWT;
if (!secret) {
  console.error("❌ JWT secret missing in environment variables");
}

/* ===================== HEALTH CHECK ===================== */
app.get("/", (req, res) => {
  res.json({ ok: true, message: "Backend is running" });
});

/* ===================== AUTH MIDDLEWARE ===================== */
function authenticator(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Authorization failed" });
    }
    req.user = decoded;
    next();
  });
}

/* ===================== ROUTES ===================== */

/* ---------- GET ACTIVITIES ---------- */
app.get("/allactivities", authenticator, async (req, res) => {
  const { userSchool } = req.user;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT * FROM Information WHERE school=?",
      [userSchool]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error retrieving activities" });
  } finally {
    if (connection) await connection.end();
  }
});

/* ---------- ADD ACTIVITY ---------- */
app.post("/add", authenticator, async (req, res) => {
  const { type, time, name, description } = req.body;
  const { userId, userSchool } = req.user;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute(
      "INSERT INTO Information (time,name,createdBy_id,school,description,type) VALUES (?,?,?,?,?,?)",
      [time, name, userId, userSchool, description || "", type]
    );
    res.status(201).json({ message: "Created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Create failed" });
  } finally {
    if (connection) await connection.end();
  }
});

/* ---------- UPDATE ---------- */
app.put("/edit/:id", authenticator, async (req, res) => {
  const { time, name, description, type } = req.body;
  const id = req.params.id;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute(
      "UPDATE Information SET time=?, name=?, description=?, type=? WHERE id=?",
      [time, name, description || "", type, id]
    );
    res.json({ message: "Update success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Update failed" });
  } finally {
    if (connection) await connection.end();
  }
});

/* ---------- DELETE ---------- */
app.delete("/delete/:id", authenticator, async (req, res) => {
  const id = req.params.id;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute("DELETE FROM Information WHERE id=?", [id]);
    res.json({ message: "Delete success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Delete failed" });
  } finally {
    if (connection) await connection.end();
  }
});

/* ---------- REGISTER ---------- */
app.post("/register", async (req, res) => {
  const { name, email, password, role, school } = req.body;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT * FROM Registeration WHERE email=?",
      [email]
    );

    if (rows.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.execute(
      "INSERT INTO Registeration (name,email,password,role,school) VALUES (?,?,?,?,?)",
      [name, email, hashedPassword, role, school]
    );

    res.status(201).json({ message: "Registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Registration failed" });
  } finally {
    if (connection) await connection.end();
  }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    const [rows] = await connection.execute(
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

    const token = jwt.sign(
      {
        userId: rows[0].id,
        userName: rows[0].name,
        userRole: rows[0].role,
        userSchool: rows[0].school,
      },
      secret,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  } finally {
    if (connection) await connection.end();
  }
});

/* ===================== START SERVER ===================== */
app.listen(port, () => {
  console.log(`✅ Server running on port ${port}`);
});
