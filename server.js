const express = require("express");
const sql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

// ===================== MIDDLEWARE =====================
app.use(express.json());

// ===================== CORS CONFIG =====================
const allowedOrigins = [
  process.env.FRONTEND_URL_LOCAL,
  process.env.FRONTEND_URL_LOCAL2,
  process.env.FRONTEND_URL_PROD
].filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true); // allow Postman / curl
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    }
  })
);

// ===================== DB CONFIG =====================
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const secret = process.env.JWT;

// ===================== AUTH MIDDLEWARE =====================
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

// ===================== TEST ROUTE =====================
app.get("/", (req, res) => {
  res.json({ message: "Backend running" });
});

app.get("/dbtest", async (req, res) => {
  let connection;
  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute("SELECT 1");
    res.json({ db: "connected" });
  } catch (err) {
    res.status(500).json({ db: "failed", error: err.message });
  } finally {
    if (connection) await connection.end();
  }
});

// ===================== AUTH ROUTES =====================
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

    res.status(201).json({ message: "Successfully registered" });
  } catch (err) {
    res.status(500).json({ message: "Registration failed" });
  } finally {
    if (connection) await connection.end();
  }
});

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
        userSchool: rows[0].school
      },
      secret,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Login failed" });
  } finally {
    if (connection) await connection.end();
  }
});

// ===================== ACTIVITY ROUTES =====================
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
    res.status(500).json({ message: "Error retrieving activities" });
  } finally {
    if (connection) await connection.end();
  }
});

app.post("/add", authenticator, async (req, res) => {
  const { type, time, name, description } = req.body;
  const { userId, userSchool } = req.user;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute(
      "INSERT INTO Information (time,name,createdBy_id,school,description,type) VALUES (?,?,?,?,?,?)",
      [time, name, userId, userSchool, description, type]
    );
    res.status(201).json({ message: "Created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Create failed" });
  } finally {
    if (connection) await connection.end();
  }
});

app.put("/edit/:id", authenticator, async (req, res) => {
  const { id } = req.params;
  const { time, name, description, type } = req.body;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute(
      "UPDATE Information SET time=?, name=?, description=?, type=? WHERE id=?",
      [time, name, description, type, id]
    );
    res.json({ message: "Update success" });
  } catch (err) {
    res.status(500).json({ message: "Update failed" });
  } finally {
    if (connection) await connection.end();
  }
});

app.delete("/delete/:id", authenticator, async (req, res) => {
  const { id } = req.params;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute("DELETE FROM Information WHERE id=?", [id]);
    res.json({ message: "Delete success" });
  } catch (err) {
    res.status(500).json({ message: "Delete failed" });
  } finally {
    if (connection) await connection.end();
  }
});

// ===================== START SERVER =====================
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
