const express = require("express");
const sql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();
app.use(express.json());

// Render/hosting uses PORT env var
const port = process.env.PORT || 3000;

// JWT secret (keep your existing env name, but also support JWT_SECRET)
const secret = process.env.JWT || process.env.JWT_SECRET;
if (!secret) {
  console.warn("⚠️ JWT secret missing. Set JWT or JWT_SECRET in your environment.");
}

// DB config
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnection: true,
  connectionLimit: 100,
  queueLimit: 0,
};

// CORS: allow local dev + optional deployed frontend URL(s)
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  process.env.FRONTEND_URL,
  process.env.FRONTEND_URL_2,
].filter(Boolean);

app.use(
  cors({
    origin(origin, cb) {
      // Allow server-to-server / Postman / curl (no origin)
      if (!origin) return cb(null, true);

      if (allowedOrigins.includes(origin)) return cb(null, true);

      return cb(new Error(`CORS blocked for origin: ${origin}`), false);
    },
    credentials: true,
  })
);

app.get("/", (req, res) => {
  res.json({ status: "ok" });
});

function authenticator(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Authentication failed" });
  }
  if (!secret) {
    return res.status(500).json({ message: "Server JWT secret not configured" });
  }

  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Authorization failed" });
    }
    req.user = decoded;
    next();
  });
}

app.get("/allactivities", authenticator, async (req, res) => {
  const { userSchool } = req.user;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT * FROM Information WHERE school=?",
      [userSchool]
    );
    res.status(200).json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error retrieving all activities." });
  } finally {
    if (connection) await connection.end();
  }
});

app.post("/add", authenticator, async (req, res) => {
  let connection;

  const { type, time, name, description } = req.body;
  const { userId, userSchool } = req.user;

  if (!type || !time || !name) {
    return res.status(400).json({ message: "type, time, name are required" });
  }

  try {
    connection = await sql.createConnection(dbConfig);

    // Avoid hardcoding schema name like defaultdb.
    await connection.execute(
      "INSERT INTO Information (time,name,createdBy_id,school,description,type) VALUES (?,?,?,?,?,?)",
      [time, name, userId, userSchool, description || "", type]
    );

    res.status(201).json({ message: "successfully created" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error creating new item" });
  } finally {
    if (connection) await connection.end();
  }
});

app.put("/edit/:id", authenticator, async (req, res) => {
  let connection;
  const id = req.params.id;
  const { time, name, description, type } = req.body;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute(
      "UPDATE Information SET time=?, name=?, description=?, type=? WHERE id=?",
      [time, name, description || "", type, id]
    );
    res.status(200).json({ message: "update success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Updating fail!" });
  } finally {
    if (connection) await connection.end();
  }
});

app.delete("/delete/:id", authenticator, async (req, res) => {
  let connection;
  const id = req.params.id;

  try {
    connection = await sql.createConnection(dbConfig);
    await connection.execute("DELETE FROM Information WHERE id=?", [id]);
    res.status(200).json({ message: "delete success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Deleting fail!" });
  } finally {
    if (connection) await connection.end();
  }
});

app.post("/register", async (req, res) => {
  const { name, email, password, role, school } = req.body;

  if (!name || !email || !password || !role || !school) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  let connection;
  try {
    connection = await sql.createConnection(dbConfig);

    const [rows] = await connection.execute(
      "SELECT * FROM Registeration WHERE email=?",
      [email]
    );

    if (rows.length > 0) {
      return res.status(409).json({ message: "email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.execute(
      "INSERT INTO Registeration (name,email,password,role,school) VALUES (?,?,?,?,?)",
      [name, email, hashedPassword, role, school]
    );

    res.status(201).json({ message: "successfully registered" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "error registration" });
  } finally {
    if (connection) await connection.end();
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "email and password required" });
  }

  let connection;
  try {
    connection = await sql.createConnection(dbConfig);

    const [rows] = await connection.execute(
      "SELECT * FROM Registeration WHERE email=?",
      [email]
    );

    if (rows.length <= 0) {
      return res.status(404).json({ message: "user not found" });
    }

    const valid = await bcrypt.compare(password, rows[0].password);

    if (!valid) {
      return res.status(401).json({ message: "invalid password" });
    }

    if (!secret) {
      return res.status(500).json({ message: "Server JWT secret not configured" });
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

    return res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login fail" });
  } finally {
    if (connection) await connection.end();
  }
});

// Friendly error for CORS origin blocks
app.use((err, req, res, next) => {
  if (String(err).includes("CORS")) {
    return res.status(403).json({ message: err.message });
  }
  next(err);
});

app.listen(port, () => {
  console.log(`server is running on port ${port}`);
});
