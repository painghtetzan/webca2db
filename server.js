const express = require("express");
const sql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

// Render provides PORT
const port = process.env.PORT || 5000;

// JWT Secret
const secret = process.env.JWT;
if (!secret) {
  console.error("❌ Missing JWT secret (process.env.JWT)");
}

// MySQL config
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

// ================== CORS ==================
app.use(
  cors({
    origin: (origin, cb) => {
      const allowed = [
        "http://localhost:3000",
        "https://educationreminder.netlify.app",
        "https://www.educationreminder.netlify.app",
      ];

      // allow requests without origin (Postman, server-to-server)
      if (!origin) return cb(null, true);

      // allow Netlify preview deploy URLs
      if (allowed.includes(origin) || origin.endsWith(".netlify.app")) {
        return cb(null, true);
      }

      return cb(new Error("Not allowed by CORS: " + origin));
    },
    credentials: false, // using Bearer token (not cookies)
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Preflight
app.options("*", cors());

// ================== HEALTH CHECK ==================
app.get("/", (req, res) => {
  res.json({ ok: true, message: "API is running" });
});

// ================== AUTH MIDDLEWARE ==================
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

// ================== ROUTES ==================

// Get all activities for user's school
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

// Add activity
app.post("/add", authenticator, async (req, res) => {
  let connection;

  const { type, time, name, description } = req.body;
  const { userId, userSchool } = req.user;

  try {
    connection = await sql.createConnection(dbConfig);

    await connection.execute(
      "INSERT INTO Information (time,name,createdBy_id,school,description,type) VALUES (?,?,?,?,?,?)",
      [time, name, userId, userSchool, description || "", type]
    );

    res.status(201).json({ message: "Successfully created" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error creating new item" });
  } finally {
    if (connection) await connection.end();
  }
});

// Update activity
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

    res.status(200).json({ message: "Update success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Updating failed" });
  } finally {
    if (connection) await connection.end();
  }
});

// Delete activity
app.delete("/delete/:id", authenticator, async (req, res) => {
  let connection;
  const id = req.params.id;

  try {
    connection = await sql.createConnection(dbConfig);

    await connection.execute("DELETE FROM Information WHERE id=?", [id]);

    res.status(200).json({ message: "Delete success" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Deleting failed" });
  } finally {
    if (connection) await connection.end();
  }
});

// Register
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
    console.error(err);
    res.status(500).json({ message: "Error registration" });
  } finally {
    if (connection) await connection.end();
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let connection;

  try {
    connection = await sql.createConnection(dbConfig);

    const [rows] = await connection.execute(
      "SELECT * FROM Registeration WHERE email=?",
      [email]
    );

    if (rows.length <= 0) {
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

    return res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  } finally {
    if (connection) await connection.end();
  }
});

// ================== START SERVER ==================
app.listen(port, () => {
  console.log(`✅ Server is running on port ${port}`);
});
