const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

const app = express();
app.use(bodyParser.json());

const users = [];
const SECRET_KEY = "JWT_SECRET"; // from lecture notes

// Register Route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ username, password: hashedPassword });
  res.json({ message: "User registered successfully!" });
});

// Login Route (with JWT)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(404).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ username: user.username }, SECRET_KEY, {
    expiresIn: "1h",
  });

  res.json({ message: "Login Successful", token });
});

// Middleware: Verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Forbidden" });
    req.user = user;
    next();
  });
}

// Protected Route
app.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}` });
});

app.listen(3000, () => console.log("Server running on port 3000"));