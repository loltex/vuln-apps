// fixed_server.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const he = require("he"); // for HTML-escaping

const app = express();
app.use(express.json());

// ----------------------------------------------------------------
// FIX VULN #1: Reflected XSS (CWE-79)
// Escape user-supplied output before embedding in HTML.
// ----------------------------------------------------------------
app.get("/greet", (req, res) => {
  const name = req.query.name;
  // Escape the name to prevent HTML/JS injection
  res.send(`<h1>Hello, ${he.escape(name || "")}!</h1>`);
});

// ----------------------------------------------------------------
// FIX VULN #2: Path Traversal (CWE-22)
// Resolve and ensure the requested file stays inside BASE_DIR.
// ----------------------------------------------------------------
const BASE_DIR = path.join(__dirname, "public");

app.get("/file", (req, res) => {
  const filename = req.query.name || "";
  const safePath = path.resolve(BASE_DIR, filename);
  if (!safePath.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).send("Forbidden");
  }
  fs.readFile(safePath, "utf8", (err, data) => {
    if (err) return res.status(404).send("Not found");
    res.send(data);
  });
});

// ----------------------------------------------------------------
// FIX VULN #3: Prototype Pollution (CWE-1321)
// Reject dangerous keys and copy only own, safe properties.
// ----------------------------------------------------------------
app.post("/settings", (req, res) => {
  const settings = Object.create(null);
  const userInput = req.body || {};
  const forbidden = new Set(["__proto__", "prototype", "constructor"]);
  for (const key of Object.keys(userInput)) {
    if (forbidden.has(key)) continue;
    settings[key] = userInput[key];
  }
  res.json({ saved: true, settings });
});

app.listen(3000, () => console.log("Server running on port 3000"));
