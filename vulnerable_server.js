// vulnerable_server.js
// ⚠️  INTENTIONALLY VULNERABLE - FOR SNYK SCANNING / SECURITY EDUCATION ONLY
// DO NOT DEPLOY TO PRODUCTION
// Vulnerabilities: Reflected XSS, Path Traversal, Prototype Pollution risk

const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());

// ----------------------------------------------------------------
// VULN #1: Reflected XSS (CWE-79)
// Snyk will flag: "Unsanitized user input rendered as HTML"
// Fix: Escape output — use a template engine with auto-escaping,
//      or sanitize with DOMPurify / he library before rendering.
// ----------------------------------------------------------------
app.get("/greet", (req, res) => {
  const name = req.query.name;
  // Vulnerable: raw user input injected into HTML response
  res.send(`<h1>Hello, ${name}!</h1>`);
});

// ----------------------------------------------------------------
// VULN #2: Path Traversal (CWE-22)
// Snyk will flag: "Unsanitized path segment allows directory traversal"
// Fix: Resolve and validate that the final path starts with the allowed base dir:
//      const safePath = path.resolve(BASE_DIR, filename);
//      if (!safePath.startsWith(BASE_DIR)) return res.status(403).send("Forbidden");
// ----------------------------------------------------------------
const BASE_DIR = path.join(__dirname, "public");

app.get("/file", (req, res) => {
  const filename = req.query.name;
  // Vulnerable: attacker can request ../../etc/passwd etc.
  const filePath = path.join(BASE_DIR, filename);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(404).send("Not found");
    res.send(data);
  });
});

// ----------------------------------------------------------------
// VULN #3: Prototype Pollution (CWE-1321)
// Snyk will flag: "User-controlled key used to set property on object"
// Fix: Validate keys — reject "__proto__", "constructor", "prototype";
//      use Object.create(null) for data containers, or use a safe merge library.
// ----------------------------------------------------------------
app.post("/settings", (req, res) => {
  const settings = {};
  const userInput = req.body; // e.g. { "__proto__": { "isAdmin": true } }
  // Vulnerable: merging untrusted keys directly onto an object
  for (const key in userInput) {
    settings[key] = userInput[key];
  }
  res.json({ saved: true, settings });
});

app.listen(3000, () => console.log("Server running on port 3000"));
