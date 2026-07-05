// VAPT Pro — Production Server (Render + Local compatible)
const http = require("http");
const fs   = require("fs");
const path = require("path");

const PORT       = process.env.PORT || 4001;
const DATA_DIR   = process.env.RENDER_DISK_PATH || __dirname;
const DB_FILE    = path.join(DATA_DIR, "db.json");
const AUDIT_FILE = path.join(DATA_DIR, "audit.txt");
const BUILD_DIR  = path.join(__dirname, "build");

function readDB() { try { return JSON.parse(fs.readFileSync(DB_FILE,"utf8")); } catch { return {}; } }
function writeDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db,null,2)); }
function readAuditLines() { try { return fs.readFileSync(AUDIT_FILE,"utf8").split("\n").filter(Boolean); } catch { return []; } }
function appendAuditLine(line) { fs.appendFileSync(AUDIT_FILE, line+"\n"); }

// Serve static files from React build
function serveStatic(res, filePath, fallback) {
  const fp = fs.existsSync(filePath) ? filePath : fallback;
  if (!fs.existsSync(fp)) { res.writeHead(404); res.end("Not found"); return; }
  const ext = path.extname(fp);
  const mime = { ".html":"text/html", ".js":"application/javascript", ".css":"text/css",
    ".json":"application/json", ".png":"image/png", ".ico":"image/x-icon",
    ".svg":"image/svg+xml", ".woff2":"font/woff2" }[ext] || "application/octet-stream";
  res.writeHead(200, { "Content-Type": mime });
  fs.createReadStream(fp).pipe(res);
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  // ── API: Audit ──────────────────────────────────────────────────────────
  if (req.url === "/api/audit" && req.method === "GET") {
    res.writeHead(200, {"Content-Type":"application/json"});
    res.end(JSON.stringify({ lines: readAuditLines() })); return;
  }
  if (req.url === "/api/audit" && req.method === "POST") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
      try { const { line } = JSON.parse(body); appendAuditLine(line); res.writeHead(200); res.end(JSON.stringify({ok:true})); }
      catch { res.writeHead(400); res.end(); }
    }); return;
  }

  // ── API: Storage ─────────────────────────────────────────────────────────
  const match = req.url.match(/^\/api\/storage\/(.+)$/);
  if (match) {
    const key = decodeURIComponent(match[1]);
    const db  = readDB();
    if (req.method === "GET") {
      res.writeHead(200,{"Content-Type":"application/json"});
      res.end(JSON.stringify({ value: db[key] ?? null })); return;
    }
    if (req.method === "POST") {
      let body = "";
      req.on("data", c => body += c);
      req.on("end", () => {
        try { const {value} = JSON.parse(body); db[key]=value; writeDB(db); res.writeHead(200); res.end(JSON.stringify({ok:true})); }
        catch { res.writeHead(400); res.end(); }
      }); return;
    }
    if (req.method === "DELETE") {
      delete db[key]; writeDB(db); res.writeHead(200); res.end(); return;
    }
  }

  // ── Static: Serve React Build ─────────────────────────────────────────
  if (req.method === "GET") {
    let filePath = path.join(BUILD_DIR, req.url === "/" ? "index.html" : req.url);
    const indexHtml = path.join(BUILD_DIR, "index.html");
    // SPA fallback — unknown routes → index.html
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = indexHtml;
    }
    serveStatic(res, filePath, indexHtml); return;
  }

  res.writeHead(405); res.end();
});

server.listen(PORT, () =>
  console.log(`✅ VAPT Pro running on port ${PORT} | data: ${DATA_DIR}`)
);
