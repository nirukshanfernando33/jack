import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cors from "cors";
import pkg from "pg";
import { Counter, Registry, collectDefaultMetrics } from "prom-client";
import { Parser } from "json2csv";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const { Pool } = pkg;

// ─────────── SECURITY ───────────
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: false }));

// ─────────── DATABASE ───────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

await pool.query(`
  CREATE TABLE IF NOT EXISTS clicks (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMPTZ DEFAULT now(),
    slug TEXT,
    dest TEXT,
    ip TEXT,
    ua TEXT
  );
`);

// ─────────── METRICS ───────────
const register = new Registry();
collectDefaultMetrics({ register });

const clicksTotal = new Counter({
  name: "clicks_total",
  help: "Total redirects",
  labelNames: ["slug"],
});
register.registerMetric(clicksTotal);

// ─────────── RATE LIMIT ───────────
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/go", limiter);

// ─────────── REDIRECT ───────────
app.get("/go/:slug", async (req, res) => {
  const { slug } = req.params;
  const rawDest = req.query.dest || "https://example.com";
  const ip = req.headers["x-forwarded-for"] || req.ip;
  const ua = req.get("user-agent") || "";

  try {
    await pool.query("INSERT INTO clicks(slug, dest, ip, ua) VALUES ($1,$2,$3,$4)", [
      slug,
      rawDest,
      ip,
      ua,
    ]);
  } catch (e) {
    console.error("DB insert failed:", e.message);
  }

  clicksTotal.inc({ slug });
  res.redirect(302, rawDest);
});

// ─────────── ADMIN ───────────
function adminOK(req) {
  return req.get("x-admin-pass") === process.env.FOB_ADMIN_PASS;
}

app.get("/admin/last", async (req, res) => {
  if (!adminOK(req)) return res.status(403).send("forbidden");
  const { rows } = await pool.query(
    "SELECT ts, slug, dest FROM clicks ORDER BY id DESC LIMIT 5"
  );
  res.json(rows);
});

app.get("/metrics", async (_req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

app.get("/status", async (_req, res) => {
  const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM clicks");
  res.json({ ok: true, ts: new Date().toISOString(), clicks: rows[0].c });
});

// ─────────── STARTUP ───────────
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`🚀 Tiny FOB v2 running on ${port}`));