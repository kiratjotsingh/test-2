import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createClient } from '@supabase/supabase-js';
import { Resend } from 'resend';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const CONTACT_TO = process.env.CONTACT_TO || 'hello@madebykirat.com';
const MAIL_FROM = process.env.MAIL_FROM || 'Made by Kirat <hello@madebykirat.com>';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

const configured = Boolean(
  process.env.SUPABASE_URL &&
  process.env.SUPABASE_SERVICE_ROLE_KEY &&
  process.env.RESEND_API_KEY &&
  process.env.ADMIN_PASSWORD &&
  SESSION_SECRET
);

const supabase = process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
const allowedOrigins = new Set(
  String(process.env.FRONTEND_ORIGIN || 'http://localhost:3000')
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean)
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    if (origin && allowedOrigins.has(origin)) {
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
    }
    return res.sendStatus(origin && allowedOrigins.has(origin) ? 204 : 403);
  }
  next();
});
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(express.static(__dirname, { index: 'index.html', extensions: ['html'] }));

const buckets = new Map();
function rateLimit(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  const bucket = buckets.get(key) || { start: now, count: 0 };
  if (now - bucket.start > 15 * 60 * 1000) {
    bucket.start = now;
    bucket.count = 0;
  }
  bucket.count++;
  buckets.set(key, bucket);
  if (bucket.count > 8) {
    return res.status(429).json({
      success: false,
      message: 'Too many attempts. Please try again later.'
    });
  }
  next();
}

function clean(value, max) {
  return String(value ?? '')
    .trim()
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .slice(0, max);
}

function escapeHtml(value) {
  return clean(value, 10000).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function makeSession() {
  const payload = Buffer
    .from(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000 }))
    .toString('base64url');
  return payload + '.' + sign(payload);
}

function validSession(token) {
  if (!token || !SESSION_SECRET) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || sign(payload) !== signature) return false;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now();
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const token = req.headers.cookie?.match(/(?:^|; )mbk_admin=([^;]+)/)?.[1];
  if (!validSession(token)) return res.status(401).json({ success: false });
  if (!supabase) return res.status(503).json({ success: false, message: 'Database is not configured.' });
  next();
}

function enquiryEmail({ id, name, email, service, brief }) {
  return `<div style="font-family:Arial,sans-serif;max-width:680px;color:#19261e">
    <p style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#637266">New website enquiry</p>
    <h1 style="font-weight:500">${escapeHtml(name)} is interested in ${escapeHtml(service)}.</h1>
    <hr>
    <p><strong>Name</strong><br>${escapeHtml(name)}</p>
    <p><strong>Email</strong><br><a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></p>
    <p><strong>Service</strong><br>${escapeHtml(service)}</p>
    <p><strong>Project brief</strong></p>
    <div style="white-space:pre-wrap;background:#f3f4ed;border-radius:12px;padding:18px">${escapeHtml(brief)}</div>
    <p style="color:#637266;font-size:12px">Submission ID: ${escapeHtml(id)}</p>
  </div>`;
}

function confirmationEmail({ name }) {
  return `<div style="font-family:Arial,sans-serif;max-width:680px;color:#19261e">
    <p style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#216742">Made by Kirat</p>
    <h1 style="font-weight:500">Thanks, ${escapeHtml(name)}.</h1>
    <p>We received your project enquiry and will get back to you at the email address you provided.</p>
    <p style="color:#536157">Small ideas. Big brands.</p>
  </div>`;
}

app.post('/api/contact', rateLimit, async (req, res) => {
  try {
    const name = clean(req.body.name, 100);
    const email = clean(req.body.email, 180).toLowerCase();
    const service = clean(req.body.service || 'Not sure yet', 80);
    const brief = clean(req.body.brief, 1200);
    const website = clean(req.body.website, 100);

    if (website) return res.json({ success: true });
    if (!name || !validEmail(email) || !brief) {
      return res.status(400).json({
        success: false,
        message: 'Please check your name, email address and project brief.'
      });
    }
    if (!configured || !supabase || !resend) {
      return res.status(503).json({
        success: false,
        message: 'The contact system is not configured yet. Please email hello@madebykirat.com directly.'
      });
    }

    const { data, error } = await supabase
      .from('contact_submissions')
      .insert({ name, email, service, brief })
      .select('id')
      .single();

    if (error) throw error;

    const id = data.id;
    const notification = await resend.emails.send({
      from: MAIL_FROM,
      to: [CONTACT_TO],
      replyTo: email,
      subject: `New project enquiry — ${service} — ${name}`,
      html: enquiryEmail({ id, name, email, service, brief }),
      headers: { 'X-Entity-Ref-ID': id }
    });

    if (notification.error) throw notification.error;

    const confirmation = await resend.emails.send({
      from: MAIL_FROM,
      to: [email],
      subject: 'We received your Made by Kirat enquiry',
      html: confirmationEmail({ name }),
      headers: { 'X-Entity-Ref-ID': `${id}-confirmation` }
    });

    if (confirmation.error) {
      console.error('Confirmation email failed:', confirmation.error);
    }

    await supabase
      .from('contact_submissions')
      .update({
        email_message_id: notification.data?.id || null,
        confirmation_message_id: confirmation.data?.id || null
      })
      .eq('id', id);

    return res.json({ success: true });
  } catch (error) {
    console.error('Contact submission error:', error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong while sending your enquiry. Please try again.'
    });
  }
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.post('/api/admin/login', rateLimit, (req, res) => {
  const password = String(req.body.password || '');
  const expected = String(process.env.ADMIN_PASSWORD || '');
  const matches = password.length === expected.length &&
    expected.length > 0 &&
    crypto.timingSafeEqual(Buffer.from(password), Buffer.from(expected));

  if (!matches) {
    return res.status(401).json({ success: false, message: 'Incorrect password.' });
  }

  const secure = process.env.NODE_ENV === 'production' ? ' Secure;' : '';
  res.setHeader(
    'Set-Cookie',
    `mbk_admin=${makeSession()}; HttpOnly;${secure} SameSite=Strict; Path=/; Max-Age=28800`
  );
  res.json({ success: true });
});

app.post('/api/admin/logout', (req, res) => {
  const secure = process.env.NODE_ENV === 'production' ? ' Secure;' : '';
  res.setHeader(
    'Set-Cookie',
    `mbk_admin=; HttpOnly;${secure} SameSite=Strict; Path=/; Max-Age=0`
  );
  res.json({ success: true });
});

app.get('/api/admin/submissions', requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('contact_submissions')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) {
    return res.status(500).json({
      success: false,
      message: 'Could not load submissions.'
    });
  }

  res.json({ success: true, data });
});

app.patch('/api/admin/submissions/:id', requireAdmin, async (req, res) => {
  const status = clean(req.body.status, 20);
  if (!['new', 'read', 'replied', 'archived'].includes(status)) {
    return res.status(400).json({ success: false });
  }

  const { error } = await supabase
    .from('contact_submissions')
    .update({ status })
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ success: false });
  res.json({ success: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true, configured }));

app.listen(PORT, () => {
  console.log(`Made by Kirat contact system running on http://localhost:${PORT}`);
});
