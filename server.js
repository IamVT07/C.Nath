require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  }),
});
const db = admin.firestore();
const app = express();

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.warn('Blocked CORS request from origin:', origin);
    return callback(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json());

const writeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }); // 10 reviews / 15 min / IP

// Simple admin check: frontend sends the admin password in a header, we compare to .env
function requireAdmin(req, res, next) {
  if (!process.env.ADMIN_PASSWORD) {
    return res.status(500).json({ error: 'Admin password not set on server' });
  }
  if (req.headers['x-admin-token'] !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ---------- PUBLIC ----------

// GET /api/reviews -> only APPROVED reviews, for the public site
app.get('/api/reviews', async (req, res) => {
  try {
    const snap = await db.collection('reviews').orderBy('createdAt', 'desc').limit(50).get();
    const reviews = snap.docs
      .map(d => ({ id: d.id, ...d.data() }))
      .filter(r => r.status === 'approved')
      .slice(0, 20)
      .map(r => ({
        name: r.name, area: r.area || '', rating: r.rating, text: r.text,
        createdAt: r.createdAt ? r.createdAt.toDate().toISOString() : null
      }));
    res.json(reviews);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load reviews' });
  }
});

// POST /api/reviews -> new review always starts as "pending"
app.post('/api/reviews', writeLimiter, async (req, res) => {
  const { name, area, text, rating } = req.body || {};
  if (typeof name !== 'string' || !name.trim() || name.length > 60) return res.status(400).json({ error: 'Invalid name' });
  if (typeof text !== 'string' || !text.trim() || text.length > 500) return res.status(400).json({ error: 'Invalid review text' });
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: 'Invalid rating' });

  try {
    await db.collection('reviews').add({
      name: name.trim(), area: (area || '').trim().slice(0, 60), text: text.trim(), rating,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not submit review' });
  }
});

// ---------- ADMIN (password protected) ----------

// GET /api/admin/reviews -> ALL reviews, any status
app.get('/api/admin/reviews', requireAdmin, async (req, res) => {
  try {
    const snap = await db.collection('reviews').orderBy('createdAt', 'desc').limit(100).get();
    const reviews = snap.docs.map(d => {
      const r = d.data();
      return {
        id: d.id, name: r.name, area: r.area || '', rating: r.rating, text: r.text,
        status: r.status || 'pending',
        createdAt: r.createdAt ? r.createdAt.toDate().toISOString() : null
      };
    });
    res.json(reviews);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load reviews' });
  }
});

app.post('/api/admin/reviews/:id/approve', requireAdmin, async (req, res) => {
  try {
    await db.collection('reviews').doc(req.params.id).update({ status: 'approved' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not approve review' });
  }
});

app.post('/api/admin/reviews/:id/reject', requireAdmin, async (req, res) => {
  try {
    await db.collection('reviews').doc(req.params.id).update({ status: 'rejected' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not reject review' });
  }
});

app.delete('/api/admin/reviews/:id', requireAdmin, async (req, res) => {
  try {
    await db.collection('reviews').doc(req.params.id).delete();
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not delete review' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`API running on :${PORT}`));

module.exports = app;
