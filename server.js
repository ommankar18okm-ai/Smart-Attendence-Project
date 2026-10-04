// Smart Attendance - backend (Express + SQLite). Data is saved in attendance.db
const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');

const db = new DatabaseSync(process.env.DB_PATH || 'attendance.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, hash TEXT, salt TEXT);
CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, roll TEXT UNIQUE NOT NULL, name TEXT NOT NULL, class TEXT);
CREATE TABLE IF NOT EXISTS attendance(student_id INTEGER, date TEXT, status TEXT CHECK(status IN('P','A')),
  PRIMARY KEY(student_id,date), FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
`);
db.exec('PRAGMA foreign_keys = ON');
for (const col of ['hash', 'salt']) { try { db.exec(`ALTER TABLE students ADD COLUMN ${col} TEXT`); } catch {} }

const salty = () => crypto.randomBytes(8).toString('hex');
const hash = (p, s) => crypto.scryptSync(p, s, 32).toString('hex');
const setStuPass = (id, pass) => { const s = salty(); db.prepare('UPDATE students SET hash=?,salt=? WHERE id=?').run(hash(pass, s), s, id); };
if (!db.prepare('SELECT 1 FROM users').get()) {
  const s = salty(); db.prepare('INSERT INTO users(username,hash,salt) VALUES(?,?,?)').run('admin', hash(process.env.ADMIN_PASSWORD || 'admin123', s), s);
}
// students without a password get their roll number as the first password
db.prepare('SELECT id,roll FROM students WHERE hash IS NULL').all().forEach(s => setStuPass(s.id, s.roll));

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));
const tokens = new Map();   // token -> {role, id}
const codes = new Map();    // QR code -> {date, exp}

app.post('/api/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  let sess = null;
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (u && hash(password, u.salt) === u.hash) sess = { role: 'admin', id: u.id };
  else {
    const s = db.prepare('SELECT * FROM students WHERE roll=?').get(username);
    if (s && hash(password, s.salt) === s.hash) sess = { role: 'student', id: s.id };
  }
  if (!sess) return res.status(401).json({ error: 'Wrong username or password' });
  const t = crypto.randomBytes(24).toString('hex'); tokens.set(t, sess);
  res.json({ token: t, role: sess.role });
});

const getBrand = () => { const r = db.prepare("SELECT v FROM settings WHERE k='brand'").get(); return r ? JSON.parse(r.v) : {}; };
app.get('/api/brand', (_, res) => res.json(getBrand()));   // public: login page needs the logo and name

app.use('/api', (req, res, next) => {
  req.s = tokens.get((req.headers.authorization || '').replace('Bearer ', ''));
  req.s ? next() : res.status(401).json({ error: 'Please log in' });
});

// ---- routes for both teacher and student ----
app.post('/api/password', (req, res) => {
  const { old = '', new: nw = '' } = req.body;
  if (nw.length < 6) return res.status(400).json({ error: 'New password must be 6+ characters' });
  const table = req.s.role === 'admin' ? 'users' : 'students';
  const row = db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(req.s.id);
  if (hash(old, row.salt) !== row.hash) return res.status(400).json({ error: 'Old password is wrong' });
  const s = salty(); db.prepare(`UPDATE ${table} SET hash=?,salt=? WHERE id=?`).run(hash(nw, s), s, req.s.id);
  res.json({ ok: true });
});

// ---- student routes ----
app.get('/api/me', (req, res) => {
  if (req.s.role !== 'student') return res.status(403).json({ error: 'Students only' });
  const st = db.prepare('SELECT roll,name FROM students WHERE id=?').get(req.s.id);
  const days = db.prepare('SELECT date,status FROM attendance WHERE student_id=? ORDER BY date DESC').all(req.s.id);
  const present = days.filter(d => d.status === 'P').length;
  res.json({ ...st, days, present, total: days.length, pct: days.length ? Math.round(1000 * present / days.length) / 10 : 0 });
});
app.post('/api/checkin', (req, res) => {
  if (req.s.role !== 'student') return res.status(403).json({ error: 'Students only' });
  const c = codes.get(req.body.code);
  if (!c || c.exp < Date.now()) return res.status(400).json({ error: 'This QR code has expired' });
  db.prepare("INSERT INTO attendance(student_id,date,status) VALUES(?,?,'P') ON CONFLICT(student_id,date) DO UPDATE SET status='P'")    .run(req.s.id, c.date);
  const st = db.prepare('SELECT roll,name FROM students WHERE id=?').get(req.s.id);
  if (!c.list.find(x => x.roll === st.roll)) c.list.push({ roll: st.roll, name: st.name, time: new Date().toLocaleTimeString() });
  res.json({ ok: true });
});

// ---- teacher-only routes below ----
app.use('/api', (req, res, next) => req.s.role === 'admin' ? next() : res.status(403).json({ error: 'Teachers only' }));

app.post('/api/brand', (req, res) => {
  const { name = '', logo = '', c1 = '', c2 = '' } = req.body, ok = c => /^#[0-9a-f]{6}$/i.test(c);
  if (name.length > 60 || (logo && (!logo.startsWith('data:image/') || logo.length > 300000))) return res.status(400).json({ error: 'Invalid name or logo' });
  const b = { name: name.trim(), logo, c1: ok(c1) ? c1 : '', c2: ok(c2) ? c2 : '' };
  db.prepare("INSERT INTO settings(k,v) VALUES('brand',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify(b));
  res.json({ ok: true });
});

app.get('/api/students', (_, res) => res.json(db.prepare('SELECT id,roll,name,class FROM students ORDER BY roll').all()));
app.post('/api/students', (req, res) => {
  const { roll, name, class: cls } = req.body;
  if (!roll || !name) return res.status(400).json({ error: 'Roll no and name are required' });
  try {
    const r = db.prepare('INSERT INTO students(roll,name,class) VALUES(?,?,?)').run(roll.trim(), name.trim(), (cls || '').trim());
    setStuPass(r.lastInsertRowid, roll.trim()); res.json({ ok: true });
  } catch { res.status(409).json({ error: 'This roll number already exists' }); }
});
app.delete('/api/students/:id', (req, res) => { db.prepare('DELETE FROM students WHERE id=?').run(req.params.id); res.json({ ok: true }); });

app.get('/api/attendance', (req, res) => {
  const rows = db.prepare('SELECT student_id,status FROM attendance WHERE date=?').all(req.query.date);
  res.json(Object.fromEntries(rows.map(r => [r.student_id, r.status])));
});
app.post('/api/attendance', (req, res) => {
  const { date, records } = req.body;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date || '')) return res.status(400).json({ error: 'Invalid date' });
  const up = db.prepare('INSERT INTO attendance(student_id,date,status) VALUES(?,?,?) ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status');
  db.exec('BEGIN');
  try { records.forEach(r => up.run(r.student_id, date, r.status === 'P' ? 'P' : 'A')); db.exec('COMMIT'); }
  catch (e) { db.exec('ROLLBACK'); return res.status(500).json({ error: 'Could not save' }); }
  res.json({ ok: true });
});

app.post('/api/qr/start', (req, res) => {
  const date = req.body.date;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date || '')) return res.status(400).json({ error: 'Invalid date' });
  const code = crypto.randomBytes(4).toString('hex');
  codes.set(code, { date, exp: Date.now() + 10 * 60000, list: [] });
  res.json({ code });
});

app.get('/api/qr/status', (req, res) => {
  const c = codes.get(req.query.code);
  if (!c) return res.status(404).json({ error: 'Unknown code' });
  res.json({ list: c.list, total: db.prepare('SELECT COUNT(*) n FROM students').get().n, left: Math.max(0, Math.round((c.exp - Date.now()) / 1000)) });
});

app.get('/api/chart', (_, res) => res.json({
  daily: db.prepare("SELECT date, ROUND(100.0*SUM(status='P')/COUNT(*),0) AS pct FROM attendance GROUP BY date ORDER BY date DESC LIMIT 14").all(),
  monthly: db.prepare("SELECT substr(date,1,7) AS m, ROUND(100.0*SUM(status='P')/COUNT(*),0) AS pct FROM attendance GROUP BY m ORDER BY m").all()
}));

const report = () => db.prepare(`
  SELECT s.id, s.roll, s.name, s.class,
    COALESCE(SUM(a.status='P'),0) AS present, COUNT(a.date) AS total,
    CASE WHEN COUNT(a.date)=0 THEN 0 ELSE ROUND(100.0*SUM(a.status='P')/COUNT(a.date),1) END AS pct
  FROM students s LEFT JOIN attendance a ON a.student_id=s.id GROUP BY s.id ORDER BY s.roll`).all();
app.get('/api/report', (_, res) => res.json(report()));
app.get('/api/export', (_, res) => {
  const csv = ['Roll,Name,Class,Present,Total,Percent', ...report().map(r => [r.roll, `"${r.name}"`, r.class, r.present, r.total, r.pct].join(','))].join('\n');
  res.set({ 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=attendance.csv' }).send(csv);
});

// Optional demo data for online hosting (set DEMO_SEED=1). Only runs when there are no students.
if (process.env.DEMO_SEED === '1' && !db.prepare('SELECT 1 FROM students').get()) {
  const names = ['Aarav Sharma','Diya Patel','Rohan Mehta','Sneha Kulkarni','Kabir Singh','Ananya Iyer','Vihaan Joshi','Isha Desai','Arjun Nair','Meera Rao'];
  names.forEach((n, i) => { const r = db.prepare('INSERT INTO students(roll,name,class) VALUES(?,?,?)').run(String(i + 1), n, '10A'); setStuPass(r.lastInsertRowid, String(i + 1)); });
  const ins = db.prepare('INSERT INTO attendance VALUES(?,?,?)');
  for (let d = 1; d <= 24; d++) {
    const dt = new Date(Date.now() - d * 864e5); if ([0, 6].includes(dt.getDay())) continue;
    for (let s = 1; s <= 10; s++) ins.run(s, dt.toISOString().slice(0, 10), (s * 7 + d * 3) % (s > 8 ? 3 : 9) === 0 ? 'A' : 'P');
  }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Running at http://localhost:' + PORT + '  (teacher login: admin / admin123, student login: roll no / roll no)'));
