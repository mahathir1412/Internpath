const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'internpath.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'student');
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, title TEXT, description TEXT, due TEXT);
CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY, task_id INTEGER, user_id INTEGER, link TEXT,
  status TEXT DEFAULT 'Submitted', feedback TEXT, UNIQUE(task_id, user_id));
CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY, user_id INTEGER UNIQUE, issued_at TEXT);
`);

// Adds the course column to existing databases (safe to run every time)
try { db.exec("ALTER TABLE users ADD COLUMN course TEXT"); } catch (e) { }

// Seed a default admin (change these via environment variables!)
const adminEmail = process.env.ADMIN_EMAIL || 'admin@internpath.com';
if (!db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail)) {
    db.prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)')
        .run('Admin', adminEmail, bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10), 'admin');
    console.log(`Admin created: ${adminEmail} / ${process.env.ADMIN_PASSWORD || 'admin123'}  (change this!)`);
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const auth = (role) => (req, res, next) => {
    try {
        req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
        if (role && req.user.role !== role) return res.status(403).json({ error: 'Not allowed' });
        next();
    } catch { res.status(401).json({ error: 'Please log in again' }); }
};
const token = (u) => jwt.sign({ id: u.id, name: u.name, role: u.role }, SECRET, { expiresIn: '7d' });

// ---------- Auth ----------
app.post('/api/register', (req, res) => {
    const { name, email, password, course } = req.body || {};
    if (!name || !course || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 6)
        return res.status(400).json({ error: 'Enter your name, email, course and a password of 6+ characters' });
    try {
        const r = db.prepare('INSERT INTO users(name,email,password,course) VALUES(?,?,?,?)')
            .run(name.trim(), email.toLowerCase(), bcrypt.hashSync(password, 10), course);
        const u = { id: r.lastInsertRowid, name: name.trim(), role: 'student' };
        res.json({ token: token(u), user: u });
    } catch { res.status(400).json({ error: 'Email already registered' }); }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body || {};
    const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
    if (!u || !bcrypt.compareSync(password || '', u.password)) return res.status(401).json({ error: 'Wrong email or password' });
    res.json({ token: token(u), user: { id: u.id, name: u.name, role: u.role } });
});

// ---------- Tasks ----------
app.get('/api/tasks', auth(), (req, res) => {
    if (req.user.role === 'admin') {
        const tasks = db.prepare('SELECT * FROM tasks ORDER BY id').all();
        const subs = db.prepare(`SELECT s.*, u.name AS student FROM submissions s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC`).all();
        return res.json({ tasks, subs });
    }
    res.json({
        tasks: db.prepare(`SELECT t.*, s.link, s.status, s.feedback FROM tasks t
    LEFT JOIN submissions s ON s.task_id=t.id AND s.user_id=? ORDER BY t.id`).all(req.user.id)
    });
});

app.post('/api/tasks', auth('admin'), (req, res) => {
    const { title, description, due } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title is required' });
    db.prepare('INSERT INTO tasks(title,description,due) VALUES(?,?,?)').run(title, description || '', due || '');
    res.json({ ok: true });
});

app.delete('/api/tasks/:id', auth('admin'), (req, res) => {
    db.prepare('DELETE FROM submissions WHERE task_id=?').run(req.params.id);
    db.prepare('DELETE FROM tasks WHERE id=?').run(req.params.id);
    res.json({ ok: true });
});

app.post('/api/tasks/:id/submit', auth('student'), (req, res) => {
    const link = (req.body.link || '').trim();
    if (!/^https?:\/\//i.test(link)) return res.status(400).json({ error: 'Enter a valid link starting with http(s)://' });
    db.prepare(`INSERT INTO submissions(task_id,user_id,link,status) VALUES(?,?,?,'Submitted')
    ON CONFLICT(task_id,user_id) DO UPDATE SET link=excluded.link, status='Submitted', feedback=NULL WHERE status!='Approved'`)
        .run(req.params.id, req.user.id, link);
    res.json({ ok: true });
});

app.post('/api/submissions/:id/review', auth('admin'), (req, res) => {
    const { status, feedback } = req.body || {};
    if (!['Approved', 'Changes'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
    db.prepare('UPDATE submissions SET status=?, feedback=? WHERE id=?').run(status, feedback || null, req.params.id);
    res.json({ ok: true });
});

// ---------- Admin overview ----------
app.get('/api/students', auth('admin'), (req, res) => {
    const total = db.prepare('SELECT COUNT(*) c FROM tasks').get().c;
    const students = db.prepare(`SELECT u.id, u.name, u.email, u.course,
    (SELECT COUNT(*) FROM submissions s WHERE s.user_id=u.id AND s.status='Approved') AS approved,
    (SELECT COUNT(*) FROM submissions s WHERE s.user_id=u.id) AS submitted
    FROM users u WHERE u.role='student' ORDER BY u.id DESC`).all();
    res.json({ total, students });
});

// ---------- Certificates ----------
app.get('/api/certificate', auth('student'), (req, res) => {
    const total = db.prepare('SELECT COUNT(*) c FROM tasks').get().c;
    const done = db.prepare(`SELECT COUNT(*) c FROM submissions WHERE user_id=? AND status='Approved'`).get(req.user.id).c;
    if (!total || done < total) return res.status(403).json({ error: 'Complete all tasks first' });
    let c = db.prepare('SELECT * FROM certificates WHERE user_id=?').get(req.user.id);
    if (!c) {
        c = { id: 'IP-' + crypto.randomBytes(4).toString('hex').toUpperCase(), issued_at: new Date().toISOString() };
        db.prepare('INSERT INTO certificates(id,user_id,issued_at) VALUES(?,?,?)').run(c.id, req.user.id, c.issued_at);
    }
    const cu = db.prepare('SELECT course FROM users WHERE id=?').get(req.user.id);
    res.json({ id: c.id, name: req.user.name, course: cu && cu.course, issued_at: c.issued_at });
});

// Public: anyone can verify a certificate ID
app.get('/api/verify/:id', (req, res) => {
    const c = db.prepare(`SELECT c.id, c.issued_at, u.name FROM certificates c JOIN users u ON u.id=c.user_id WHERE c.id=?`)
        .get(req.params.id.toUpperCase());
    c ? res.json({ valid: true, ...c }) : res.status(404).json({ valid: false });
});

app.listen(PORT, () => console.log(`InternPath running at http://localhost:${PORT}`));