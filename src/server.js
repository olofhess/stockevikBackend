import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { randomBytes, createHash } from 'node:crypto';

const { Pool } = pg;
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL saknas.');
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render reverse proxy
// Allow temporary blob: image URLs created by the profile-photo picker.
// Other Helmet security headers and CSP restrictions remain enabled.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      imgSrc: ["'self'", 'data:', 'blob:']
    }
  }
}));
app.use(express.json({ limit: '160kb' }));
app.use(cookieParser());
const production = process.env.NODE_ENV === 'production';
const cookieName = 'stockevik_session';
const sessionHours = 24 * 7;
const allowedOrigin = process.env.FRONTEND_ORIGIN?.replace(/\/$/, '') || '';

// Cross-origin browser access is disabled by default; optional exact allow-list later.
app.use((req, res, next) => {
  const origin = req.get('Origin');
  if (origin && allowedOrigin && origin === allowedOrigin) {
    res.set('Access-Control-Allow-Origin', allowedOrigin);
    res.set('Access-Control-Allow-Credentials', 'true');
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  }
  if (req.method === 'OPTIONS') return origin && origin === allowedOrigin ? res.sendStatus(204) : res.sendStatus(403);
  // Protect cookie-authenticated writes from cross-site requests.
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && origin) {
    const myOrigin = `${req.protocol}://${req.get('host')}`;
    if (origin !== myOrigin && (!allowedOrigin || origin !== allowedOrigin)) {
      return res.status(403).json({ error: 'OtillÃ¥tet ursprung.' });
    }
  }
  next();
});

const loginLimiter = rateLimit({windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false});
const writeLimiter = rateLimit({windowMs: 60 * 1000, limit: 25, standardHeaders: 'draft-7', legacyHeaders: false});
const hashToken = token => createHash('sha256').update(token).digest('hex');
const publicMember = m => ({id: m.id, name: m.name, house: m.house, username: m.username, avatarVersion: m.avatar_updated_at ? new Date(m.avatar_updated_at).getTime() : null});
const selfMember = m => ({...publicMember(m), role: m.role, email: m.email});
const registrationLimiter = rateLimit({windowMs:15*60*1000,limit:5,standardHeaders:'draft-7',legacyHeaders:false});
const safeText = (t, max) => typeof t === 'string' && t.trim().length > 0 && t.trim().length <= max ? t.trim() : null;

async function initialize() {
  await pool.query(`
  CREATE TABLE IF NOT EXISTS members (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    house TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')),
    role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member','admin')),
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash CHAR(64) PRIMARY KEY,
    member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS posts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    member_id BIGINT NOT NULL REFERENCES members(id),
    body TEXT NOT NULL CHECK(char_length(body) BETWEEN 1 AND 5000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS posts_created ON posts(created_at DESC);
  CREATE TABLE IF NOT EXISTS comments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    member_id BIGINT NOT NULL REFERENCES members(id),
    body TEXT NOT NULL CHECK(char_length(body) BETWEEN 1 AND 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS comments_post ON comments(post_id, created_at);
  `);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS avatar_data BYTEA;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS avatar_updated_at TIMESTAMPTZ;`);
  // Safe migration from v0.6. Existing members, posts and comments are retained.
  await pool.query(`ALTER TABLE members DROP CONSTRAINT IF EXISTS members_status_check;
    ALTER TABLE members ADD CONSTRAINT members_status_check CHECK (status IN ('active','inactive','pending'));`);
}

async function seedOnlyForDemo() {
  if (process.env.SEED_DEMO !== 'true') return;
  const credentials = [
    ['Kalle', 'Kalles Stuga', 'kalle@stockevik.test', process.env.KALLE_PASSWORD],
    ['Olle', 'Olles Stuga', 'olle@stockevik.test', process.env.OLLE_PASSWORD],
    ['Johan', 'Johans Stuga', 'johan@stockevik.test', process.env.JOHAN_PASSWORD]
  ];
  if (credentials.some(x => !x[3] || x[3].length < 12)) {
    throw new Error('SEED_DEMO requires three independent passwords of at least 12 characters.');
  }
  for (const [name, house, email, password] of credentials) {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(`INSERT INTO members (name, house, username, email, password_hash)
      VALUES ($1,$2,$3,$4,$5) ON CONFLICT (email) DO NOTHING`, [name, house, name.toLowerCase(), email, hash]);
  }
  console.log('Demo accounts checked (existing accounts left unchanged).');
}

// One-time administrator-triggered repair of the existing Kalle demo account.
// Enable RESET_KALLE_PASSWORD=true in Render for one deploy, then remove it.
async function resetKallePasswordOnce() {
  if (process.env.RESET_KALLE_PASSWORD !== 'true') return;
  const password = process.env.KALLE_PASSWORD;
  if (!password || password.length < 12) {
    throw new Error('RESET_KALLE_PASSWORD requires KALLE_PASSWORD of at least 12 characters.');
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const {rows} = await client.query(`UPDATE members
      SET password_hash=$1, status='active'
      WHERE email=$2 RETURNING id`, [passwordHash, 'kalle@stockevik.test']);
    if (rows.length !== 1) throw new Error('Kalle demo account not found: reset aborted.');
    await client.query('DELETE FROM sessions WHERE member_id=$1', [rows[0].id]);
    await client.query('COMMIT');
    console.log('Kalle demo password reset; existing Kalle sessions cleared.');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function authenticate(req, res, next) {
  const token = req.cookies[cookieName];
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return res.status(401).json({error: 'Logga in fÃ¶rst.'});
  try {
    const {rows} = await pool.query(`SELECT m.id, m.name, m.house, m.username, m.status, m.role, m.email, m.avatar_updated_at FROM sessions s
       JOIN members m ON m.id=s.member_id WHERE s.token_hash=$1 AND s.expires_at > now()`, [hashToken(token)]);
    if (!rows.length || rows[0].status !== 'active') return res.status(401).json({error:'Sessionen har gÃ¥tt ut.'});
    req.member = rows[0];
    next();
  } catch (err) { next(err); }
}

app.get('/api/health', async (_req, res, next) => {
  try {await pool.query('SELECT 1'); res.json({ok:true, app:'Det hÃ¤nder i Stockevik', version:'backend-1.0'});}
  catch(err){next(err);}
});

app.post('/api/login', loginLimiter, async (req, res, next) => {
  try {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!email || password.length > 2000) return res.status(400).json({error:'Ange e-post och lÃ¶senord.'});
    const {rows} = await pool.query('SELECT * FROM members WHERE email=$1 AND status=$2', [email, 'active']);
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
      return res.status(401).json({error:'Fel e-post eller lÃ¶senord.'});
    }
    const token = randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions(token_hash,member_id,expires_at) VALUES ($1,$2,now() + interval \'7 days\')',[hashToken(token), rows[0].id]);
    res.cookie(cookieName, token, {httpOnly:true, secure:production, sameSite:'lax', maxAge:sessionHours*3600*1000, path:'/'});
    res.json({member:selfMember(rows[0])});
  } catch(err){next(err);}
});

app.post('/api/logout', async (req, res, next) => {
  try {
    const token = req.cookies[cookieName];
    if (token && /^[0-9a-f]{64}$/.test(token)) await pool.query('DELETE FROM sessions WHERE token_hash=$1',[hashToken(token)]);
    res.clearCookie(cookieName, {httpOnly:true, secure:production, sameSite:'lax', path:'/'});
    res.json({ok:true});
  } catch(err){next(err);}
});

app.get('/api/me', authenticate, (req, res) => res.json({member:selfMember(req.member)}));


// Profile edits are limited to the authenticated account.
app.put('/api/me/profile', authenticate, writeLimiter, async (req,res,next) => {
  try {
    const name = safeText(req.body?.name,100);
    const house = safeText(req.body?.house,100);
    if (!name || !house) return res.status(400).json({error:'Ange namn och fastighet.'});
    const {rows} = await pool.query(`UPDATE members SET name=$1,house=$2 WHERE id=$3
      RETURNING id,name,house,username,email,role,avatar_updated_at`,[name,house,req.member.id]);
    res.json({member:selfMember(rows[0])});
  } catch(err) { next(err); }
});

app.put('/api/me/password', authenticate, writeLimiter, async (req,res,next) => {
  try {
    const oldPassword = req.body?.oldPassword;
    const newPassword = req.body?.newPassword;
    if (typeof oldPassword !== 'string' || typeof newPassword !== 'string' ||
        oldPassword.length > 2000 || newPassword.length < 8 || newPassword.length > 200) {
      return res.status(400).json({error:'Ange nuvarande lösenord och ett nytt med minst 8 tecken.'});
    }
    const {rows} = await pool.query('SELECT password_hash FROM members WHERE id=$1',[req.member.id]);
    if (!rows.length || !(await bcrypt.compare(oldPassword, rows[0].password_hash))) {
      return res.status(403).json({error:'Nuvarande lösenord är fel.'});
    }
    const passwordHash = await bcrypt.hash(newPassword,12);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE members SET password_hash=$1 WHERE id=$2',[passwordHash,req.member.id]);
      // Keep only this browser's current session; sign out other devices.
      await client.query('DELETE FROM sessions WHERE member_id=$1 AND token_hash<>$2',
        [req.member.id,hashToken(req.cookies[cookieName])]);
      await client.query('COMMIT');
      res.json({ok:true});
    } catch(error) { await client.query('ROLLBACK'); throw error; }
    finally {client.release();}
  } catch(err) { next(err); }
});

// Small, compressed profile pictures are stored inside PostgreSQL, not on Render's ephemeral disk.
// Only approved signed-in members may view pictures. Only the owner may change theirs.
app.get('/api/avatars/:id', authenticate, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.sendStatus(404);
    const {rows} = await pool.query(`SELECT avatar_data FROM members WHERE id=$1 AND status='active'`, [req.params.id]);
    if (!rows.length || !rows[0].avatar_data) return res.sendStatus(404);
    res.set('Content-Type', 'image/jpeg');
    res.set('Cache-Control', 'private, no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    res.send(rows[0].avatar_data);
  } catch(err) { next(err); }
});

app.put('/api/me/avatar', authenticate, writeLimiter, async (req, res, next) => {
  try {
    const encoded = req.body?.jpegBase64;
    if (typeof encoded !== 'string' || encoded.length > 140000 || encoded.length < 50 ||
        !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
      return res.status(400).json({error:'Bilden kunde inte läsas. Välj en JPEG-bild.'});
    }
    const data = Buffer.from(encoded, 'base64');
    if (data.length > 100000 || data.length < 100 || data[0] !== 0xff || data[1] !== 0xd8 ||
        data[data.length-2] !== 0xff || data[data.length-1] !== 0xd9) {
      return res.status(400).json({error:'Profilbilden måste vara en JPEG på högst 100 kB.'});
    }
    const {rows} = await pool.query(`UPDATE members SET avatar_data=$1,avatar_updated_at=now()
      WHERE id=$2 RETURNING avatar_updated_at`, [data, req.member.id]);
    res.json({ok:true, avatarVersion:new Date(rows[0].avatar_updated_at).getTime()});
  } catch(err) { next(err); }
});

app.delete('/api/me/avatar', authenticate, writeLimiter, async (req,res,next) => {
  try {
    await pool.query('UPDATE members SET avatar_data=NULL,avatar_updated_at=NULL WHERE id=$1',[req.member.id]);
    res.json({ok:true});
  } catch(err) { next(err); }
});

app.get('/api/posts', authenticate, async (_req, res, next) => {
  try {
    const {rows} = await pool.query(`SELECT p.id, p.body, p.created_at, m.name AS author, m.id AS author_id, m.avatar_updated_at AS author_avatar_version,
      COALESCE((SELECT json_agg(json_build_object('id',c.id,'text',c.body,'date',c.created_at,'author',cm.name,'authorId',cm.id,'avatarVersion',cm.avatar_updated_at) ORDER BY c.created_at,c.id)
      FROM comments c JOIN members cm ON cm.id=c.member_id WHERE c.post_id=p.id),'[]'::json) AS comments
      FROM posts p JOIN members m ON m.id=p.member_id ORDER BY p.created_at DESC,p.id DESC LIMIT 100`);
    res.json({posts:rows.map(p=>({id:p.id, text:p.body, date:p.created_at, author:p.author, authorId:p.author_id, avatarVersion:p.author_avatar_version ? new Date(p.author_avatar_version).getTime() : null, comments:p.comments}))});
  } catch(err){next(err);}
});

app.post('/api/posts', authenticate, writeLimiter, async (req, res, next) => {
  try {
    const body = safeText(req.body?.text, 5000);
    if (!body) return res.status(400).json({error:'InlÃ¤gget mÃ¥ste innehÃ¥lla 1â€“5000 tecken.'});
    const {rows} = await pool.query('INSERT INTO posts(member_id,body) VALUES ($1,$2) RETURNING id,created_at',[req.member.id,body]);
    res.status(201).json({post:{id:rows[0].id, text:body, author:req.member.name, authorId:req.member.id, avatarVersion:req.member.avatar_updated_at ? new Date(req.member.avatar_updated_at).getTime() : null, date:rows[0].created_at, comments:[]}});
  } catch(err){next(err);}
});

// Only the author can edit a post. Authentication and ownership are checked in PostgreSQL.
app.put('/api/posts/:id', authenticate, writeLimiter, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({error:'Ogiltigt inläggs-ID.'});
    const body = safeText(req.body?.text, 5000);
    if (!body) return res.status(400).json({error:'Inlägget måste innehålla 1–5000 tecken.'});
    const {rows} = await pool.query(
      'UPDATE posts SET body=$1 WHERE id=$2 AND member_id=$3 RETURNING id',
      [body, req.params.id, req.member.id]
    );
    if (!rows.length) {
      const found = await pool.query('SELECT 1 FROM posts WHERE id=$1', [req.params.id]);
      return res.status(found.rowCount ? 403 : 404).json({
        error: found.rowCount ? 'Du kan bara redigera dina egna inlägg.' : 'Inlägget saknas.'
      });
    }
    res.json({ok:true});
  } catch (err) { next(err); }
});

// Deleting a post also deletes its comments (comments.post_id ON DELETE CASCADE).
// Only the author can delete the post, verified against the logged-in member on the server.
app.delete('/api/posts/:id', authenticate, writeLimiter, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({error:'Ogiltigt inläggs-ID.'});
    const deleted = await pool.query(
      'DELETE FROM posts WHERE id=$1 AND member_id=$2 RETURNING id',
      [req.params.id, req.member.id]
    );
    if (!deleted.rowCount) {
      const found = await pool.query('SELECT 1 FROM posts WHERE id=$1', [req.params.id]);
      return res.status(found.rowCount ? 403 : 404).json({
        error: found.rowCount ? 'Du kan bara ta bort dina egna inlägg.' : 'Inlägget saknas.'
      });
    }
    res.json({ok:true});
  } catch(err) { next(err); }
});

app.post('/api/posts/:id/comments', authenticate, writeLimiter, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({error:'Ogiltigt inlÃ¤ggs-ID.'});
    const body=safeText(req.body?.text,2000);
    if (!body) return res.status(400).json({error:'Kommentaren mÃ¥ste innehÃ¥lla 1â€“2000 tecken.'});
    const {rows}=await pool.query(`INSERT INTO comments(post_id,member_id,body)
      SELECT id,$2,$3 FROM posts WHERE id=$1 RETURNING id,created_at`,[req.params.id,req.member.id,body]);
    if (!rows.length) return res.status(404).json({error:'InlÃ¤gget saknas.'});
    res.status(201).json({comment:{id:rows[0].id, text:body, author:req.member.name, authorId:req.member.id, avatarVersion:req.member.avatar_updated_at ? new Date(req.member.avatar_updated_at).getTime() : null, date:rows[0].created_at}});
  } catch(err){next(err);}
});

// No public member directory. Never send email, phone or password hashes to other members.
app.get('/api/members', authenticate, async (req, res, next) => {
  try {
    const {rows}=await pool.query('SELECT id,name,house,username,avatar_updated_at FROM members WHERE status=$1 ORDER BY name',['active']);
    res.json({members:rows.map(publicMember)});
  } catch(err){next(err);}
});


// Requests are public; approval is always a separate administrator action.
app.post('/api/register', registrationLimiter, async (req,res,next) => {
  try {
    const name = safeText(req.body?.name,100);
    const house = safeText(req.body?.house,100);
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!name || !house || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 180 || password.length < 8 || password.length > 200) {
      return res.status(400).json({error:'Ange namn, fastighet, giltig e-post och lÃ¶senord med minst 8 tecken.'});
    }
    // A server-generated internal username is never used as a credential.
    const username = 'medlem_' + randomBytes(12).toString('hex');
    const hash = await bcrypt.hash(password,12);
    await pool.query(`INSERT INTO members(name,house,username,email,password_hash,status,role)
      VALUES($1,$2,$3,$4,$5,'pending','member') ON CONFLICT(email) DO NOTHING`,
      [name,house,username,email,hash]);
    res.status(202).json({message:'Din ansÃ¶kan Ã¤r mottagen. Du kan logga in nÃ¤r en administratÃ¶r har godkÃ¤nt den.'});
  } catch(err){next(err);}
});

function requireAdmin(req,res,next) {
  if (req.member.role !== 'admin') return res.status(403).json({error:'Endast administratÃ¶ren har tillgÃ¥ng.'});
  next();
}
app.get('/api/admin/applications', authenticate, requireAdmin, async (_req,res,next) => {
  try {
    const {rows} = await pool.query(`SELECT id,name,house,email,joined_at FROM members
       WHERE status='pending' ORDER BY joined_at ASC,id ASC`);
    res.json({applications:rows});
  } catch(err){next(err);}
});
app.post('/api/admin/applications/:id/decision', authenticate, requireAdmin, writeLimiter, async (req,res,next) => {
  try {
    if (!/^\d+$/.test(req.params.id) || !['approve','reject'].includes(req.body?.decision))
      return res.status(400).json({error:'Ogiltigt beslut.'});
    const status = req.body.decision === 'approve' ? 'active' : 'inactive';
    const {rows} = await pool.query(`UPDATE members SET status=$2 WHERE id=$1 AND status='pending'
      RETURNING id`, [req.params.id,status]);
    if (!rows.length) return res.status(404).json({error:'AnsÃ¶kan hittades inte eller Ã¤r redan behandlad.'});
    res.json({ok:true});
  } catch(err){next(err);}
});

// Frontend and API share one origin, so the secure session cookie works in browsers.
app.use(express.static('public'));
app.use((req,res)=>res.status(404).json({error:'OkÃ¤nd adress.'}));
app.use((err,req,res,next)=>{
  console.error('API error:', err);
  res.status(500).json({error:'Ett serverfel uppstod.'});
});

try {
  await initialize();
  await seedOnlyForDemo();
  await resetKallePasswordOnce();
  // Explicit administrator assignment: set ADMIN_EMAIL to an existing account in Render.
  const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  if (adminEmail) {
    const result = await pool.query(`UPDATE members SET role='admin' WHERE email=$1 AND status='active' RETURNING id`,[adminEmail]);
    if (!result.rowCount) console.warn('ADMIN_EMAIL does not match an active member.');
  }
  const port=Number(process.env.PORT || 10000);
  app.listen(port,'0.0.0.0',()=>console.log(`Stockevik backend listening on ${port}`));
} catch(err){console.error('Startup failed:',err);process.exit(1);}