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
app.use(express.json({ limit: '550kb' }));
app.use(cookieParser());
const production = process.env.NODE_ENV === 'production';
const cookieName = 'lillachatten_session';
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
      return res.status(403).json({ error: 'Otillåtet ursprung.' });
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
// Accept only small, genuine-looking JPEG data produced by our browser image compressor.
function postImageBuffer(encoded) {
  if (encoded === undefined || encoded === null) return null;
  if (typeof encoded !== 'string' || encoded.length < 50 || encoded.length > 410000 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error('Ogiltig bilddata.');
  const buffer = Buffer.from(encoded, 'base64');
  if (buffer.length < 100 || buffer.length > 300000 || buffer[0] !== 0xff ||
      buffer[1] !== 0xd8 || buffer[buffer.length-2] !== 0xff || buffer[buffer.length-1] !== 0xd9) {
    throw new Error('Bilden måste vara en JPEG på högst 300 kB.');
  }
  return buffer;
}


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
  -- Each member can have at most one reaction per post. Deleting the post removes reactions.
  CREATE TABLE IF NOT EXISTS post_reactions (
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    reaction TEXT NOT NULL CHECK (reaction IN ('up','down','heart')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (post_id, member_id)
  );
  CREATE INDEX IF NOT EXISTS post_reactions_member ON post_reactions(member_id);
  `);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS avatar_data BYTEA;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS avatar_updated_at TIMESTAMPTZ;`);
  // One association profile per independent installation (future: one database per association).
  await pool.query(`CREATE TABLE IF NOT EXISTS association_settings (
    association_id TEXT PRIMARY KEY,
    association_name TEXT NOT NULL,
    app_title TEXT NOT NULL,
    tagline TEXT NOT NULL,
    welcome_title TEXT NOT NULL,
    welcome_text TEXT NOT NULL,
    about_text TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  // A fresh installation starts without an association name.
  await pool.query('ALTER TABLE association_settings ADD COLUMN IF NOT EXISTS configured_at TIMESTAMPTZ;');
  await pool.query(`INSERT INTO association_settings
    (association_id,association_name,app_title,tagline,welcome_title,welcome_text,about_text)
    VALUES ('local','','Lillachatten','En privat mötesplats','','','')
    ON CONFLICT (association_id) DO NOTHING`);
  // One installation, one association, one invitation process.
  // Older group tables are deliberately left untouched for recoverability.
  await pool.query(`CREATE TABLE IF NOT EXISTS member_invitations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    invited_email TEXT NOT NULL CHECK(char_length(invited_email) BETWEEN 3 AND 180),
    invited_by BIGINT NOT NULL REFERENCES members(id),
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS member_invitations_email
    ON member_invitations(lower(invited_email));`);
  // Each post can have one compressed JPEG, stored durably in PostgreSQL.
  await pool.query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS image_data BYTEA;');
  // Safe migration from v0.6. Existing members, posts and comments are retained.
  await pool.query(`ALTER TABLE members DROP CONSTRAINT IF EXISTS members_status_check;
    ALTER TABLE members ADD CONSTRAINT members_status_check CHECK (status IN ('active','inactive','pending'));`);
}

// A single fixed administrator. Other accounts are preserved as ordinary members,
// including their posts; their old administrator sessions are invalidated.
const administratorEmail = 'admin@forening.test';
async function ensureSingleAdministrator() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(745169)');
    const {rows} = await client.query('SELECT id FROM members WHERE lower(email)=$1 FOR UPDATE', [administratorEmail]);
    let adminId = rows[0]?.id;
    if (!adminId) {
      const password = process.env.FIRST_ADMIN_PASSWORD || '';
      if (password.length < 12 || password.length > 200) {
        throw new Error('Skapa admin@forening.test: ange FIRST_ADMIN_PASSWORD (12–200 tecken) i Render.');
      }
      const passwordHash = await bcrypt.hash(password,12);
      const created = await client.query(`INSERT INTO members
        (name,house,username,email,password_hash,status,role)
        VALUES ('Administratör','Föreningen',$1,$2,$3,'active','member') RETURNING id`,
        ['admin_'+randomBytes(8).toString('hex'),administratorEmail,passwordHash]);
      adminId = created.rows[0].id;
    }
    // Only remove elevated permissions; never delete users or content.
    const {rows: demoted} = await client.query(`UPDATE members SET role='member'
      WHERE role='admin' AND id<>$1 RETURNING id`,[adminId]);
    if (demoted.length) await client.query('DELETE FROM sessions WHERE member_id = ANY($1::bigint[])',
      [demoted.map(m=>m.id)]);
    await client.query("UPDATE members SET role='admin',status='active' WHERE id=$1",[adminId]);
    await client.query('COMMIT');
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS members_only_one_admin
      ON members ((role)) WHERE role='admin'`);
  } catch(err) { await client.query('ROLLBACK').catch(()=>{}); throw err; }
  finally { client.release(); }
}

// One-time recovery for the accidental Stockevik test profile left in a fresh
// Lillachatten database. Do not touch established installations or their data.
// The legacy name is used ONLY as a precise migration match, never as a default.
async function recoverUnusedTestInstallation() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(745170)');
    const {rows} = await client.query(`SELECT association_id FROM association_settings
      WHERE association_id='local'
        AND association_name='Stockeviks samhällsförening'
        AND app_title='Det händer i Stockevik'
        AND configured_at IS NOT NULL
        AND (SELECT count(*) FROM members)=1
        AND EXISTS (SELECT 1 FROM members WHERE lower(email)=$1 AND role='admin' AND status='active')
        AND NOT EXISTS (SELECT 1 FROM posts)
        AND NOT EXISTS (SELECT 1 FROM comments)
        AND NOT EXISTS (SELECT 1 FROM member_invitations)
      FOR UPDATE`, [administratorEmail]);
    if (!rows.length) {
      await client.query('COMMIT');
      console.log('Lillachatten: no unused legacy profile to recover.');
      return;
    }
    const password = process.env.FIRST_ADMIN_PASSWORD || '';
    if (password.length < 12 || password.length > 200) {
      throw new Error('FIRST_ADMIN_PASSWORD måste vara 12–200 tecken för engångsåterställning.');
    }
    const passwordHash = await bcrypt.hash(password, 12);
    await client.query(`UPDATE association_settings SET
      association_name='', app_title='Lillachatten', tagline='En privat mötesplats',
      welcome_title='', welcome_text='', about_text='',
      configured_at=NULL, updated_at=now() WHERE association_id='local'`);
    await client.query('UPDATE members SET password_hash=$1 WHERE lower(email)=$2',
      [passwordHash, administratorEmail]);
    await client.query(`DELETE FROM sessions WHERE member_id IN
      (SELECT id FROM members WHERE lower(email)=$1)`, [administratorEmail]);
    await client.query('COMMIT');
    console.log('Lillachatten: unused legacy profile reset; initial administrator password restored.');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function authenticate(req, res, next) {
  const token = req.cookies[cookieName];
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return res.status(401).json({error: 'Logga in först.'});
  try {
    const {rows} = await pool.query(`SELECT m.id, m.name, m.house, m.username, m.status, m.role, m.email, m.avatar_updated_at FROM sessions s
       JOIN members m ON m.id=s.member_id WHERE s.token_hash=$1 AND s.expires_at > now()`, [hashToken(token)]);
    if (!rows.length || rows[0].status !== 'active') return res.status(401).json({error:'Sessionen har gått ut.'});
    req.member = rows[0];
    next();
  } catch (err) { next(err); }
}

app.get('/api/health', async (_req, res, next) => {
  try {await pool.query('SELECT 1'); res.json({ok:true, app:'Lillachatten', version:'17'});}
  catch(err){next(err);}
});

app.post('/api/login', loginLimiter, async (req, res, next) => {
  try {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!email || password.length > 2000) return res.status(400).json({error:'Ange e-post och lösenord.'});
    const {rows} = await pool.query('SELECT * FROM members WHERE email=$1 AND status=$2', [email, 'active']);
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
      return res.status(401).json({error:'Fel e-post eller lösenord.'});
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

// Images are private: only logged-in approved members can retrieve them.
app.get('/api/posts/:id/image', authenticate, async (req,res,next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.sendStatus(404);
    const {rows} = await pool.query('SELECT image_data FROM posts WHERE id=$1', [req.params.id]);
    if (!rows.length || !rows[0].image_data) return res.sendStatus(404);
    res.set('Content-Type','image/jpeg');
    res.set('Cache-Control','private, no-store');
    res.set('X-Content-Type-Options','nosniff');
    res.send(rows[0].image_data);
  } catch(err) { next(err); }
});

app.get('/api/posts', authenticate, async (req, res, next) => {
  try {
    const {rows} = await pool.query(`SELECT p.id, p.body, p.created_at, (p.image_data IS NOT NULL) AS has_image, m.name AS author, m.id AS author_id, m.avatar_updated_at AS author_avatar_version,
      COALESCE((SELECT json_agg(json_build_object('id',c.id,'text',c.body,'date',c.created_at,'author',cm.name,'authorId',cm.id,'avatarVersion',cm.avatar_updated_at) ORDER BY c.created_at,c.id)
      FROM comments c JOIN members cm ON cm.id=c.member_id WHERE c.post_id=p.id),'[]'::json) AS comments
      FROM posts p JOIN members m ON m.id=p.member_id ORDER BY p.created_at DESC,p.id DESC LIMIT 100`);
    const ids = rows.map(p => p.id);
    const counts = new Map();
    const mine = new Map();
    if (ids.length) {
      const [allReactions, myReactions] = await Promise.all([
        pool.query(`SELECT post_id, reaction, count(*)::int AS total FROM post_reactions
                    WHERE post_id = ANY($1::bigint[]) GROUP BY post_id, reaction`, [ids]),
        pool.query(`SELECT post_id, reaction FROM post_reactions
                    WHERE member_id=$1 AND post_id = ANY($2::bigint[])`, [req.member.id, ids])
      ]);
      for (const r of allReactions.rows) {
        const id = String(r.post_id);
        if (!counts.has(id)) counts.set(id, {up:0, down:0, heart:0});
        counts.get(id)[r.reaction] = r.total;
      }
      for (const r of myReactions.rows) mine.set(String(r.post_id), r.reaction);
    }
    res.json({posts:rows.map(p=>({
      id:p.id, text:p.body, date:p.created_at, author:p.author, authorId:p.author_id,
      avatarVersion:p.author_avatar_version ? new Date(p.author_avatar_version).getTime() : null,
      hasImage:p.has_image, comments:p.comments,
      reactions:counts.get(String(p.id)) || {up:0,down:0,heart:0},
      myReaction:mine.get(String(p.id)) || null
    }))});
  } catch(err){next(err);}
});

// One reaction per member and post: choose another emoji to replace it, or click again to undo.
// This endpoint also serves reactions to post images because the image belongs to the post.
app.put('/api/posts/:id/reaction', authenticate, writeLimiter, async (req,res,next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({error:'Ogiltigt inläggs-ID.'});
    const reaction = req.body?.reaction;
    if (reaction !== null && !['up','down','heart'].includes(reaction))
      return res.status(400).json({error:'Välj tumme upp, tumme ner eller hjärta.'});
    const exists = await pool.query('SELECT 1 FROM posts WHERE id=$1', [req.params.id]);
    if (!exists.rowCount) return res.status(404).json({error:'Inlägget saknas.'});
    if (reaction === null) {
      await pool.query('DELETE FROM post_reactions WHERE post_id=$1 AND member_id=$2',
        [req.params.id,req.member.id]);
    } else {
      await pool.query(`INSERT INTO post_reactions(post_id,member_id,reaction)
          VALUES($1,$2,$3) ON CONFLICT(post_id,member_id)
          DO UPDATE SET reaction=EXCLUDED.reaction`,
        [req.params.id,req.member.id,reaction]);
    }
    res.json({ok:true});
  } catch(err){next(err);}
});

app.post('/api/posts', authenticate, writeLimiter, async (req, res, next) => {
  try {
    const body = safeText(req.body?.text, 5000);
    if (!body) return res.status(400).json({error:'Skriv en kort text till bilden eller inlägget.'});
    let imageData;
    try { imageData = postImageBuffer(req.body?.jpegBase64); }
    catch (err) { return res.status(400).json({error:err.message}); }
    const {rows} = await pool.query('INSERT INTO posts(member_id,body,image_data) VALUES ($1,$2,$3) RETURNING id,created_at',
      [req.member.id,body,imageData]);
    res.status(201).json({post:{id:rows[0].id, text:body, author:req.member.name, authorId:req.member.id, avatarVersion:req.member.avatar_updated_at ? new Date(req.member.avatar_updated_at).getTime() : null, hasImage:!!imageData, date:rows[0].created_at, comments:[]}});
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
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({error:'Ogiltigt inläggs-ID.'});
    const body=safeText(req.body?.text,2000);
    if (!body) return res.status(400).json({error:'Kommentaren måste innehÃ¥lla 1–2000 tecken.'});
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


// Self-registration is disabled. Only a one-use invitation can create an account.
app.post('/api/register', (_req,res) => res.status(403).json({error:'Medlemskap kräver en personlig inbjudan.'}));

function requireAdmin(req,res,next) {
  if (req.member.role !== 'admin' || req.member.email.toLowerCase() !== administratorEmail) return res.status(403).json({error:'Endast administratören har tillgÃ¥ng.'});
  next();
}
// Association profile. No access to member data, and only administrators may edit text.
const associationId = 'local'; // Internal single-installation identifier, not the association's name.
const associationFields = ['association_name','app_title','tagline','welcome_title','welcome_text','about_text'];
app.get('/api/association', async (_req,res,next) => {
  try {
    const {rows} = await pool.query(`SELECT association_id,association_name,app_title,tagline,
      welcome_title,welcome_text,about_text,configured_at FROM association_settings WHERE association_id=$1`,[associationId]);
    if (!rows.length) return res.status(503).json({error:'Föreningsprofilen saknas.'});
    res.set('Cache-Control','no-store');
    res.json({association:{...rows[0],configured:!!rows[0].configured_at}});
  } catch(err){next(err);}
});
// First action of the sole administrator on a brand-new installation.
app.post('/api/admin/association/initialize', authenticate, requireAdmin, writeLimiter, async (req,res,next) => {
  try {
    const name=safeText(req.body?.name,180);
    if (!name) return res.status(400).json({error:'Ange föreningens namn.'});
    const {rows}=await pool.query(`UPDATE association_settings SET association_name=$2,
      app_title=$2,tagline='Vår egen mötesplats · utan annonser',
      welcome_title='Välkommen till ' || $2 || '!',
      welcome_text='Nyheter, bilder och samtal mellan medlemmarna – utan annonser.',
      about_text='En privat mötesplats för medlemmarna i ' || $2 || '.',
      configured_at=now(),updated_at=now()
      WHERE association_id=$1 AND configured_at IS NULL
      RETURNING association_id,association_name,app_title,tagline,welcome_title,welcome_text,about_text,configured_at`,
      [associationId,name]);
    if (!rows.length) return res.status(409).json({error:'Föreningen har redan fått ett namn.'});
    res.json({association:{...rows[0],configured:true}});
  } catch(err){next(err);}
});
app.put('/api/admin/association', authenticate, requireAdmin, writeLimiter, async (req,res,next) => {
  try {
    const values = associationFields.map(field => typeof req.body?.[field] === 'string' ? req.body[field].trim() : '');
    if (values.some((value,i) => !value || value.length > (i === 5 ? 600 : 180)))
      return res.status(400).json({error:'Alla föreningstexter måste fyllas i och hålla sig inom längdgränsen.'});
    const {rows} = await pool.query(`UPDATE association_settings SET
      association_name=$2,app_title=$3,tagline=$4,welcome_title=$5,welcome_text=$6,
      about_text=$7,updated_at=now() WHERE association_id=$1
      RETURNING association_id,association_name,app_title,tagline,welcome_title,welcome_text,about_text`,
      [associationId,...values]);
    if (!rows.length) return res.status(404).json({error:'Föreningsprofilen saknas.'});
    res.json({association:rows[0]});
  } catch(err){next(err);}
});

// Only administrators may inspect contact details or change another member.
// No permanent deletion: posts and comments remain attributable to the member.
app.get('/api/admin/members', authenticate, requireAdmin, async (_req,res,next) => {
  try {
    const {rows} = await pool.query(`SELECT id,name,house,username,email,status,role
      FROM members WHERE status <> 'pending' ORDER BY lower(name),id`);
    res.json({members:rows});
  } catch(err) { next(err); }
});

app.put('/api/admin/members/:id', authenticate, requireAdmin, writeLimiter, async (req,res,next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({error:'Ogiltigt medlems-ID.'});
    const name = safeText(req.body?.name,100);
    const house = safeText(req.body?.house,100);
    const username = safeText(req.body?.username,50);
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const status = req.body?.status;
    if (!name || !house || !username || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        email.length > 180 || !['active','inactive'].includes(status)) {
      return res.status(400).json({error:'Kontrollera namn, fastighet, användarnamn, e-postadress och status.'});
    }
    if (/[\s]/.test(username) || username.length < 2) {
      return res.status(400).json({error:'Användarnamnet ska vara 2–50 tecken utan mellanslag.'});
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const {rows:original} = await client.query(`SELECT id,role,status,email FROM members
        WHERE id=$1 AND status <> 'pending' FOR UPDATE`, [req.params.id]);
      if (!original.length) { await client.query('ROLLBACK'); return res.status(404).json({error:'Medlemmen hittades inte.'}); }
      // Administrator accounts must never be disabled via this editor.
      if (original[0].role === 'admin' && (status !== 'active' || email !== administratorEmail)) {
        await client.query('ROLLBACK');
        return res.status(403).json({error:'Administratörens e-post och status kan inte ändras här.'});
      }
      const {rows} = await client.query(`UPDATE members
        SET name=$2,house=$3,username=$4,email=$5,status=$6 WHERE id=$1
        RETURNING id,name,house,username,email,status,role`,
        [req.params.id,name,house,username,email,status]);
      if (status === 'inactive') await client.query('DELETE FROM sessions WHERE member_id=$1',[req.params.id]);
      await client.query('COMMIT');
      res.json({member:rows[0]});
    } catch (err) {
      await client.query('ROLLBACK');
      if (err.code === '23505') return res.status(409).json({error:'E-postadressen eller användarnamnet används redan.'});
      throw err;
    } finally { client.release(); }
  } catch(err) { next(err); }
});

// Administrator can set a new password for an existing non-admin member.
// The new secret is never returned or logged. Existing sessions are invalidated.
app.post('/api/admin/members/:id/reset-password', authenticate, requireAdmin, writeLimiter, async (req,res,next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({error:'Ogiltigt medlems-ID.'});
    const password = req.body?.password;
    if (typeof password !== 'string' || password.length < 8 || password.length > 200) {
      return res.status(400).json({error:'Det nya lösenordet måste innehålla 8–200 tecken.'});
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const {rows} = await client.query(`SELECT id,role,status FROM members
        WHERE id=$1 FOR UPDATE`, [req.params.id]);
      if (!rows.length || rows[0].status === 'pending') {
        await client.query('ROLLBACK');
        return res.status(404).json({error:'Medlemmen hittades inte.'});
      }
      if (rows[0].role === 'admin') {
        await client.query('ROLLBACK');
        return res.status(403).json({error:'Administratörer byter lösenord under Min profil.'});
      }
      await client.query('UPDATE members SET password_hash=$1 WHERE id=$2', [passwordHash, req.params.id]);
      await client.query('DELETE FROM sessions WHERE member_id=$1', [req.params.id]);
      await client.query('COMMIT');
      res.json({ok:true});
    } catch(err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {client.release();}
  } catch(err) {next(err);}
});

// An administrator may invite a new member by email. No groups, no approval queue.
app.post('/api/admin/invitations', authenticate, requireAdmin, writeLimiter, async (req,res,next) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 180)
    return res.status(400).json({error:'Ange en giltig e-postadress.'});
  if (email === administratorEmail) return res.status(409).json({error:'Administratören har redan ett konto.'});
  let ready;
  try { ready=await pool.query('SELECT configured_at FROM association_settings WHERE association_id=$1',[associationId]); }
  catch(err) { return next(err); }
  if (!ready.rows[0]?.configured_at) return res.status(409).json({error:'Ge först föreningen ett namn.'});
  const client = await pool.connect();
  let invitationId;
  let token;
  try {
    await client.query('BEGIN');
    // Avoid concurrent invitations for the same address.
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',[email]);
    const member = await client.query('SELECT id FROM members WHERE lower(email)=$1',[email]);
    if (member.rowCount) {await client.query('ROLLBACK');return res.status(409).json({error:'Adressen är redan registrerad.'});}
    await client.query(`UPDATE member_invitations SET revoked_at=now()
      WHERE lower(invited_email)=$1 AND accepted_at IS NULL AND revoked_at IS NULL`,[email]);
    token = randomBytes(32).toString('hex');
    const invitation = await client.query(`INSERT INTO member_invitations
      (invited_email,invited_by,token_hash,expires_at)
      VALUES($1,$2,$3,now()+interval '48 hours') RETURNING id`,
      [email,req.member.id,hashToken(token)]);
    invitationId = invitation.rows[0].id;
    await client.query('COMMIT');
  } catch(err) {await client.query('ROLLBACK').catch(()=>{});return next(err);}
  finally {client.release();}

  // Link always opens the same origin serving the app; no stale hard-coded domain.
  // Set PUBLIC_BASE_URL on Render if an external canonical hostname is required.
  const baseUrl = (process.env.PUBLIC_BASE_URL || (!production ? `${req.protocol}://${req.get('host')}` : '')).replace(/\/$/,'');
  if (!/^https:\/\/[^/]+$/i.test(baseUrl) && production) {
    await pool.query('UPDATE member_invitations SET revoked_at=now() WHERE id=$1',[invitationId]);
    return res.status(503).json({error:'Ange PUBLIC_BASE_URL som den offentliga HTTPS-adressen till appen i Render.'});
  }
  const url = `${baseUrl}/accept-invitation.html#token=${token}`;
  try {
    const association=await pool.query('SELECT association_name FROM association_settings WHERE association_id=$1',[associationId]);
    const associationName=association.rows[0].association_name;
    const safeAssociationName=associationName.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) throw new Error('RESEND_API_KEY missing');
    const response = await fetch('https://api.resend.com/emails', {
      method:'POST',
      headers:{Authorization:`Bearer ${apiKey}`,'Content-Type':'application/json',
        'Idempotency-Key':`lillachatten-invite-${invitationId}`},
      body:JSON.stringify({
        from:'Lilla Chatten <inbjudan@lillachatten.se>',
        to:[email], subject:`Inbjudan till ${associationName}`, 
        text:`Du är inbjuden till ${associationName}.\n\nÖppna din personliga inbjudan:\n${url}\n\nLänken gäller i 48 timmar.`,
        html:`<p>Du är inbjuden till ${safeAssociationName}.</p><p><a href="${url}" style="display:inline-block;background:#24697b;color:white;padding:12px 20px;border-radius:8px;text-decoration:none">Visa inbjudan</a></p><p>Inbjudan gäller i 48 timmar.</p>`
      }), signal:AbortSignal.timeout(15000)
    });
    if (!response.ok) throw new Error(`Resend status ${response.status}`);
    res.status(201).json({ok:true,message:'Inbjudan är skickad.'});
  } catch(err) {
    await pool.query('UPDATE member_invitations SET revoked_at=now() WHERE id=$1',[invitationId]);
    console.error('Invitation email failure:',err.message);
    res.status(502).json({error:'Inbjudan kunde inte skickas. Kontrollera Resend och försök igen.'});
  }
});

app.post('/api/invitations/preview',registrationLimiter,async(req,res,next)=>{
  res.set('Cache-Control','no-store');
  const token = typeof req.body?.token === 'string' ? req.body.token : '';
  if (!/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({error:'Ogiltig inbjudningslänk.'});
  try {
    const result=await pool.query(`SELECT invited_email,expires_at FROM member_invitations
      WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`,[hashToken(token)]);
    if (!result.rowCount) return res.status(404).json({error:'Inbjudan är redan använd, återkallad eller har gått ut.'});
    res.json({email:result.rows[0].invited_email,expiresAt:result.rows[0].expires_at,canAccept:true});
  } catch(err){next(err);}
});

app.post('/api/invitations/decline',registrationLimiter,async(req,res,next)=>{
  res.set('Cache-Control','no-store');
  const token=typeof req.body?.token==='string'?req.body.token:'';
  if (!/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({error:'Ogiltig inbjudningslänk.'});
  try {
    const result=await pool.query(`UPDATE member_invitations SET revoked_at=now()
      WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() RETURNING id`,[hashToken(token)]);
    if (!result.rowCount) return res.status(404).json({error:'Inbjudan gäller inte längre.'});
    res.json({ok:true});
  }catch(err){next(err);}
});

app.post('/api/invitations/accept',registrationLimiter,async(req,res,next)=>{
  res.set('Cache-Control','no-store');
  const token=typeof req.body?.token==='string'?req.body.token:'';
  const name=safeText(req.body?.name,100),house=safeText(req.body?.house,100);
  const password=typeof req.body?.password==='string'?req.body.password:'';
  if (!/^[0-9a-f]{64}$/.test(token)||!name||!house||password.length<12||password.length>200)
    return res.status(400).json({error:'Namn, bostad och lösenord med minst 12 tecken är obligatoriska. Utan lösenord går det inte att logga in.'});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const invitation=await client.query(`SELECT id,invited_email FROM member_invitations
      WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()
      FOR UPDATE`,[hashToken(token)]);
    if (!invitation.rowCount){await client.query('ROLLBACK');return res.status(404).json({error:'Inbjudan gäller inte längre.'});}
    const email=invitation.rows[0].invited_email.trim().toLowerCase();
    if (email===administratorEmail){await client.query('ROLLBACK');return res.status(403).json({error:'Den här adressen är reserverad.'});}
    if ((await client.query('SELECT 1 FROM members WHERE lower(email)=$1',[email])).rowCount){
      await client.query('ROLLBACK');return res.status(409).json({error:'Adressen har redan ett konto. Logga in i stället.'});
    }
    const passwordHash=await bcrypt.hash(password,12);
    await client.query(`INSERT INTO members(name,house,username,email,password_hash,status,role)
      VALUES($1,$2,$3,$4,$5,'active','member')`,
      [name,house,'medlem_'+randomBytes(12).toString('hex'),email,passwordHash]);
    await client.query('UPDATE member_invitations SET accepted_at=now() WHERE id=$1',[invitation.rows[0].id]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,email,message:'Registreringen är klar. Välkommen till Lillachatten!'});
  }catch(err){await client.query('ROLLBACK').catch(()=>{});if(err.code==='23505')return res.status(409).json({error:'E-postadressen är redan registrerad.'});next(err);}
  finally{client.release();}
});

// Frontend and API share one origin, so the secure session cookie works in browsers.
app.use(express.static('public'));
app.use((req,res)=>res.status(404).json({error:'Okänd adress.'}));
app.use((err,req,res,next)=>{
  console.error('API error:', err);
  res.status(500).json({error:'Ett serverfel uppstod.'});
});

try {
  await initialize();
  await ensureSingleAdministrator();
  await recoverUnusedTestInstallation();
  const port=Number(process.env.PORT || 10000);
  app.listen(port,'0.0.0.0',()=>console.log(`Lillachatten listening on ${port}`));
} catch(err){console.error('Startup failed:',err);process.exit(1);}