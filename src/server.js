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
  await pool.query(`INSERT INTO association_settings
    (association_id,association_name,app_title,tagline,welcome_title,welcome_text,about_text)
    VALUES ('stockevik','Stockeviks samhällsförening','Det händer i Stockevik',
    'Vår egen mötesplats · utan annonser','Välkommen till vår mötesplats!',
    'Nyheter, bilder och samtal mellan grannar – utan annonser.',
    'Ett privat samtalsforum för oss i Stockevik.')
    ON CONFLICT (association_id) DO NOTHING`);
  // FUTURE MULTI-GROUP IDENTITY SCHEMA - step 1 (unused by existing routes)
  // Only creates new tables. Existing members, sessions, posts and settings remain untouched.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS identity_accounts (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      email TEXT NOT NULL,
      display_name TEXT NOT NULL,
      email_verified_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (char_length(email) BETWEEN 3 AND 180),
      CHECK (char_length(display_name) BETWEEN 1 AND 100)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS identity_accounts_email_unique
      ON identity_accounts (lower(email));

    CREATE TABLE IF NOT EXISTS group_spaces (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      group_name TEXT NOT NULL CHECK (char_length(group_name) BETWEEN 1 AND 100),
      plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'paid')),
      state TEXT NOT NULL DEFAULT 'provisional'
        CHECK (state IN ('provisional', 'active', 'suspended', 'closed')),
      created_by BIGINT NOT NULL REFERENCES identity_accounts(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS group_memberships (
      group_id BIGINT NOT NULL REFERENCES group_spaces(id) ON DELETE CASCADE,
      account_id BIGINT NOT NULL REFERENCES identity_accounts(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'admin')),
      status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('invited', 'active', 'left', 'removed')),
      joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (group_id, account_id)
    );
    CREATE INDEX IF NOT EXISTS group_memberships_account
      ON group_memberships(account_id);

    CREATE TABLE IF NOT EXISTS group_invitations (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      group_id BIGINT NOT NULL REFERENCES group_spaces(id) ON DELETE CASCADE,
      invited_email TEXT NOT NULL,
      invited_by BIGINT NOT NULL REFERENCES identity_accounts(id),
      token_hash CHAR(64) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      accepted_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (char_length(invited_email) BETWEEN 3 AND 180)
    );
    CREATE INDEX IF NOT EXISTS group_invitations_group
      ON group_invitations(group_id);
  `);

  // Each post can have one compressed JPEG, stored durably in PostgreSQL.
  await pool.query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS image_data BYTEA;');
  // Safe migration from v0.6. Existing members, posts and comments are retained.
  await pool.query(`ALTER TABLE members DROP CONSTRAINT IF EXISTS members_status_check;
    ALTER TABLE members ADD CONSTRAINT members_status_check CHECK (status IN ('active','inactive','pending'));`);
}

// Temporary, explicit test-only seed. No emails sent, no existing logins changed.
// Enable CREATE_TEST_GROUP_ONCE=true in the TEST Render service for one deploy only.
async function createFirstTestGroupOnce() {
  if (process.env.CREATE_TEST_GROUP_ONCE !== 'true') return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(745173)');
    // The test database must have exactly one active administrator.
    // Do not depend on FIRST_ADMIN_EMAIL: bootstrap settings may differ from the existing account.
    const { rows: admins } = await client.query(
      "SELECT id, name, email FROM members WHERE role='admin' AND status='active'"
    );
    if (admins.length !== 1) throw new Error('Test group aborted: expected exactly one active administrator.');
    const email = admins[0].email.trim().toLowerCase();
    const { rows: accounts } = await client.query(
      `INSERT INTO identity_accounts (email, display_name)
       VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING id`,
      [email, admins[0].name]
    );
    let accountId = accounts[0]?.id;
    if (!accountId) {
      const { rows } = await client.query(
        'SELECT id FROM identity_accounts WHERE lower(email)=$1', [email]
      );
      if (rows.length !== 1) throw new Error('Test identity lookup failed.');
      accountId = rows[0].id;
    }
    // Existing admin email has NOT been verified in the new identity system.
    const { rows: existing } = await client.query(
      "SELECT id FROM group_spaces WHERE created_by=$1 AND group_name='Provgruppen' FOR UPDATE",
      [accountId]
    );
    let groupId = existing[0]?.id;
    if (!groupId) {
      const { rows } = await client.query(
        `INSERT INTO group_spaces (group_name, created_by, state)
         VALUES ('Provgruppen',$1,'provisional') RETURNING id`, [accountId]
      );
      groupId = rows[0].id;
    }
    await client.query(
      `INSERT INTO group_memberships (group_id,account_id,role,status)
       VALUES ($1,$2,'admin','active') ON CONFLICT (group_id,account_id) DO NOTHING`,
      [groupId,accountId]
    );
    await client.query('COMMIT');
    console.log('Test identity and provisional group ready; one admin membership linked.');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// Bootstrap the first administrator if this installation has no administrator yet.
// Existing members, applications, posts and comments are never changed.
// Credentials are supplied ONLY via the TEST service's Render environment.
async function bootstrapFirstAdmin() {
  const email = (process.env.FIRST_ADMIN_EMAIL || '').trim().toLowerCase();
  const name = (process.env.FIRST_ADMIN_NAME || '').trim();
  const password = process.env.FIRST_ADMIN_PASSWORD || '';
  const house = (process.env.FIRST_ADMIN_HOUSE || '').trim() || 'Föreningens administratör';
  if (!email && !name && !password) return;
  if (!email || !name || !password ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 180 || name.length > 100 || house.length > 100 ||
      password.length < 12 || password.length > 200) {
    throw new Error('FIRST_ADMIN_EMAIL, FIRST_ADMIN_NAME och FIRST_ADMIN_PASSWORD (minst 12 tecken) måste anges korrekt.');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Prevent simultaneous startups from creating multiple administrators.
    await client.query('SELECT pg_advisory_xact_lock(745169)');
    const {rows:admins} = await client.query("SELECT id FROM members WHERE role='admin' LIMIT 1");
    if (admins.length) {
      console.log('First administrator bootstrap skipped: an administrator already exists.');
      await client.query('COMMIT');
      return;
    }
    // Never modify an existing member who happens to have the requested email.
    const {rows:existing} = await client.query('SELECT id FROM members WHERE email=$1', [email]);
    if (existing.length) {
      throw new Error('FIRST_ADMIN_EMAIL is already registered. Choose a different email; existing members were not changed.');
    }
    const hash = await bcrypt.hash(password, 12);
    const username = 'admin_' + randomBytes(8).toString('hex');
    await client.query(`INSERT INTO members(name, house, username, email, password_hash, status, role)
      VALUES($1,$2,$3,$4,$5,'active','admin')`,
      [name, house, username, email, hash]);
    await client.query('COMMIT');
    console.log('First administrator account created; existing members preserved.');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally { client.release(); }
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
// Association profile. No access to member data, and only administrators may edit text.
const associationId = 'stockevik'; // Installation identity; will become deployment configuration later.
const associationFields = ['association_name','app_title','tagline','welcome_title','welcome_text','about_text'];
app.get('/api/association', async (_req,res,next) => {
  try {
    const {rows} = await pool.query(`SELECT association_id,association_name,app_title,tagline,
      welcome_title,welcome_text,about_text FROM association_settings WHERE association_id=$1`,[associationId]);
    if (!rows.length) return res.status(503).json({error:'Föreningsprofilen saknas.'});
    res.set('Cache-Control','no-store');
    res.json({association:rows[0]});
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
      const {rows:original} = await client.query(`SELECT id,role,status FROM members
        WHERE id=$1 AND status <> 'pending' FOR UPDATE`, [req.params.id]);
      if (!original.length) { await client.query('ROLLBACK'); return res.status(404).json({error:'Medlemmen hittades inte.'}); }
      // Administrator accounts must never be disabled via this editor.
      if (original[0].role === 'admin' && status !== 'active') {
        await client.query('ROLLBACK');
        return res.status(403).json({error:'Administratörskonton kan inte inaktiveras här.'});
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

// List only the groups administered by the logged-in test account.
// This endpoint never exposes other members' contact details.
app.get('/api/my-admin-groups', authenticate, requireAdmin, async (req, res, next) => {
  try {
    const {rows} = await pool.query(
      `SELECT gs.id, gs.group_name FROM group_spaces gs
       JOIN group_memberships gm ON gm.group_id=gs.id
       JOIN identity_accounts ia ON ia.id=gm.account_id
       WHERE lower(ia.email)=lower($1)
         AND gm.role='admin' AND gm.status='active'
         AND gs.state IN ('provisional','active')
       ORDER BY gs.id`, [req.member.email]
    );
    res.set('Cache-Control', 'no-store');
    res.json({groups: rows});
  } catch (err) {next(err);}
});

// First invitation stage: only a logged-in group administrator can create an invitation.
// The invitation is NOT a membership and does NOT grant access to any group content.
// Email delivery and acceptance are deliberately not enabled yet.
app.post('/api/groups/:groupId/invitations', authenticate, requireAdmin, writeLimiter, async (req, res, next) => {
  const groupId = req.params.groupId;
  const invitedEmail = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!/^\d+$/.test(groupId) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(invitedEmail) || invitedEmail.length > 180) {
    return res.status(400).json({error:'Ange giltig grupp och e-postadress.'});
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize invitations for one group to enforce the free group's member ceiling.
    const {rows: groups} = await client.query(
      'SELECT id, plan FROM group_spaces WHERE id=$1 FOR UPDATE', [groupId]);
    if (groups.length !== 1) {
      await client.query('ROLLBACK');
      return res.status(404).json({error:'Gruppen finns inte.'});
    }
    // Match the current, authenticated legacy admin to its new identity,
    // and verify admin membership in this particular group.
    const {rows: admins} = await client.query(
      `SELECT ia.id FROM identity_accounts ia
       JOIN group_memberships gm ON gm.account_id=ia.id
       WHERE lower(ia.email)=lower($1) AND gm.group_id=$2
         AND gm.role='admin' AND gm.status='active'`,
      [req.member.email, groupId]
    );
    if (admins.length !== 1) {
      await client.query('ROLLBACK');
      return res.status(403).json({error:'Du administrerar inte den här gruppen.'});
    }
    const {rows: active} = await client.query(
      `SELECT count(*)::int AS total FROM group_memberships
       WHERE group_id=$1 AND status='active'`, [groupId]
    );
    const {rows: existingMember} = await client.query(
      `SELECT 1 FROM identity_accounts ia JOIN group_memberships gm ON gm.account_id=ia.id
       WHERE gm.group_id=$1 AND gm.status='active' AND lower(ia.email)=$2 LIMIT 1`,
      [groupId, invitedEmail]
    );
    if (existingMember.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({error:'Personen är redan medlem.'});
    }
    const {rows: pending} = await client.query(
      `SELECT count(*)::int AS total FROM group_invitations
       WHERE group_id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`,
      [groupId]
    );
    if (groups[0].plan === 'free' && active[0].total + pending[0].total >= 25) {
      await client.query('ROLLBACK');
      return res.status(409).json({error:'Gratisgruppen har redan 25 medlemmar eller öppna inbjudningar.'});
    }
    const {rows: duplicates} = await client.query(
      `SELECT 1 FROM group_invitations WHERE group_id=$1 AND lower(invited_email)=$2
       AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() LIMIT 1`,
      [groupId, invitedEmail]
    );
    if (duplicates.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({error:'En giltig inbjudan finns redan för adressen.'});
    }
    const token = randomBytes(32).toString('hex');
    const {rows: invitations} = await client.query(
      `INSERT INTO group_invitations
       (group_id, invited_email, invited_by, token_hash, expires_at)
       VALUES ($1,$2,$3,$4,now() + interval '48 hours')
       RETURNING id, expires_at`,
      [groupId, invitedEmail, admins[0].id, hashToken(token)]
    );
    await client.query('COMMIT');
    res.status(201).json({
      invitationId: invitations[0].id,
      expiresAt: invitations[0].expires_at,
      // This bearer token must only be delivered privately to the intended invitee.
      // No recipient-facing invitation page exists yet; do not distribute it now.
      token,
      message: 'Inbjudan skapad men kan inte skickas innan mottagarsidan är klar.'
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) { /* Preserve original error. */ }
    next(err);
  } finally {
    client.release();
  }
});

// Invitation preview only: never grants membership or discloses group posts.
// Link secret is transmitted in POST body, not in URLs or request logs.
app.post('/api/invitations/preview', registrationLimiter, async (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  const token = typeof req.body?.token === 'string' ? req.body.token : '';
  if (!/^[0-9a-f]{64}$/.test(token)) {
    return res.status(400).json({error:'Ogiltig inbjudningslänk.'});
  }
  try {
    const {rows} = await pool.query(
      `SELECT gs.group_name, gi.invited_email, gi.expires_at
       FROM group_invitations gi
       JOIN group_spaces gs ON gs.id=gi.group_id
       WHERE gi.token_hash=$1 AND gi.accepted_at IS NULL
         AND gi.revoked_at IS NULL AND gi.expires_at > now()
         AND gs.state IN ('provisional','active')`,
      [hashToken(token)]
    );
    if (rows.length !== 1) {
      return res.status(404).json({error:'Inbjudan är ogiltig eller har gått ut.'});
    }
    res.json({groupName:rows[0].group_name, email:rows[0].invited_email,
      expiresAt:rows[0].expires_at, canAccept:false});
  } catch (err) {next(err);}
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
  // Schema check (temporary): print only table names and row counts. No personal data.
  for (const table of ['identity_accounts', 'group_spaces', 'group_memberships', 'group_invitations']) {
    const { rows } = await pool.query(`SELECT count(*)::int AS total FROM ${table}`);
    console.log(`Schema check: ${table} exists; rows=${rows[0].total}`);
  }

  await bootstrapFirstAdmin();
  // TEMPORARY DIAGNOSTIC: report counts only; no personal data or secrets in logs.
  const diagnosticAdminEmail = (process.env.FIRST_ADMIN_EMAIL || '').trim().toLowerCase();
  const { rows: diagnosticAdminRows } = await pool.query(`
    SELECT
      count(*) FILTER (WHERE role = 'admin')::int AS all_admins,
      count(*) FILTER (WHERE role = 'admin' AND status = 'active')::int AS active_admins,
      count(*) FILTER (WHERE lower(email) = $1)::int AS email_matches,
      count(*) FILTER (WHERE lower(email) = $1 AND status = 'active')::int AS email_active,
      count(*) FILTER (WHERE lower(email) = $1 AND role = 'admin')::int AS email_admin
    FROM members`, [diagnosticAdminEmail]);
  const d = diagnosticAdminRows[0];
  console.log(`Test-admin diagnosis: all_admins=${d.all_admins}, active_admins=${d.active_admins}, email_matches=${d.email_matches}, email_active=${d.email_active}, email_admin=${d.email_admin}`);
  await createFirstTestGroupOnce();

  // Tillfällig engångsåterställning. Aktiveras enbart med explicit Render-variabel.
  if (process.env.RESET_FIRST_ADMIN_PASSWORD === 'true') {
    const email = (process.env.FIRST_ADMIN_EMAIL || '').trim().toLowerCase();
    const password = process.env.FIRST_ADMIN_PASSWORD || '';
    if (!email || password.length < 12 || password.length > 200) {
      throw new Error('Admin reset requires FIRST_ADMIN_EMAIL and FIRST_ADMIN_PASSWORD (minst 12 tecken).');
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        "SELECT id FROM members WHERE email=$1 AND role='admin' AND status='active' FOR UPDATE",
        [email]
      );
      if (rows.length !== 1) throw new Error('Admin reset aborted: aktiv administrator med angiven e-post saknas.');
      const hash = await bcrypt.hash(password, 12);
      await client.query('UPDATE members SET password_hash=$1 WHERE id=$2', [hash, rows[0].id]);
      await client.query('DELETE FROM sessions WHERE member_id=$1', [rows[0].id]);
      await client.query('COMMIT');
      console.log('Existing test administrator password reset; old sessions cleared.');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

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