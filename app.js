// app.js — Bet! MVP API (tokens-only beta) — hardened
// Render env vars required: DATABASE_URL, JWT_SECRET, PORT=8080
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pkg from 'pg';
import dotenv from 'dotenv';
dotenv.config();

const { Pool } = pkg;
const app = express();
app.use(cors());
app.use(bodyParser.json());

// ---- Config ----
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set');
}

let pool;
try {
  if (!DATABASE_URL) throw new Error('DATABASE_URL missing');

  // Parse the URL ourselves to avoid pg’s connectionString quirks
  const u = new URL(DATABASE_URL.trim());

  pool = new Pool({
    host: u.hostname,
    port: Number(u.port || 5432),
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: u.pathname.replace(/^\//, '') || 'postgres',
    ssl: { rejectUnauthorized: false }
  });
} catch (e) {
  console.error('FATAL: Failed to create DB pool:', e.message);
  process.exit(1);
}

async function query(q, params) {
  try {
    const r = await pool.query(q, params);
    return r;
  } catch (e) {
    console.error('DB ERROR:', e.message);
    throw e;
  }
}

function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'unauthorized' }); }
}

// ---- Health endpoints ----
app.get('/', (_req, res) => res.send('Bet! API up'));
app.get('/health/db', async (_req, res) => {
  try {
    const r = await query('select 1 as ok', []);
    res.json({ ok: true, db: r.rows[0] });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---- Ensure bot account ----
async function ensureBotAccount() {
  const email = 'bot@bet.app';
  const { rows } = await query('select id from users where email=$1', [email]);
  let botId;
  if (!rows.length) {
    const hash = await bcrypt.hash('bot_password', 10);
    const r1 = await query(
      'insert into users (email, display_name, password_hash) values ($1,$2,$3) returning id',
      [email, 'Coach Watkins (Bot)', hash]
    );
    botId = r1.rows[0].id;
    await query('insert into wallets (user_id, balance_credits) values ($1, $2)', [botId, 1000000]);
    console.log('Bot account created:', botId);
  } else {
    botId = rows[0].id;
    // make sure bot has a wallet
    const w = await query('select 1 from wallets where user_id=$1', [botId]);
    if (!w.rows.length) {
      await query('insert into wallets (user_id, balance_credits) values ($1, $2)', [botId, 1000000]);
    }
    console.log('Bot account exists:', botId);
  }
  return botId;
}

// ---- Auth ----
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, displayName, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const existing = await query('select id from users where email=$1', [email]);
    if (existing.rows.length) return res.status(400).json({ error: 'email in use' });
    const hash = await bcrypt.hash(password, 10);
    const u = await query(
      'insert into users (email, display_name, password_hash) values ($1,$2,$3) returning id,email,display_name',
      [email, displayName || email.split('@')[0], hash]
    );
    const user = u.rows[0];
    await query('insert into wallets (user_id, balance_credits) values ($1,$2)', [user.id, 0]);
    await grantCredits(user.id, 10);
    const token = signJwt({ id: user.id, email: user.email, name: user.display_name });
    res.json({ token, user });
  } catch (e) {
    console.error('SIGNUP ERROR:', e.message);
    res.status(500).json({ error: 'signup failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await query('select id,email,display_name,password_hash from users where email=$1', [email]);
    if (!r.rows.length) return res.status(400).json({ error: 'invalid credentials' });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash || '');
    if (!ok) return res.status(400).json({ error: 'invalid credentials' });
    const token = signJwt({ id: u.id, email: u.email, name: u.display_name });
    res.json({ token, user: { id: u.id, email: u.email, display_name: u.display_name } });
  } catch (e) {
    console.error('LOGIN ERROR:', e.message);
    res.status(500).json({ error: 'login failed' });
  }
});

// ---- Wallet & Transactions ----
async function getBalance(userId) {
  const r = await query('select balance_credits from wallets where user_id=$1', [userId]);
  if (!r.rows.length) throw new Error('wallet missing');
  return r.rows[0].balance_credits | 0;
}
async function setBalance(userId, newBal) {
  await query('update wallets set balance_credits=$2, updated_at=now() where user_id=$1', [userId, newBal]);
}
async function addTxn(userId, betId, amount, type) {
  await query('insert into transactions (user_id, bet_id, amount, type) values ($1,$2,$3,$4)',
    [userId, betId, amount, type]);
}
async function grantCredits(userId, amt) {
  const bal = await getBalance(userId);
  await setBalance(userId, bal + amt);
  await addTxn(userId, null, amt, 'GRANT');
}

app.get('/wallet', auth, async (req, res) => {
  try {
    const bal = await getBalance(req.user.id);
    const tx = await query(
      'select id, amount, type, ts from transactions where user_id=$1 order by ts desc limit 20', [req.user.id]
    );
    res.json({ balance: bal, transactions: tx.rows });
  } catch (e) {
    console.error('WALLET ERROR:', e.message);
    res.status(500).json({ error: 'wallet failed' });
  }
});

// ---- Bot lines ----
function preLine() {
  const lines = [
    "Son, that’s a JV bet.",
    "You sure you wanna step on this field?",
    "I’ve seen walk-ons with more nerve."
  ];
  return lines[Math.floor(Math.random() * lines.length)];
}
function postWin() {
  const lines = [
    "Told ya. Hit the sleds.",
    "That’s why they call me Coach.",
    "Film study’s at 5am. Be early."
  ];
  return lines[Math.floor(Math.random() * lines.length)];
}
function postLose() {
  const lines = [
    "Even Saban drops one.",
    "You got me this time, champ.",
    "We’ll fix it in practice."
  ];
  return lines[Math.floor(Math.random() * lines.length)];
}

// ---- Escrow helpers ----
async function escrow(userId, betId, stake) {
  const bal = await getBalance(userId);
  if (bal < stake) throw new Error('insufficient credits');
  await setBalance(userId, bal - stake);
  await addTxn(userId, betId, -stake, 'ESCROW');
}
async function release(userId, betId, amount) {
  const bal = await getBalance(userId);
  await setBalance(userId, bal + amount);
  await addTxn(userId, betId, amount, 'RELEASE');
}

// ---- Bets ----
// status: PENDING -> ACCEPTED -> RESOLVED (or CANCELLED)
app.post('/bets', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { sport, market, sideCreator, stake, opponentId, botType } = req.body;
    if (!sport || !market || !stake) return res.status(400).json({ error: 'missing fields' });

    await client.query('begin');
    const betIns = await client.query(
      `insert into bets (creator_id, opponent_id, bot_type, sport, market, side_creator, stake, status)
       values ($1,$2,$3,$4,$5,$6,$7,'PENDING') returning id`,
      [req.user.id, opponentId || null, botType || null, sport, market, sideCreator || 'A', stake | 0]
    );
    const betId = betIns.rows[0].id;

    await escrow(req.user.id, betId, stake | 0);
    await client.query('insert into bet_events (bet_id, actor_id, action) values ($1,$2,$3)',
      [betId, req.user.id, 'CREATED']);

    let botLine;
    if (botType) {
      const botId = await ensureBotAccount();
      const sideOpp = (sideCreator || 'A') === 'A' ? 'B' : 'A';
      await escrow(botId, betId, stake | 0);
      await client.query(
        'update bets set opponent_id=$1, side_opponent=$2, status=$3 where id=$4',
        [botId, sideOpp, 'ACCEPTED', betId]
      );
      await client.query('insert into bet_events (bet_id, actor_id, action) values ($1,$2,$3)',
        [betId, botId, 'ACCEPTED']);
      botLine = preLine();
    }

    await client.query('commit');
    res.json({ id: betId, status: botType ? 'ACCEPTED' : 'PENDING', botLine });
  } catch (e) {
    await pool.query('rollback');
    console.error('CREATE BET ERROR:', e.message);
    res.status(500).json({ error: 'create bet failed' });
  } finally {
    client.release();
  }
});

app.get('/bets', auth, async (req, res) => {
  try {
    const r = await query(
      `select b.*,
              (b.creator_id = $1) as is_creator,
              (b.status='ACCEPTED' and (b.creator_id=$1 or b.opponent_id=$1)) as can_resolve
       from bets b
       where (b.creator_id=$1 or b.opponent_id=$1 or b.status='PENDING')
       order by b.created_at desc
       limit 50`, [req.user.id]
    );
    res.json(r.rows);
  } catch (e) {
    console.error('LIST BETS ERROR:', e.message);
    res.status(500).json({ error: 'list bets failed' });
  }
});

app.post('/bets/:id/accept', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    await client.query('begin');
    const r = await client.query('select * from bets where id=$1 for update', [id]);
    if (!r.rows.length) return res.status(404).json({ error: 'bet not found' });
    const bet = r.rows[0];
    if (bet.status !== 'PENDING') return res.status(400).json({ error: 'not pending' });
    if (bet.creator_id === req.user.id) return res.status(400).json({ error: 'creator cannot accept' });

    await escrow(req.user.id, id, bet.stake | 0);
    await client.query('update bets set opponent_id=$1, side_opponent=$2, status=$3 where id=$4',
      [req.user.id, bet.side_creator === 'A' ? 'B' : 'A', 'ACCEPTED', id]);
    await client.query('insert into bet_events (bet_id, actor_id, action) values ($1,$2,$3)',
      [id, req.user.id, 'ACCEPTED']);

    await client.query('commit');
    res.json({ ok: true });
  } catch (e) {
    await client.query('rollback');
    console.error('ACCEPT ERROR:', e.message);
    res.status(500).json({ error: 'accept failed' });
  } finally {
    client.release();
  }
});

app.post('/bets/:id/resolve', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { winner } = req.body; // 'CREATOR' | 'OPPONENT'
    if (!['CREATOR', 'OPPONENT'].includes(winner)) return res.status(400).json({ error: 'bad winner' });

    await client.query('begin');
    const r = await client.query('select * from bets where id=$1 for update', [id]);
    if (!r.rows.length) return res.status(404).json({ error: 'bet not found' });
    const bet = r.rows[0];
    if (bet.status !== 'ACCEPTED') return res.status(400).json({ error: 'not accepted' });

    const creatorId = bet.creator_id;
    const opponentId = bet.opponent_id; // <-- correct
    const stake = bet.stake | 0;

    const winnerId = (winner === 'CREATOR') ? creatorId : opponentId;
    await release(winnerId, id, stake * 2);

    await client.query('update bets set status=$1 where id=$2', ['RESOLVED', id]);
    await client.query('insert into bet_events (bet_id, actor_id, action, meta) values ($1,$2,$3,$4)',
      [id, req.user.id, 'RESOLVED', JSON.stringify({ winner })]);

    // bot post-line
    let line = null;
    if (bet.bot_type && opponentId) {
      const botUser = await query('select email from users where id=$1', [opponentId]);
      const isBot = (botUser.rows[0]?.email === 'bot@bet.app');
      if (isBot) line = (winner === 'CREATOR') ? postLose() : postWin();
    }

    await client.query('commit');
    res.json({ ok: true, botLine: line });
  } catch (e) {
    await client.query('rollback');
    console.error('RESOLVE ERROR:', e.message);
    res.status(500).json({ error: 'resolve failed' });
  } finally {
    client.release();
  }
});

// ---- Boot ----
ensureBotAccount()
  .then(() => {
    app.listen(PORT, () => console.log(`Bet! API listening on ${PORT}`));
  })
  .catch((e) => {
    console.error('FATAL during boot:', e.message);
    process.exit(1);
  });
