const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

app.use(express.static(path.join(__dirname)));
app.use(express.json({ limit: '1mb' }));

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;

  const [salt, hash] = storedHash.split(':');
  if (!salt || !hash) return false;

  const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(derived, 'hex'));
  } catch (error) {
    return false;
  }
}

function runAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function getAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function allAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

const sessions = new Map();
const loginAttempts = new Map();
const siteContent = {
  headline: 'Fale com a BN Investing',
  subtitle: 'Conte-nos sobre sua empresa, seu objetivo e o que você quer transformar. Nossa equipe vai te responder com estratégia, clareza e atenção para o que realmente importa.'
};
const usuarios = [];

async function initializeDatabase() {
  await runAsync(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runAsync(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      telefone TEXT,
      email TEXT NOT NULL,
      assunto TEXT NOT NULL,
      mensagem TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const admin = await getAsync('SELECT id FROM users WHERE email = ?', ['admin@bninvesting.com']);
  if (!admin) {
    await runAsync(
      'INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
      ['Administrador', 'admin@bninvesting.com', hashPassword('123456'), 1]
    );
  }

  await runAsync(
    `DELETE FROM orders
     WHERE LOWER(nome) = 'cliente'
        OR LOWER(nome) = 'pedro'
        OR LOWER(nome) = 'maria'
        OR LOWER(nome) LIKE 'pedro%'
        OR LOWER(email) = 'maria@email.com'
        OR LOWER(email) LIKE 'pedro%'
        OR LOWER(email) LIKE '%@teste.com'`
  );

  await runAsync(
    `DELETE FROM users
     WHERE is_admin = 0
       AND (
         LOWER(email) = LOWER(?)
         OR LOWER(name) = 'cliente'
         OR LOWER(name) = 'pedro'
         OR LOWER(name) = 'maria'
         OR LOWER(name) LIKE 'pedro%'
         OR LOWER(email) = 'maria@email.com'
         OR LOWER(email) LIKE 'pedro%'
         OR LOWER(email) LIKE '%@teste.com'
       )`,
    ['cliente@bninvesting.com']
  );
}

const dbReady = initializeDatabase();

app.use(async (req, res, next) => {
  try {
    await dbReady;
    next();
  } catch (error) {
    next(error);
  }
});

function normalizarTexto(valor) {
  return String(valor ?? '').trim();
}

function isDemoValue(valor) {
  const texto = normalizarTexto(valor).toLowerCase();
  if (!texto) return false;

  return (
    texto === 'cliente' ||
    texto === 'pedro' ||
    texto === 'maria' ||
    texto === 'maria@email.com' ||
    texto.includes('pedro') ||
    texto.includes('@teste.com') ||
    texto.includes('teste') ||
    texto.includes('maria@email.com')
  );
}

function validarEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function criarToken() {
  return `bn_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function getBearerToken(req) {
  const auth = req.headers.authorization || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function getSessionToken(req) {
  const bearerToken = getBearerToken(req);
  if (bearerToken) return bearerToken;

  const cookies = req.headers.cookie || '';
  const match = cookies
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith('bn_session='));

  return match ? decodeURIComponent(match.slice('bn_session='.length)) : null;
}

function requireAuth(req, res, next) {
  const token = getSessionToken(req);
  const session = token ? sessions.get(token) : null;

  if (!session || session.expiresAt <= Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({
      success: false,
      message: 'Sessão inválida ou expirada. Faça login novamente.'
    });
  }

  req.user = { ...session };
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({
      success: false,
      message: 'Acesso restrito ao administrador.'
    });
  }

  next();
}

function getClientIp(req) {
  return (
    req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

function applyLoginRateLimit(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || [];
  const recentAttempts = attempts.filter((ts) => ts > now - 15 * 60 * 1000);

  if (recentAttempts.length >= 5) {
    return res.status(429).json({
      success: false,
      message: 'Muitas tentativas de login. Tente novamente mais tarde.'
    });
  }

  next();
}

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get(/^\/(?:index|servicos|faleconosco|termos)\.html$/, (req, res) => {
  const target = req.path.replace(/^\//, '');
  const filePath = path.join(__dirname, target);
  return res.sendFile(filePath);
});

app.get('/api/session', requireAuth, (req, res) => {
  return res.status(200).json({
    success: true,
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      isAdmin: Boolean(req.user.isAdmin)
    }
  });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);

  res.clearCookie('bn_session', { path: '/' });
  return res.status(200).json({
    success: true,
    message: 'Sessão encerrada com sucesso.'
  });
});

app.get('/api/admin', requireAuth, requireAdmin, async (_req, res) => {
  try {
    const messages = (await allAsync(`
      SELECT id, nome, email, assunto, mensagem, telefone, created_at as criadoEm
      FROM orders
      ORDER BY id DESC
      LIMIT 20
    `)).filter((item) => !isDemoValue(item.nome) && !isDemoValue(item.email));

    const clients = (await allAsync(`
      SELECT id, name, email, is_admin as isAdmin
      FROM users
      WHERE is_admin = 0
      ORDER BY id ASC
    `)).filter((user) => !isDemoValue(user.name) && !isDemoValue(user.email));

    return res.status(200).json({
      success: true,
      messages: messages.map((item) => ({
        id: item.id,
        nome: item.nome,
        email: item.email,
        assunto: item.assunto,
        mensagem: item.mensagem,
        telefone: item.telefone || '',
        criadoEm: item.criadoEm
      })),
      clients: clients.map((user) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.isAdmin ? 'administrador' : 'cliente'
      })),
      content: { ...siteContent }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao carregar painel administrativo.'
    });
  }
});

app.post('/api/contact', requireAuth, async (req, res) => {
  const nome = normalizarTexto(req.body?.nome);
  const telefone = normalizarTexto(req.body?.telefone);
  const email = normalizarTexto(req.body?.email || req.body?.emailContato).toLowerCase();
  const assunto = normalizarTexto(req.body?.assunto);
  const mensagem = normalizarTexto(req.body?.mensagem);

  if (!nome || !email || !assunto || !mensagem) {
    return res.status(400).json({
      success: false,
      message: 'Preencha nome, e-mail, assunto e mensagem.'
    });
  }

  try {
    const item = {
      id: Date.now(),
      nome,
      telefone,
      email,
      assunto,
      mensagem,
      criadoEm: new Date().toISOString()
    };

    await runAsync(
      'INSERT INTO orders (nome, telefone, email, assunto, mensagem, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [nome, telefone, email, assunto, mensagem, item.criadoEm]
    );

    return res.status(200).json({
      success: true,
      message: 'Mensagem enviada com sucesso!',
      item
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao salvar a mensagem.'
    });
  }
});

app.put('/api/site-content', requireAuth, requireAdmin, (req, res) => {
  const headline = normalizarTexto(req.body?.headline);
  const subtitle = normalizarTexto(req.body?.subtitle);

  if (headline) siteContent.headline = headline;
  if (subtitle) siteContent.subtitle = subtitle;

  return res.status(200).json({
    success: true,
    content: { ...siteContent }
  });
});

app.post('/register', async (req, res) => {
  const nome = normalizarTexto(req.body?.nome);
  const email = normalizarTexto(req.body?.email || req.body?.emailContato).toLowerCase();
  const senha = String(req.body?.senha || '').trim();
  const confirmarSenha = String(req.body?.confirmarSenha || '').trim();

  if (!nome || nome.length < 2) {
    return res.status(400).json({
      success: false,
      message: 'Informe um nome válido com pelo menos 2 caracteres.'
    });
  }

  if (!email || !validarEmail(email)) {
    return res.status(400).json({
      success: false,
      message: 'Informe um e-mail válido.'
    });
  }

  if (!senha || !confirmarSenha) {
    return res.status(400).json({
      success: false,
      message: 'Preencha a senha e a confirmação.'
    });
  }

  if (senha.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'A senha deve ter pelo menos 6 caracteres.'
    });
  }

  if (senha !== confirmarSenha) {
    return res.status(400).json({
      success: false,
      message: 'A confirmação da senha não confere.'
    });
  }

  try {
    const usuarioExistente = await getAsync('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', [email]);
    if (usuarioExistente) {
      return res.status(409).json({
        success: false,
        message: 'Este e-mail já está cadastrado.'
      });
    }

    const result = await runAsync(
      'INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
      [nome, email, hashPassword(senha), 0]
    );

    const token = criarToken();
    sessions.set(token, {
      id: result.id,
      name: nome,
      email,
      isAdmin: false,
      expiresAt: Date.now() + 60 * 60 * 1000
    });

    res.cookie('bn_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60 * 1000
    });

    return res.status(200).json({
      success: true,
      message: 'Cadastro realizado com sucesso!',
      user: {
        id: result.id,
        name: nome,
        email,
        isAdmin: false,
        token
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar usuário.'
    });
  }
});

app.post('/login', applyLoginRateLimit, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const senha = String(req.body?.senha || '').trim();

  if (!email || !senha) {
    return res.status(400).json({
      success: false,
      message: 'Preencha o e-mail e a senha.'
    });
  }

  const ip = getClientIp(req);
  const attempts = loginAttempts.get(ip) || [];
  const recentAttempts = attempts.filter((ts) => ts > Date.now() - 15 * 60 * 1000);

  if (recentAttempts.length >= 5) {
    return res.status(429).json({
      success: false,
      message: 'Muitas tentativas de login. Tente novamente mais tarde.'
    });
  }

  try {
    const usuario = await getAsync('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email]);

    if (!usuario || !verifyPassword(senha, usuario.password_hash)) {
      recentAttempts.push(Date.now());
      loginAttempts.set(ip, recentAttempts);
      return res.status(401).json({
        success: false,
        message: 'E-mail ou senha inválidos.'
      });
    }

    const isAdmin = Boolean(usuario.is_admin);
    const token = criarToken();
    sessions.set(token, {
      id: usuario.id,
      name: usuario.name,
      email: usuario.email,
      isAdmin,
      expiresAt: Date.now() + 60 * 60 * 1000
    });

    loginAttempts.delete(ip);

    res.cookie('bn_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60 * 1000
    });

    return res.status(200).json({
      success: true,
      message: 'Login realizado com sucesso!',
      user: {
        id: usuario.id,
        name: usuario.name,
        email: usuario.email,
        isAdmin,
        token
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao processar o login.'
    });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
  });
}

module.exports = { app, db };
