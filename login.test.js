const test = require('node:test');
const assert = require('node:assert/strict');
const { app, db } = require('./server.js');

function onceServer() {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const { port } = server.address();
      resolve({ server, port });
    });
  });
}

test('login com credenciais válidas', async () => {
  const { server, port } = await onceServer();

  try {
    const response = await fetch(`http://localhost:${port}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@bninvesting.com', senha: '123456' })
    });

    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.equal(data.user.name, 'Administrador');
    assert.equal(data.user.isAdmin, true);
  } finally {
    server.close();
  }
});

test('login com credenciais inválidas', async () => {
  const { server, port } = await onceServer();

  try {
    const response = await fetch(`http://localhost:${port}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@bninvesting.com', senha: 'senhaerrada' })
    });

    const data = await response.json();

    assert.equal(response.status, 401);
    assert.equal(data.success, false);
    assert.match(data.message, /inválidos|incorreta/i);
  } finally {
    server.close();
  }
});

test('admin exige autenticação', async () => {
  const { server, port } = await onceServer();

  try {
    const response = await fetch(`http://localhost:${port}/api/admin`);
    const data = await response.json();

    assert.equal(response.status, 401);
    assert.equal(data.success, false);
    assert.match(data.message, /sessão|autentic/i);
  } finally {
    server.close();
  }
});

test('contato exige autenticação', async () => {
  const { server, port } = await onceServer();

  try {
    const response = await fetch(`http://localhost:${port}/api/contact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nome: 'Maria',
        telefone: '(11) 99999-8888',
        email: 'maria@email.com',
        assunto: 'Projeto',
        mensagem: 'Preciso de ajuda com presença digital.'
      })
    });

    const data = await response.json();

    assert.equal(response.status, 401);
    assert.equal(data.success, false);
    assert.match(data.message, /sessão|autentic/i);
  } finally {
    server.close();
  }
});

test('admin consegue listar mensagens e clientes', async () => {
  const { server, port } = await onceServer();
  const realEmail = `cliente${Date.now()}@real.com`;

  try {
    const loginResponse = await fetch(`http://localhost:${port}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@bninvesting.com', senha: '123456' })
    });

    const loginData = await loginResponse.json();
    assert.equal(loginResponse.status, 200);
    assert.equal(loginData.success, true);

    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
        ['Cliente Real', realEmail, 'fakehash', 0],
        (err) => (err ? reject(err) : resolve())
      );
    });

    const createResponse = await fetch(`http://localhost:${port}/api/contact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${loginData.user.token}`
      },
      body: JSON.stringify({
        nome: 'Maria',
        telefone: '(11) 99999-8888',
        email: 'maria@email.com',
        assunto: 'Projeto',
        mensagem: 'Preciso de ajuda com presença digital.'
      })
    });

    const createData = await createResponse.json();
    assert.equal(createResponse.status, 200);
    assert.equal(createData.success, true);

    const adminResponse = await fetch(`http://localhost:${port}/api/admin`, {
      headers: {
        Authorization: `Bearer ${loginData.user.token}`
      }
    });
    const adminData = await adminResponse.json();

    assert.equal(adminResponse.status, 200);
    assert.equal(Array.isArray(adminData.messages), true);
    assert.equal(Array.isArray(adminData.clients), true);
    assert.equal(adminData.messages.some((item) => item.email === 'maria@email.com'), true);
    assert.equal(adminData.clients.some((item) => item.email === realEmail), true);
  } finally {
    server.close();
  }
});

test('admin filtra mensagens e clientes falsos', async () => {
  const { server, port } = await onceServer();

  try {
    const loginResponse = await fetch(`http://localhost:${port}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@bninvesting.com', senha: '123456' })
    });

    const loginData = await loginResponse.json();
    assert.equal(loginResponse.status, 200);

    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
        ['Pedro', 'pedro@teste.com', 'fakehash', 0],
        (err) => (err ? reject(err) : resolve())
      );
    });

    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO orders (nome, telefone, email, assunto, mensagem, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        ['Pedro', '(11) 99999-9999', 'pedro@teste.com', 'Teste', 'Mensagem falsa de teste', new Date().toISOString()],
        (err) => (err ? reject(err) : resolve())
      );
    });

    const adminResponse = await fetch(`http://localhost:${port}/api/admin`, {
      headers: { Authorization: `Bearer ${loginData.user.token}` }
    });
    const adminData = await adminResponse.json();

    assert.equal(adminResponse.status, 200);
    assert.equal(adminData.messages.some((item) => /pedro|@teste.com/i.test(item.email || item.nome || '')), false);
    assert.equal(adminData.clients.some((item) => /pedro|@teste.com/i.test(item.email || item.name || '')), false);
  } finally {
    server.close();
  }
});

test('cadastro cria usuário e permite login', async () => {
  const { server, port } = await onceServer();
  const uniqueEmail = `pedro${Date.now()}@teste.com`;

  try {
    const registerResponse = await fetch(`http://localhost:${port}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nome: 'Pedro',
        email: uniqueEmail,
        senha: '123456',
        confirmarSenha: '123456'
      })
    });

    const registerData = await registerResponse.json();
    assert.equal(registerResponse.status, 200);
    assert.equal(registerData.success, true);
    assert.equal(registerData.user.name, 'Pedro');

    const loginResponse = await fetch(`http://localhost:${port}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: uniqueEmail, senha: '123456' })
    });

    const loginData = await loginResponse.json();
    assert.equal(loginResponse.status, 200);
    assert.equal(loginData.success, true);
    assert.equal(loginData.user.email, uniqueEmail);
  } finally {
    server.close();
  }
});

test('cadastro rejeita nome e e-mail inválidos', async () => {
  const { server, port } = await onceServer();

  try {
    const response = await fetch(`http://localhost:${port}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nome: 'A',
        email: 'email-invalido',
        senha: '123456',
        confirmarSenha: '123456'
      })
    });

    const data = await response.json();
    assert.equal(response.status, 400);
    assert.equal(data.success, false);
    assert.match(data.message, /nome|e-mail|inválid/i);
  } finally {
    server.close();
  }
});

test('sessão via cookie retorna usuário autenticado', async () => {
  const { server, port } = await onceServer();

  try {
    const loginResponse = await fetch(`http://localhost:${port}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@bninvesting.com', senha: '123456' })
    });

    const loginData = await loginResponse.json();
    assert.equal(loginResponse.status, 200);

    const sessionResponse = await fetch(`http://localhost:${port}/api/session`, {
      headers: {
        Cookie: `bn_session=${loginData.user.token}`
      }
    });
    const sessionData = await sessionResponse.json();

    assert.equal(sessionResponse.status, 200);
    assert.equal(sessionData.success, true);
    assert.equal(sessionData.user.email, 'admin@bninvesting.com');
  } finally {
    server.close();
  }
});

test('logout revoga a sessão', async () => {
  const { server, port } = await onceServer();

  try {
    const loginResponse = await fetch(`http://localhost:${port}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@bninvesting.com', senha: '123456' })
    });

    const loginData = await loginResponse.json();
    assert.equal(loginResponse.status, 200);

    const logoutResponse = await fetch(`http://localhost:${port}/api/logout`, {
      method: 'POST',
      headers: {
        Cookie: `bn_session=${loginData.user.token}`
      }
    });
    const logoutData = await logoutResponse.json();

    assert.equal(logoutResponse.status, 200);
    assert.equal(logoutData.success, true);

    const sessionResponse = await fetch(`http://localhost:${port}/api/session`, {
      headers: {
        Cookie: `bn_session=${loginData.user.token}`
      }
    });
    const sessionData = await sessionResponse.json();

    assert.equal(sessionResponse.status, 401);
    assert.equal(sessionData.success, false);
  } finally {
    server.close();
  }
});
