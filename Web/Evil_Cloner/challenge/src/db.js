const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

const CLONE_DIR = '/tmp/clone_files/';
const PROFILE_DIR = '/tmp/profiles/';

if (!fs.existsSync(CLONE_DIR)) fs.mkdirSync(CLONE_DIR, { recursive: true });
if (!fs.existsSync(PROFILE_DIR)) fs.mkdirSync(PROFILE_DIR, { recursive: true });

const dbConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT, 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

let pool;

async function getPool() {
  if (!pool) {
    pool = mysql.createPool(dbConfig);
  }
  return pool;
}

async function run(sql, params = []) {
  const connection = await getPool();
  const [result] = await connection.execute(sql, params);
  return {
    lastID: (typeof result.insertId === 'number' && result.insertId > 0) ? result.insertId : null,
    changes: result.affectedRows ?? 0
  };
}

async function get(sql, params = []) {
  const connection = await getPool();
  const [rows] = await connection.execute(sql, params);
  return rows[0] || null;
}

async function all(sql, params = []) {
  const connection = await getPool();
  const [rows] = await connection.execute(sql, params);
  return rows || [];
}

async function exec(sql, params = []) {
  const connection = await getPool();
  await connection.query(sql, params);
}

async function query(sql, params = []) {
  const isSelect = /^\s*select/i.test(sql);
  if (isSelect) {
    return all(sql, params);
  }
  const { lastID, changes } = await run(sql, params);
  return { insertId: lastID, affectedRows: changes };
}

const database = { query, exec };

function randomFolderName() {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < 8; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)];
  return s;
}

async function initDb() {
  await getPool();

  await exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      data_dir CHAR(8) NOT NULL UNIQUE,
      clone_dir VARCHAR(255) NOT NULL UNIQUE
    )
  `);

  await exec(`
    CREATE TABLE IF NOT EXISTS logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      entry TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

async function createUser(username, hash) {
  let dir;
  let clone_dir;
  while (true) {
    dir = randomFolderName();
    clone_dir = randomFolderName();
    const exists = await get('SELECT 1 FROM users WHERE data_dir = ? LIMIT 1', [dir]);
    const exists_clone_dir = await get('SELECT 1 FROM users WHERE clone_dir = ? LIMIT 1', [clone_dir]);
    if (!exists && !exists_clone_dir) break;
  }
  const userProfileDir = path.join(PROFILE_DIR, dir);
  fs.mkdirSync(userProfileDir, { recursive: true });
  const userRootClones = path.join(CLONE_DIR, clone_dir);
  fs.mkdirSync(userRootClones, { recursive: true });

  const { lastID } = await run(
    `INSERT INTO users (username, password, data_dir, clone_dir)
     VALUES (?, ?, ?, ?)`,
    [username, hash, dir, userRootClones]
  );

  if (!lastID) {
    return await findUserByUsername(username);
  }

  return await findUserById(lastID);
}

async function findUserByUsername(username) {
  return await get('SELECT * FROM users WHERE username = ? LIMIT 1', [username]);
}

async function findUserById(id) {
  return await get('SELECT * FROM users WHERE id = ? LIMIT 1', [id]);
}

module.exports = { database, initDb, createUser, findUserByUsername, findUserById, getPool };
