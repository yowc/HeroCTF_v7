const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const morgan = require('morgan');
const expressLayouts = require('express-ejs-layouts');

const { initDb } = require('./db');
const authRouter = require('./routes/auth');
const filesRouter = require('./routes/files');
const cloneRouter = require('./routes/clone');

const app = express();

app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const dbHost = process.env.DB_HOST || '127.0.0.1';
const dbPort = parseInt(process.env.DB_PORT || '3306', 10);
const dbUser = process.env.DB_USER || 'root';
const dbPassword = process.env.DB_PASSWORD || '';
const dbName = process.env.DB_NAME || 'evilcloner_db';

const sessionStore = new MySQLStore({
  host: dbHost,
  port: dbPort,
  user: dbUser,
  password: dbPassword,
  database: dbName,
  createDatabaseTable: true
});

app.use(session({
  store: sessionStore,
  secret: crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', 'layout');

app.use('/public', express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

app.use('/', authRouter);
app.use('/files', filesRouter);
app.use('/clone', cloneRouter);

app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/clone');
  res.redirect('/login');
});

app.use((_, res) => {
  res.status(404).render('404');
});

(async () => {
  await initDb();
  app.listen(3000, () => console.log(`App running at http://localhost:3000`));
})();

module.exports = app;
