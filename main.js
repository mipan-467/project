/**
 * main.js
 *
 * Packages you'll need:
 *   npm init -y
 *   npm install express dotenv helmet cors morgan cookie-parser express-rate-limit compression bcryptjs jsonwebtoken express-validator
 *   npm install --save-dev nodemon
 *
 * Start in development:
 *   NODE_ENV=development PORT=3000 JWT_SECRET=your_secret_here nodemon main.js
 *
 * This is a small starter with auth (register / login) using in-memory storage.
 * Replace in-memory store with a real DB in production.
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';
if (!process.env.JWT_SECRET) {
    console.warn('Warning: using default JWT_SECRET. Set JWT_SECRET in production.');
}

// Middlewares
app.use(helmet());
app.use(cors({
    origin: true,
    credentials: true,
}));
app.use(compression());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Basic rate limiter
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api', apiLimiter);

// Root
app.get('/', (req, res) => {
    res.json({ status: 'ok', env: process.env.NODE_ENV || 'development', message: 'API is running' });
});

/**
 * In-memory users store (for example only)
 * user: { id, name, email, passwordHash, createdAt }
 */
const users = [];
let nextUserId = 1;

/**
 * Auth routes
 * POST /api/auth/register  { name, email, password }
 * POST /api/auth/login     { email, password }
 * POST /api/auth/logout    clears cookie
 */

// Register
app.post(
    '/api/auth/register',
    [
        body('name').trim().isLength({ min: 1 }).withMessage('name required'),
        body('email').isEmail().withMessage('valid email required').normalizeEmail(),
        body('password').isLength({ min: 6 }).withMessage('password must be at least 6 chars'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { name, email, password } = req.body;
        const existing = users.find(u => u.email === email);
        if (existing) return res.status(409).json({ error: 'email already in use' });

        const passwordHash = await bcrypt.hash(password, 10);
        const user = { id: nextUserId++, name, email, passwordHash, createdAt: new Date().toISOString() };
        users.push(user);

        const safeUser = { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt };
        res.status(201).json({ user: safeUser });
    }
);

// Login
app.post(
    '/api/auth/login',
    [
        body('email').isEmail().withMessage('valid email required').normalizeEmail(),
        body('password').exists().withMessage('password required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { email, password } = req.body;
        const user = users.find(u => u.email === email);
        if (!user) return res.status(401).json({ error: 'invalid credentials' });

        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) return res.status(401).json({ error: 'invalid credentials' });

        const payload = { id: user.id, email: user.email, name: user.name };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        // set httpOnly cookie and also return token in body
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 60 * 60 * 1000,
        });

        const safeUser = { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt };
        res.json({ token, user: safeUser });
    }
);

// Logout
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ ok: true });
});

// Middleware to protect routes (example)
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = (authHeader.startsWith('Bearer ') && authHeader.slice(7)) || req.cookies.token;
    if (!token) return res.status(401).json({ error: 'unauthenticated' });

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'invalid or expired token' });
    }
}

/**
 * Users routes (example CRUD) - password not returned
 */
const usersRouter = express.Router();

usersRouter.get('/', requireAuth, (req, res) => {
    const safe = users.map(({ passwordHash, ...u }) => u);
    res.json(safe);
});

usersRouter.get('/:id', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const user = users.find(u => u.id === id);
    if (!user) return res.status(404).json({ error: 'user not found' });
    const { passwordHash, ...safe } = user;
    res.json(safe);
});

usersRouter.put('/:id', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const user = users.find(u => u.id === id);
    if (!user) return res.status(404).json({ error: 'user not found' });
    const { name, email } = req.body;
    if (email && users.some(u => u.email === email && u.id !== id)) return res.status(409).json({ error: 'email already in use' });
    if (name) user.name = name;
    if (email) user.email = email;
    const { passwordHash, ...safe } = user;
    res.json(safe);
});

usersRouter.delete('/:id', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const idx = users.findIndex(u => u.id === id);
    if (idx === -1) return res.status(404).json({ error: 'user not found' });
    const [deleted] = users.splice(idx, 1);
    const { passwordHash, ...safe } = deleted;
    res.json(safe);
});

app.use('/api/users', usersRouter);

// Example items router (public)
const itemsRouter = express.Router();
const items = [];

itemsRouter.get('/', (req, res) => res.json(items));
itemsRouter.post('/', (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const item = { id: items.length + 1, name, createdAt: new Date().toISOString() };
    items.push(item);
    res.status(201).json(item);
});
app.use('/api/items', itemsRouter);

// 404
app.use((req, res) => res.status(404).json({ error: 'not_found' }));

// Error handler
app.use((err, req, res, next) => {
    console.error(err);
    const status = err.status || 500;
    res.status(status).json({ error: err.message || 'internal_server_error' });
});

// Start
const server = app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT} (env: ${process.env.NODE_ENV || 'development'})`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down...');
    server.close(() => process.exit(0));
});

module.exports = app;