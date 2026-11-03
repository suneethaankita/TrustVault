const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { run, get, all, logAuditEvent } = require('../database');
const { JWT_SECRET } = require('../middleware/auth');

// Register a new user
async function register(req, res) {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    // Role validation: defaults to VIEWER if not specified
    const assignedRole = ['OWNER', 'VIEWER'].includes(role) ? role : 'VIEWER';

    // Password strength check
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    // Check if user already exists
    const existing = await get('SELECT id FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const userId = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    await run(
      'INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, name.trim(), email.toLowerCase().trim(), passwordHash, assignedRole, now]
    );

    await logAuditEvent({
      actor_id: userId,
      actor_name: name.trim(),
      actor_email: email.toLowerCase().trim(),
      action: 'USER_REGISTER',
      resource_type: 'USER',
      resource_id: userId,
      resource_name: email.toLowerCase().trim(),
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `User registered with role ${assignedRole}`
    });

    res.status(201).json({
      message: 'Account created successfully. You can now sign in.',
      userId
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Failed to register account.' });
  }
}

// Sign in
async function login(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await get('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);

    if (!user) {
      await logAuditEvent({
        actor_name: 'Unknown User',
        actor_email: email.toLowerCase().trim(),
        action: 'LOGIN_FAILURE',
        resource_type: 'AUTH',
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: 'Attempted login with non-existent email.'
      });

      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      await logAuditEvent({
        actor_id: user.id,
        actor_name: user.name,
        actor_email: user.email,
        action: 'LOGIN_FAILURE',
        resource_type: 'AUTH',
        resource_id: user.id,
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: 'Incorrect password supplied.'
      });

      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    // Set secure HTTP-only cookie
    res.cookie('trustvault_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    await logAuditEvent({
      actor_id: user.id,
      actor_name: user.name,
      actor_email: user.email,
      action: 'LOGIN_SUCCESS',
      resource_type: 'AUTH',
      resource_id: user.id,
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `User signed in successfully with role ${user.role}.`
    });

    res.json({
      message: 'Sign in successful.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error during login.' });
  }
}

// Get current logged-in user profile
async function getCurrentUser(req, res) {
  res.json({ user: req.user });
}

// Sign out
async function logout(req, res) {
  if (req.user) {
    await logAuditEvent({
      actor_id: req.user.id,
      actor_name: req.user.name,
      actor_email: req.user.email,
      action: 'LOGOUT',
      resource_type: 'AUTH',
      resource_id: req.user.id,
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: 'User logged out.'
    });
  }

  res.clearCookie('trustvault_token');
  res.json({ message: 'Signed out successfully.' });
}

// List all users (so document owners can select a named user to grant permissions)
async function listUsers(req, res) {
  try {
    const users = await all(
      'SELECT id, name, email, role FROM users ORDER BY name ASC'
    );
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve users.' });
  }
}

module.exports = {
  register,
  login,
  getCurrentUser,
  logout,
  listUsers
};
