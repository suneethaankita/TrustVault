const jwt = require('jsonwebtoken');
const { get, logAuditEvent } = require('../database');

const JWT_SECRET = process.env.JWT_SECRET || 'trustvault-super-secure-key-2026-snovasys';

// Middleware to authenticate user via JWT (Cookie or Header)
async function authenticateToken(req, res, next) {
  let token = null;

  if (req.cookies && req.cookies.trustvault_token) {
    token = req.cookies.trustvault_token;
  } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.query && req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required. Please sign in.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Always query database for active user state (prevents stale token attacks)
    const user = await get('SELECT id, name, email, role FROM users WHERE id = ?', [decoded.id]);
    if (!user) {
      res.clearCookie('trustvault_token');
      return res.status(401).json({ error: 'User account no longer exists or session is invalid.' });
    }

    req.user = user;
    next();
  } catch (err) {
    res.clearCookie('trustvault_token');
    return res.status(401).json({ error: 'Invalid or expired session. Please sign in again.' });
  }
}

// Middleware to enforce specific roles (ADMIN, OWNER, VIEWER)
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      logAuditEvent({
        actor_id: req.user ? req.user.id : null,
        actor_name: req.user ? req.user.name : 'Unknown',
        actor_email: req.user ? req.user.email : 'unknown',
        action: 'PRIVILEGE_VIOLATION_ATTEMPT',
        resource_type: 'ROUTE',
        resource_id: req.originalUrl,
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: `Role '${req.user ? req.user.role : 'none'}' attempted to access restricted endpoint requiring [${allowedRoles.join(', ')}]`
      });

      return res.status(403).json({
        error: `Access Denied: Insufficient role permissions. Requires one of: ${allowedRoles.join(', ')}`
      });
    }
    next();
  };
}

module.exports = {
  JWT_SECRET,
  authenticateToken,
  requireRole
};
