var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// .wrangler/tmp/bundle-Q0vcA9/checked-fetch.js
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
var urls;
var init_checked_fetch = __esm({
  ".wrangler/tmp/bundle-Q0vcA9/checked-fetch.js"() {
    urls = /* @__PURE__ */ new Set();
    __name(checkURL, "checkURL");
    globalThis.fetch = new Proxy(globalThis.fetch, {
      apply(target, thisArg, argArray) {
        const [request, init] = argArray;
        checkURL(request, init);
        return Reflect.apply(target, thisArg, argArray);
      }
    });
  }
});

// ../lib.deadlight/core/src/auth/errors.js
var JWTError;
var init_errors = __esm({
  "../lib.deadlight/core/src/auth/errors.js"() {
    init_checked_fetch();
    JWTError = class extends Error {
      static {
        __name(this, "JWTError");
      }
      constructor(message, code) {
        super(message);
        this.name = "JWTError";
        this.code = code;
      }
    };
  }
});

// ../lib.deadlight/core/src/auth/jwt.js
var jwt_exports = {};
__export(jwt_exports, {
  createJWT: () => createJWT,
  verifyJWT: () => verifyJWT
});
function base64UrlEncode(arrayBuffer) {
  const uint8Array = new Uint8Array(arrayBuffer);
  let base64String = "";
  for (let i = 0; i < uint8Array.length; i++) {
    base64String += String.fromCharCode(uint8Array[i]);
  }
  return btoa(base64String).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function base64UrlDecode(base64UrlString) {
  const base64String = base64UrlString.replace(/-/g, "+").replace(/_/g, "/").padEnd(base64UrlString.length + (4 - base64UrlString.length % 4) % 4, "=");
  const binaryString = atob(base64String);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}
async function createJWT(payload, secret, options = {}) {
  const encoder = new TextEncoder();
  const now = Math.floor(Date.now() / 1e3);
  const enhancedPayload = {
    ...payload,
    iat: now,
    exp: options.expiresIn ? now + options.expiresIn : now + 3600,
    // default 1 hour
    ...options.issuer && { iss: options.issuer },
    ...options.audience && { aud: options.audience },
    ...options.notBefore && { nbf: now + options.notBefore }
  };
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(enhancedPayload)));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const encodedSignature = base64UrlEncode(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}
async function verifyJWT(token, secret, options = {}) {
  try {
    const encoder = new TextEncoder();
    const now = Math.floor(Date.now() / 1e3);
    const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
    if (!encodedHeader || !encodedPayload || !encodedSignature) {
      throw new JWTError("Invalid token format", "INVALID_FORMAT");
    }
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const data = `${encodedHeader}.${encodedPayload}`;
    const signature = base64UrlDecode(encodedSignature);
    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      encoder.encode(data)
    );
    if (!isValid) {
      throw new JWTError("Invalid token signature", "INVALID_SIGNATURE");
    }
    const decodedPayloadBytes = base64UrlDecode(encodedPayload);
    const decodedPayloadString = new TextDecoder().decode(decodedPayloadBytes);
    const payload = JSON.parse(decodedPayloadString);
    if (payload.exp && payload.exp < now) {
      throw new JWTError("Token has expired", "TOKEN_EXPIRED");
    }
    if (payload.nbf && payload.nbf > now) {
      throw new JWTError("Token not yet valid", "TOKEN_NOT_BEFORE");
    }
    if (options.issuer && payload.iss !== options.issuer) {
      throw new JWTError("Invalid issuer", "INVALID_ISSUER");
    }
    if (options.audience && payload.aud !== options.audience) {
      throw new JWTError("Invalid audience", "INVALID_AUDIENCE");
    }
    return payload;
  } catch (error) {
    if (error instanceof JWTError) {
      throw error;
    }
    throw new JWTError(`JWT verification error: ${error.message}`, "VERIFICATION_ERROR");
  }
}
var init_jwt = __esm({
  "../lib.deadlight/core/src/auth/jwt.js"() {
    init_checked_fetch();
    init_errors();
    __name(base64UrlEncode, "base64UrlEncode");
    __name(base64UrlDecode, "base64UrlDecode");
    __name(createJWT, "createJWT");
    __name(verifyJWT, "verifyJWT");
  }
});

// ../lib.deadlight/core/src/auth/password.js
var password_exports = {};
__export(password_exports, {
  checkAuth: () => checkAuth,
  hashPassword: () => hashPassword,
  verifyPassword: () => verifyPassword
});
async function hashPassword(password, options = {}) {
  const encoder = new TextEncoder();
  const iterations = options.iterations || 1e5;
  const saltLength = options.saltLength || 16;
  const salt = crypto.getRandomValues(new Uint8Array(saltLength));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
    // Length in bits
  );
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map((b2) => b2.toString(16).padStart(2, "0")).join("");
  const saltHex = Array.from(salt).map((b2) => b2.toString(16).padStart(2, "0")).join("");
  return { hash: hashHex, salt: saltHex, iterations };
}
async function verifyPassword(password, storedHash, storedSalt, iterations = 1e5) {
  const encoder = new TextEncoder();
  const salt = Uint8Array.from(
    storedSalt.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
  );
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
    // Length in bits
  );
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map((b2) => b2.toString(16).padStart(2, "0")).join("");
  return hashHex === storedHash;
}
async function checkAuth(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const token = cookies.split(";").map((c) => c.trim()).find((c) => c.startsWith("token="))?.split("=")[1];
  if (!token) {
    return null;
  }
  try {
    return await verifyJWT(token, env.JWT_SECRET);
  } catch (error) {
    console.warn("Auth check failed:", error.message);
    return null;
  }
}
var init_password = __esm({
  "../lib.deadlight/core/src/auth/password.js"() {
    init_checked_fetch();
    init_jwt();
    __name(hashPassword, "hashPassword");
    __name(verifyPassword, "verifyPassword");
    __name(checkAuth, "checkAuth");
  }
});

// ../lib.deadlight/core/src/db/base.js
var DatabaseError, BaseModel;
var init_base = __esm({
  "../lib.deadlight/core/src/db/base.js"() {
    init_checked_fetch();
    DatabaseError = class extends Error {
      static {
        __name(this, "DatabaseError");
      }
      constructor(message, code) {
        super(message);
        this.name = "DatabaseError";
        this.code = code;
      }
    };
    BaseModel = class {
      static {
        __name(this, "BaseModel");
      }
      constructor(db) {
        this.db = db;
      }
      async query(sql, params = []) {
        try {
          const stmt = params.length === 0 ? this.db.prepare(sql) : this.db.prepare(sql).bind(...params);
          const result = await stmt.all();
          return result.results || result;
        } catch (error) {
          throw new DatabaseError(`Query failed: ${error.message}`, "QUERY_ERROR");
        }
      }
      async queryFirst(sql, params = []) {
        try {
          const stmt = params.length === 0 ? this.db.prepare(sql) : this.db.prepare(sql).bind(...params);
          const result = await stmt.first();
          return result;
        } catch (error) {
          throw new DatabaseError(`Query failed: ${error.message}`, "QUERY_ERROR");
        }
      }
      async execute(sql, params = []) {
        try {
          const stmt = params.length === 0 ? this.db.prepare(sql) : this.db.prepare(sql).bind(...params);
          const result = await stmt.run();
          return result;
        } catch (error) {
          throw new DatabaseError(`Execute failed: ${error.message}`, "EXECUTE_ERROR");
        }
      }
    };
  }
});

// ../lib.deadlight/core/src/auth/index.js
var init_auth = __esm({
  "../lib.deadlight/core/src/auth/index.js"() {
    init_checked_fetch();
    init_password();
    init_errors();
  }
});

// ../lib.deadlight/core/src/db/models/user.js
var UserModel;
var init_user = __esm({
  "../lib.deadlight/core/src/db/models/user.js"() {
    init_checked_fetch();
    init_base();
    init_auth();
    UserModel = class extends BaseModel {
      static {
        __name(this, "UserModel");
      }
      async create({ username, password, role = "user" }) {
        try {
          const existing = await this.queryFirst(
            "SELECT id FROM users WHERE username = ?",
            [username]
          );
          if (existing) {
            throw new DatabaseError("Username already exists", "DUPLICATE_USER");
          }
          const { hash, salt } = await hashPassword(password);
          const result = await this.execute(
            "INSERT INTO users (username, password, salt, role, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            [username, hash, salt, role]
          );
          return await this.getById(result.meta.last_row_id);
        } catch (error) {
          if (error instanceof DatabaseError) throw error;
          throw new DatabaseError(`Failed to create user: ${error.message}`, "CREATE_ERROR");
        }
      }
      async getById(id) {
        const user = await this.queryFirst(
          "SELECT id, username, role, created_at, last_login FROM users WHERE id = ?",
          [id]
        );
        return user;
      }
      async getByUsername(username) {
        const user = await this.queryFirst(
          "SELECT id, username, role, created_at, last_login FROM users WHERE username = ?",
          [username]
        );
        return user;
      }
      async authenticate(username, password) {
        try {
          const user = await this.queryFirst(
            "SELECT * FROM users WHERE username = ?",
            [username]
          );
          if (!user) {
            return { success: false, error: "USER_NOT_FOUND" };
          }
          const isValid = await verifyPassword(password, user.password, user.salt);
          if (!isValid) {
            return { success: false, error: "INVALID_PASSWORD" };
          }
          const { password: _2, salt: __, ...safeUser } = user;
          return { success: true, user: safeUser };
        } catch (error) {
          return { success: false, error: "DATABASE_ERROR", details: error.message };
        }
      }
      async updateLastLogin(userId) {
        return await this.execute(
          "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
          [userId]
        );
      }
      async changePassword(userId, newPassword) {
        const { hash, salt } = await hashPassword(newPassword);
        return await this.execute(
          "UPDATE users SET password = ?, salt = ? WHERE id = ?",
          [hash, salt, userId]
        );
      }
      async delete(userId) {
        return await this.execute("DELETE FROM users WHERE id = ?", [userId]);
      }
      async list({ limit = 50, offset = 0 } = {}) {
        return await this.query(
          "SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
          [limit, offset]
        );
      }
      async count() {
        const result = await this.queryFirst("SELECT COUNT(*) as total FROM users");
        return result.total;
      }
    };
  }
});

// ../lib.deadlight/core/src/logging/logger.js
var Logger;
var init_logger = __esm({
  "../lib.deadlight/core/src/logging/logger.js"() {
    init_checked_fetch();
    Logger = class {
      static {
        __name(this, "Logger");
      }
      constructor(options = {}) {
        this.context = options.context || "app";
        this.level = options.level || "info";
      }
      info(message, data = {}) {
        this.log("info", message, data);
      }
      warn(message, data = {}) {
        this.log("warn", message, data);
      }
      error(message, data = {}) {
        this.log("error", message, data);
      }
      log(level, message, data) {
        const logEntry = {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          level,
          context: this.context,
          message,
          ...data
        };
        console.log(JSON.stringify(logEntry));
      }
    };
  }
});

// src/config.js
var init_config = __esm({
  "src/config.js"() {
    init_checked_fetch();
  }
});

// src/templates/base.js
function renderTemplate(title, bodyContent, user = null, config2 = null) {
  const siteTitle = config2?.title || "D E A D L I G H T";
  const pageTitle = title === "home" ? siteTitle : `${title} | ${siteTitle}`;
  const authLinks = user ? `
      <a href="/admin/add">Create New Post</a> |
      <a href="/admin">Dashboard</a> |
      <a href="/admin/proxy">Proxy Server</a> |
      <a href="/logout">Logout</a>
      ` : `<a href="/login">Login</a>`;
  return `
    <!DOCTYPE html>
    <html lang="en" data-theme="dark">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${pageTitle}</title>
      <link rel="icon" type="image/x-icon" href="/favicon.ico">
      <link rel="shortcut icon" type="image/x-icon" href="/favicon.ico">
      <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
      <link rel="stylesheet" href="/styles/theme.css">
      <link rel="stylesheet" href="/styles/dark_min.css" id="theme-stylesheet">
    </head>
    <body>
      <header>
        <h1><a href="/">${siteTitle}</a></h1>
        <nav>
          ${authLinks}
          <div class="theme-toggle-container">
            <button id="theme-toggle" class="theme-toggle" aria-label="Toggle theme">
              <span class="theme-icon">\u2735</span>
            </button>
          </div>
        </nav>
      </header>
      ${bodyContent}
      <script>
        document.addEventListener('DOMContentLoaded', () => {
          const themeToggle = document.getElementById('theme-toggle');
          const html = document.documentElement;
          const stylesheet = document.getElementById('theme-stylesheet');
          
          // Load saved theme
          let currentTheme = localStorage.getItem('theme') || 'dark';
          html.setAttribute('data-theme', currentTheme);
          stylesheet.href = '/styles/' + currentTheme + '_min.css';

          // Update theme icon
          const themeIcon = themeToggle.querySelector('.theme-icon');
          themeIcon.textContent = currentTheme === 'dark' ? '\u2667' : '\u25C7';
          
          // Handle theme toggle
          themeToggle.addEventListener('click', () => {
            currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            // Update localStorage
            localStorage.setItem('theme', currentTheme);
            
            // Update HTML attribute
            html.setAttribute('data-theme', currentTheme);
            
            // Update stylesheet
            stylesheet.href = '/styles/' + currentTheme + '_min.css';
            
            // Update icon
            themeIcon.textContent = currentTheme === 'dark' ? '\u2661' : '\u2664';
          });
        });

        // Keyboard navigation for pagination (moved outside of theme toggle)
        document.addEventListener('keydown', (e) => {
          // Don't interfere with form inputs
          if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
          
          if (e.key === 'ArrowLeft') {
            const prevLink = document.querySelector('.pagination-prev');
            if (prevLink && !prevLink.classList.contains('pagination-disabled')) {
              prevLink.click();
            }
          } else if (e.key === 'ArrowRight') {
            const nextLink = document.querySelector('.pagination-next');
            if (nextLink && !nextLink.classList.contains('pagination-disabled')) {
              nextLink.click();
            }
          }
        });
      <\/script>
    </body>
    </html>
  `;
}
var init_base2 = __esm({
  "src/templates/base.js"() {
    init_checked_fetch();
    init_config();
    __name(renderTemplate, "renderTemplate");
  }
});

// src/templates/admin/dashboard.js
var dashboard_exports = {};
__export(dashboard_exports, {
  renderAdminDashboard: () => renderAdminDashboard
});
function renderAdminDashboard(stats, posts, requestStats = [], user, config2 = null) {
  const chartData = requestStats && requestStats.length > 0 ? requestStats.map((day) => ({
    day: new Date(day.day).toLocaleDateString("en-US", { weekday: "short" }),
    requests: day.requests
  })) : [];
  const maxRequests = chartData.length > 0 ? Math.max(...chartData.map((d2) => d2.requests), 1) : 1;
  const content = `
    <div class="container">
      <div class="page-header">
        <h1>Dashboard</h1>
      </div>
      
      <div class="admin-dashboard">
        <!-- Stats Grid -->
        <div class="stats-grid">
          <div class="stat-card">
            <h3>TOTAL POSTS</h3>
            <div class="stat-number">${stats.totalPosts}</div>
          </div>
          <div class="stat-card">
            <h3>TOTAL USERS</h3>
            <div class="stat-number">${stats.totalUsers || 0}</div>
          </div>
          <div class="stat-card">
            <h3>POSTS TODAY</h3>
            <div class="stat-number">${stats.postsToday || 0}</div>
          </div>
          <div class="stat-card">
            <h3>PUBLISHED</h3>
            <div class="stat-number">${stats.publishedPosts || 0}</div>
          </div>
        </div>

        <!-- Quick Actions -->
        <div class="quick-actions">
          <h2>Quick Actions</h2>
          <div class="action-buttons">
            <a href="/admin/add" class="button">Create New Post</a>
            <a href="/admin/users" class="button">Manage Users</a>
            <a href="/admin/settings" class="button">Settings</a>
            <a href="/" class="button">View Blog</a>
          </div>
        </div>

        <!-- Request Chart -->
        ${chartData.length > 0 ? `
          <div class="chart-section">
            <h2>Requests (Last 7 Days)</h2>
            <div class="simple-chart">
              ${chartData.map((data) => `
                <div class="chart-bar" style="--height: ${data.requests / maxRequests * 100}%">
                  <div class="bar"></div>
                  <div class="label">${data.day}</div>
                  <div class="value">${data.requests}</div>
                </div>
              `).join("")}
            </div>
          </div>
        ` : ""}

        <!-- Recent Posts -->
        <div class="recent-posts-section">
          <h2>Recent Posts</h2>
          ${posts.length > 0 ? `
            <table class="data-table">
              <thead>
                <tr>
                  <th>TITLE</th>
                  <th>AUTHOR</th>
                  <th>DATE</th>
                  <th>STATUS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                ${posts.map((post) => `
                  <tr>
                    <td>
                      <a href="/post/${post.slug || post.id}" class="post-title-link">${post.title}</a>
                    </td>
                    <td>${post.author_username || "Unknown"}</td>
                    <td>${new Date(post.created_at).toLocaleDateString()}</td>
                    <td>${post.published ? '<span class="badge">Published</span>' : "Draft"}</td>
                    <td class="action-cell">
                      <a href="/admin/edit/${post.id}" class="button small-button edit-button">Edit</a>
                      <form action="/admin/delete/${post.id}" method="POST" style="display: inline;">
                        <button type="submit" class="button small-button delete-button" 
                                onclick="return confirm('Delete this post?')">Delete</button>
                      </form>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          ` : `
            <div class="empty-state">
              <p>No posts yet.</p>
              <a href="/admin/add" class="button">Create your first post</a>
            </div>
          `}
        </div>
      </div>
    </div>
  `;
  return renderTemplate("Dashboard", content, user, config2);
}
var init_dashboard = __esm({
  "src/templates/admin/dashboard.js"() {
    init_checked_fetch();
    init_base2();
    __name(renderAdminDashboard, "renderAdminDashboard");
  }
});

// src/templates/admin/userManagement.js
var userManagement_exports = {};
__export(userManagement_exports, {
  renderUserManagement: () => renderUserManagement
});
function renderUserManagement(users, currentUser, config2 = null) {
  const content = `
    <div class="user-management">
      <div class="page-header">
        <h1>User Management</h1>
        <a href="/admin/users/add" class="button">Add New User</a>
      </div>
      
      <div class="user-stats">
        <p>Total Users: ${users.length}</p>
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Posts</th>
            <th>Last Active</th>
            <th>Joined</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${users.map((user) => `
            <tr>
              <td>
                <strong>${user.username}</strong>
                ${user.id === currentUser.id ? '<span class="badge">You</span>' : ""}
              </td>
              <td>${user.post_count || 0}</td>
              <td>${user.last_post ? new Date(user.last_post).toLocaleDateString() : "Never"}</td>
              <td>${new Date(user.created_at).toLocaleDateString()}</td>
              <td>
                ${user.id !== currentUser.id ? `
                  <form action="/admin/users/delete/${user.id}" method="POST" style="display: inline;">
                    <button type="submit" class="small-button delete-button" 
                            onclick="return confirm('Delete user ${user.username}? This will delete all their posts.')">
                      Delete
                    </button>
                  </form>
                ` : '<span class="muted">-</span>'}
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>

      <div class="info-box">
        <p><strong>Note:</strong> Deleting a user will delete all their posts. You cannot delete your own account while logged in.</p>
      </div>
    </div>
  `;
  return renderTemplate("User Management", content, currentUser, config2);
}
var init_userManagement = __esm({
  "src/templates/admin/userManagement.js"() {
    init_checked_fetch();
    init_base2();
    __name(renderUserManagement, "renderUserManagement");
  }
});

// src/templates/admin/settings.js
var settings_exports = {};
__export(settings_exports, {
  renderSettings: () => renderSettings
});
function renderSettings(settings, user, config2 = null) {
  const content = `
    <div class="settings-page">
      <h1>Site Settings</h1>
      
      <form method="POST" action="/admin/settings" class="settings-form">
        <div class="settings-grid">
          <div class="setting-group">
            <h3>General Settings</h3>
            
            <div class="setting-item">
              <label for="site_title">Site Title</label>
              <input type="text" id="site_title" name="site_title" 
                     value="${settings.site_title || ""}" required>
              <small>The name of your site, shown in header and page titles</small>
            </div>
            
            <div class="setting-item">
              <label for="site_description">Site Description</label>
              <textarea id="site_description" name="site_description" rows="3">${settings.site_description || ""}</textarea>
              <small>Brief description for SEO and social sharing</small>
            </div>
          </div>

          <div class="setting-group">
            <h3>Display Settings</h3>
            
            <div class="setting-item">
              <label for="posts_per_page">Posts Per Page</label>
              <input type="number" id="posts_per_page" name="posts_per_page" 
                     value="${settings.posts_per_page || 10}" min="1" max="50">
              <small>How many posts to show on the home page</small>
            </div>
            
            <div class="setting-item">
              <label for="date_format">Date Format</label>
              <select id="date_format" name="date_format">
                <option value="M/D/YYYY" ${settings.date_format === "M/D/YYYY" ? "selected" : ""}>M/D/YYYY (12/25/2024)</option>
                <option value="D/M/YYYY" ${settings.date_format === "D/M/YYYY" ? "selected" : ""}>D/M/YYYY (25/12/2024)</option>
                <option value="YYYY-MM-DD" ${settings.date_format === "YYYY-MM-DD" ? "selected" : ""}>YYYY-MM-DD (2024-12-25)</option>
                <option value="MMM D, YYYY" ${settings.date_format === "MMM D, YYYY" ? "selected" : ""}>MMM D, YYYY (Dec 25, 2024)</option>
              </select>
            </div>
            
            <div class="setting-item">
              <label for="timezone">Timezone</label>
              <input type="text" id="timezone" name="timezone" 
                     value="${settings.timezone || "UTC"}" placeholder="UTC">
              <small>Timezone for post timestamps</small>
            </div>
          </div>

          <div class="setting-group">
            <h3>Access Control</h3>
            
          <div class="checkbox-group">
            <label class="checkbox-label">
              <input type="checkbox" name="enable_registration" ${settings.enable_registration ? "checked" : ""}>
              <span>Enable User Registration</span>
            </label>
            <small>Allow visitors to create new accounts (currently placeholder)</small>
          </div>
            
            <div class="checkbox-group">
              <label class="checkbox-label">
                <input type="checkbox" name="require_login_to_read" 
                       ${settings.require_login_to_read ? "checked" : ""}>
                <span>Require Login to Read Posts</span>
              </label>
            </div>
            
            <div class="checkbox-group">
              <label class="checkbox-label">
                <input type="checkbox" name="maintenance_mode" 
                       ${settings.maintenance_mode ? "checked" : ""}>
                <span>Maintenance Mode</span>
              </label>
            </div>
          </div>
        </div>

        <div class="form-actions">
          <button type="submit" class="button primary">Save Settings</button>
          <a href="/admin" class="button secondary">Cancel</a>
        </div>
      </form>
    </div>
  `;
  return renderTemplate("Settings", content, user, config2);
}
var init_settings = __esm({
  "src/templates/admin/settings.js"() {
    init_checked_fetch();
    init_base2();
    __name(renderSettings, "renderSettings");
  }
});

// src/services/proxy.js
var ProxyService2;
var init_proxy = __esm({
  "src/services/proxy.js"() {
    init_checked_fetch();
    ProxyService2 = class {
      static {
        __name(this, "ProxyService");
      }
      constructor(config2) {
        this.baseUrl = config2.PROXY_URL || "http://localhost:8080";
        this.timeout = 8e3;
        this.circuitState = {
          failures: 0,
          lastFailure: null,
          state: "CLOSED",
          // CLOSED, OPEN, HALF_OPEN
          maxFailures: 3,
          resetTimeout: 3e4
          // 30 seconds
        };
        this.statusCache = {
          data: null,
          timestamp: null,
          ttl: 5e3
          // 5 seconds
        };
      }
      // Circuit breaker logic
      isCircuitOpen() {
        if (this.circuitState.state === "OPEN") {
          const timeSinceFailure = Date.now() - this.circuitState.lastFailure;
          if (timeSinceFailure > this.circuitState.resetTimeout) {
            this.circuitState.state = "HALF_OPEN";
            return false;
          }
          return true;
        }
        return false;
      }
      recordSuccess() {
        this.circuitState.failures = 0;
        this.circuitState.state = "CLOSED";
      }
      recordFailure() {
        this.circuitState.failures++;
        this.circuitState.lastFailure = Date.now();
        if (this.circuitState.failures >= this.circuitState.maxFailures) {
          this.circuitState.state = "OPEN";
          console.warn(`Circuit breaker OPEN: ${this.circuitState.failures} consecutive failures`);
        }
      }
      // Enhanced request method with retry and circuit breaker
      async makeRequest(endpoint, options = {}, retries = 2) {
        if (this.isCircuitOpen()) {
          throw new Error("Circuit breaker is OPEN - proxy appears to be down");
        }
        const url = `${this.baseUrl}${endpoint}`;
        for (let attempt = 0; attempt <= retries; attempt++) {
          try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            const response = await fetch(url, {
              signal: controller.signal,
              headers: {
                "Content-Type": "application/json",
                "User-Agent": "Deadlight-Blog/4.0",
                "X-Request-ID": crypto.randomUUID()
                // For debugging
              },
              ...options
            });
            clearTimeout(timeoutId);
            if (!response.ok) {
              const errorText = await response.text().catch(() => "Unknown error");
              throw new Error(`Proxy API error: ${response.status} ${response.statusText} - ${errorText}`);
            }
            this.recordSuccess();
            return await response.json();
          } catch (error) {
            console.error(`Proxy API attempt ${attempt + 1} failed: ${error.message}`);
            if (error.name === "AbortError") {
              error.message = "Proxy request timeout";
            } else if (error.message.includes("fetch is not defined")) {
              error.message = "Network error - check proxy connectivity";
            }
            if (attempt === retries) {
              this.recordFailure();
              throw error;
            }
            await new Promise((resolve) => setTimeout(resolve, Math.pow(2, attempt) * 1e3));
          }
        }
      }
      // Cached health check to prevent excessive calls
      async healthCheck() {
        const now = Date.now();
        if (this.statusCache.data && this.statusCache.timestamp && now - this.statusCache.timestamp < this.statusCache.ttl) {
          return this.statusCache.data;
        }
        try {
          const [blogStatus, emailStatus] = await Promise.allSettled([
            this.getBlogStatus(),
            this.getEmailStatus()
          ]);
          const result = {
            proxy_connected: true,
            blog_api: blogStatus.status === "fulfilled",
            email_api: emailStatus.status === "fulfilled",
            timestamp: (/* @__PURE__ */ new Date()).toISOString(),
            circuit_state: this.circuitState.state,
            failures: this.circuitState.failures
          };
          this.statusCache = {
            data: result,
            timestamp: now
          };
          return result;
        } catch (error) {
          const result = {
            proxy_connected: false,
            error: error.message,
            timestamp: (/* @__PURE__ */ new Date()).toISOString(),
            circuit_state: this.circuitState.state,
            failures: this.circuitState.failures
          };
          this.statusCache = {
            data: result,
            timestamp: now,
            ttl: 2e3
            // Only cache failures for 2 seconds
          };
          return result;
        }
      }
      // Blog API endpoints with better error context
      async getBlogStatus() {
        try {
          return await this.makeRequest("/api/blog/status");
        } catch (error) {
          console.error("Blog status check failed:", error.message);
          throw new Error(`Blog API unavailable: ${error.message}`);
        }
      }
      async publishPost(postData) {
        try {
          return await this.makeRequest("/api/blog/publish", {
            method: "POST",
            body: JSON.stringify(postData)
          });
        } catch (error) {
          console.error("Blog post publish failed:", error.message);
          throw new Error(`Failed to publish post: ${error.message}`);
        }
      }
      // Email API with queue fallback integration
      async sendEmail(emailData) {
        try {
          return await this.makeRequest("/api/email/send", {
            method: "POST",
            body: JSON.stringify(emailData)
          });
        } catch (error) {
          console.error("Email send failed, should queue:", error.message);
          throw new Error(`Email proxy unavailable: ${error.message}`);
        }
      }
      // SMS sending through proxy
      async sendSms(smsData) {
        try {
          return await this.makeRequest("/api/sms/send", {
            method: "POST",
            body: JSON.stringify(smsData)
          });
        } catch (error) {
          console.error("SMS send failed:", error.message);
          throw new Error(`SMS proxy unavailable: ${error.message}`);
        }
      }
      // Federation with retry logic
      async sendFederatedPost(postData) {
        try {
          return await this.makeRequest("/api/federation/send", {
            method: "POST",
            body: JSON.stringify(postData)
          }, 1);
        } catch (error) {
          console.error("Federation send failed:", error.message);
          throw new Error(`Federation unavailable: ${error.message}`);
        }
      }
      // Enhanced federation methods that work with your existing FederationService
      async sendFederationActivity(activityData) {
        try {
          return await this.makeRequest("/api/federation/activity", {
            method: "POST",
            body: JSON.stringify(activityData)
          });
        } catch (error) {
          console.error("Federation activity send failed:", error.message);
          throw new Error(`Federation activity failed: ${error.message}`);
        }
      }
      // IMAP/SMTP bridge status
      async getEmailServerStatus() {
        try {
          const result = await this.makeRequest("/api/email/server-status");
          return {
            imap_connected: result.imap?.connected || false,
            smtp_connected: result.smtp?.connected || false,
            ...result
          };
        } catch (error) {
          return {
            imap_connected: false,
            smtp_connected: false,
            error: error.message
          };
        }
      }
      // Protocol-specific status checks
      async getProtocolStatus() {
        try {
          return await this.makeRequest("/api/protocols/status");
        } catch (error) {
          return {
            http_proxy: false,
            socks_proxy: false,
            error: error.message
          };
        }
      }
      // Get email status (integrates with your existing outbox)
      async getEmailStatus() {
        try {
          const result = await this.makeRequest("/api/email/status");
          return {
            queue_size: result.queue_size || 0,
            last_processed: result.last_processed,
            server_status: result.server_status || "unknown",
            ...result
          };
        } catch (error) {
          return {
            queue_size: 0,
            server_status: "offline",
            error: error.message
          };
        }
      }
      // Utility method to check if proxy is available before queuing operations
      async isProxyAvailable() {
        try {
          const status = await this.healthCheck();
          return status.proxy_connected;
        } catch {
          return false;
        }
      }
      // Method to get current circuit breaker status for debugging
      getCircuitState() {
        return {
          state: this.circuitState.state,
          failures: this.circuitState.failures,
          lastFailure: this.circuitState.lastFailure,
          isOpen: this.isCircuitOpen()
        };
      }
      // Integration with your existing federation trust system
      async verifyFederatedDomain(domain) {
        try {
          return await this.makeRequest("/api/federation/verify", {
            method: "POST",
            body: JSON.stringify({ domain })
          });
        } catch (error) {
          console.error("Domain verification failed:", error.message);
          return { verified: false, error: error.message };
        }
      }
      // Method to trigger queue processing on the proxy side
      async triggerQueueProcessing() {
        try {
          return await this.makeRequest("/api/queue/process", {
            method: "POST"
          });
        } catch (error) {
          console.error("Queue processing trigger failed:", error.message);
          throw error;
        }
      }
    };
  }
});

// src/services/federation.js
var Transport, EmailTransport, HttpTransport, FederationService;
var init_federation = __esm({
  "src/services/federation.js"() {
    init_checked_fetch();
    init_proxy();
    init_logger();
    init_password();
    Transport = class {
      static {
        __name(this, "Transport");
      }
      constructor(config2) {
        this.logger = new Logger({ context: "federation-transport" });
      }
      async send(data) {
        throw new Error("send not implemented");
      }
      async receive(data) {
        throw new Error("receive not implemented");
      }
    };
    EmailTransport = class extends Transport {
      static {
        __name(this, "EmailTransport");
      }
      constructor(proxyService) {
        super();
        this.proxyService = proxyService;
      }
      async send({ post, targetDomains, federationType = "new_post", instanceUrl, domain, signPayload }) {
        const results = [];
        const payload = await this.createFederationPayload(post, federationType, instanceUrl, domain, signPayload);
        for (const targetDomain of targetDomains) {
          try {
            const emailData = {
              to: `blog@${targetDomain}`,
              from: `blog@${domain}`,
              subject: `[Deadlight Federation] ${federationType === "new_post" ? "New Post" : "Discovery"} from ${domain}`,
              body: JSON.stringify(payload, null, 2),
              headers: {
                "X-Deadlight-Type": "federation",
                "X-Deadlight-Version": "1.0",
                "Content-Type": "application/json"
              }
            };
            const result = await this.proxyService.sendEmail(emailData);
            results.push({ domain: targetDomain, success: true, result });
            this.logger.info("Federation email sent", { postId: post?.id, targetDomain });
          } catch (error) {
            results.push({ domain: targetDomain, success: false, error: error.message });
            this.logger.error("Federation email failed", { postId: post?.id, targetDomain, error: error.message });
          }
        }
        return results;
      }
      async receive({ emailData, db, verifySignature }) {
        try {
          const payload = JSON.parse(emailData.body);
          const isValid = await verifySignature(payload);
          if (!isValid) throw new Error("Invalid federation signature");
          switch (payload.federation_type) {
            case "new_post":
              return await this.handleNewPost(payload.payload, emailData, db);
            case "comment":
              return await this.handleComment(payload.payload, emailData, db);
            case "discovery_request":
              return await this.handleDiscoveryRequest(payload.payload, emailData, db);
            case "discovery_response":
              return await this.handleDiscoveryResponse(payload.payload, emailData, db);
            default:
              throw new Error(`Unknown federation type: ${payload.federation_type}`);
          }
        } catch (error) {
          this.logger.error("Failed to process federation email", { from: emailData.from, error: error.message });
          throw error;
        }
      }
      async createFederationPayload(data, type, instanceUrl, domain, signPayload) {
        const payload = {
          deadlight_version: "1.0",
          federation_type: type,
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          payload: data
        };
        payload.signature = await signPayload(payload);
        return payload;
      }
      async handleNewPost(postData, emailData, db) {
        const { post, origin } = postData;
        const trust = await this.getTrustRelationship(origin.domain, db);
        if (!trust) {
          this.logger.warn("Received post from untrusted domain", { domain: origin.domain });
          return { status: "rejected", reason: "untrusted_domain" };
        }
        const existing = await db.prepare(`
      SELECT id FROM posts 
      WHERE federation_metadata LIKE ?
      LIMIT 1
    `).bind(`%"source_url":"${post.source_url}"%`).first();
        if (existing) {
          this.logger.info("Duplicate federated post ignored", { sourceUrl: post.source_url });
          return { status: "duplicate", postId: existing.id };
        }
        const federationMetadata = {
          source_domain: origin.domain,
          source_url: post.source_url,
          original_id: post.id,
          author: post.author,
          received_at: (/* @__PURE__ */ new Date()).toISOString(),
          received_via: "email",
          sender_email: emailData.from
        };
        const insertResult = await db.prepare(`
      INSERT INTO posts 
      (title, content, slug, author_id, created_at, published, 
       post_type, federation_metadata, moderation_status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
          post.title,
          post.content,
          `federated-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          1,
          // System user ID
          post.published_at,
          trust.trust_level === "verified" ? 1 : 0,
          "federated",
          JSON.stringify(federationMetadata),
          trust.trust_level === "verified" ? "approved" : "pending"
        ).run();
        this.logger.info("Federated post created", {
          postId: insertResult.lastRowId,
          sourceDomain: origin.domain,
          status: trust.trust_level === "verified" ? "published" : "pending"
        });
        return { status: "success", postId: insertResult.lastRowId, published: trust.trust_level === "verified" };
      }
      async handleComment(commentData, emailData, db) {
        const { comment, origin } = commentData;
        const trust = await this.getTrustRelationship(origin.domain, db);
        if (!trust) {
          this.logger.warn("Received comment from untrusted domain", { domain: origin.domain });
          return { status: "rejected", reason: "untrusted_domain" };
        }
        const parentPost = await db.prepare(`
      SELECT id, thread_id FROM posts 
      WHERE federation_metadata LIKE ? 
      LIMIT 1
    `).bind(`%"source_url":"${comment.parent_url}"%`).first();
        if (!parentPost) {
          this.logger.warn("Comment parent post not found", { parentUrl: comment.parent_url });
          return { status: "rejected", reason: "parent_not_found" };
        }
        const federationMetadata = {
          source_domain: origin.domain,
          source_url: comment.source_url,
          original_id: comment.id,
          author: comment.author,
          received_at: (/* @__PURE__ */ new Date()).toISOString(),
          received_via: "email",
          sender_email: emailData.from,
          parent_url: comment.parent_url
        };
        const insertResult = await db.prepare(`
      INSERT INTO posts 
      (title, content, slug, author_id, created_at, published, 
       post_type, federation_metadata, moderation_status, parent_id, thread_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
          `Comment on ${comment.parent_url}`,
          comment.content,
          `comment-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          1,
          // System user ID
          comment.published_at,
          trust.trust_level === "verified" ? 1 : 0,
          "comment",
          JSON.stringify(federationMetadata),
          trust.trust_level === "verified" ? "approved" : "pending",
          parentPost.id,
          parentPost.thread_id || parentPost.id
        ).run();
        this.logger.info("Federated comment created", {
          commentId: insertResult.lastRowId,
          sourceDomain: origin.domain,
          parentId: parentPost.id,
          threadId: parentPost.thread_id || parentPost.id
        });
        return { status: "success", commentId: insertResult.lastRowId };
      }
      async handleDiscoveryRequest(requestData, emailData, db, instanceUrl, domain, signPayload) {
        this.logger.info("Handling discovery request", { from: requestData.requesting_domain });
        const responsePayload = await this.createFederationPayload({
          domain,
          public_key: await this.getPublicKey(),
          instance_url: instanceUrl,
          capabilities: ["posts", "comments", "discovery"],
          version: "1.0",
          software: "deadlight"
        }, "discovery_response", instanceUrl, domain, signPayload);
        const emailData2 = {
          to: `blog@${requestData.requesting_domain}`,
          from: `blog@${domain}`,
          subject: `[Deadlight Federation] Discovery Response from ${domain}`,
          body: JSON.stringify(responsePayload, null, 2),
          headers: {
            "X-Deadlight-Type": "federation",
            "X-Deadlight-Version": "1.0",
            "In-Reply-To": emailData.messageId
          }
        };
        await this.proxyService.sendEmail(emailData2);
        return { status: "response_sent" };
      }
      async handleDiscoveryResponse(payload, emailData, db) {
        this.logger.info("Received discovery response", { from: payload.domain });
        await this.establishTrust(payload.domain, payload.public_key, "unverified", db);
        return { status: "processed" };
      }
    };
    HttpTransport = class extends Transport {
      static {
        __name(this, "HttpTransport");
      }
      constructor(baseUrl) {
        super();
        this.baseUrl = baseUrl;
      }
      async send({ post, targetDomains, federationType = "new_post" }) {
        const results = [];
        for (const domain of targetDomains) {
          try {
            const response = await fetch(`https://${domain}/federation/outbox`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ post, federation_type: federationType })
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            results.push({ domain, success: true, result: await response.json() });
            this.logger.info("Federated post sent via HTTP", { postId: post.id, targetDomain: domain });
          } catch (error) {
            results.push({ domain, success: false, error: error.message });
            this.logger.error("Federated post failed via HTTP", { postId: post.id, targetDomain: domain, error: error.message });
          }
        }
        return results;
      }
      async receive({ postData, db }) {
        const keywords = await loadModerationKeywords(db);
        const { status, notes } = checkModeration(postData.content, keywords);
        await db.prepare(`
      INSERT INTO posts
        (source_domain, title, content, author_id, created_at, published,
         post_type, federation_metadata, moderation_status, moderation_notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
          postData.source_domain,
          postData.title,
          postData.content,
          1,
          postData.published_at,
          status === "approved" ? 1 : 0,
          "federated",
          JSON.stringify({ source_url: postData.source_url, source_domain: postData.source_domain }),
          status,
          notes
        ).run();
        return {
          success: true,
          message: status === "pending" ? "Post received and pending moderation" : "Post received and auto-approved"
        };
      }
    };
    FederationService = class {
      static {
        __name(this, "FederationService");
      }
      constructor(env, transportType = "email") {
        this.db = env.DB;
        this.env = env;
        this.logger = new Logger({ context: "federation" });
        this.proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL });
        this.transport = transportType === "email" ? new EmailTransport(this.proxyService) : new HttpTransport(env.SITE_URL || "https://deadlight.boo");
        this.siteUrl = env.SITE_URL || "https://deadlight.boo";
      }
      async getConnectedDomains() {
        const res = await this.db.prepare("SELECT domain, trust_level FROM federation_trust").all();
        return res.results || [];
      }
      async getFederatedPosts(limit = 50) {
        const res = await this.db.prepare(`
      SELECT id, title, content, created_at, federation_metadata
      FROM posts
      WHERE post_type = 'federated'
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(limit).all();
        return (res.results || []).map((row) => {
          const meta = row.federation_metadata ? JSON.parse(row.federation_metadata) : {};
          return {
            id: row.id,
            title: row.title,
            content: row.content,
            author: meta.author || "Unknown",
            source_domain: meta.source_domain,
            source_url: meta.source_url,
            published_at: row.created_at
          };
        });
      }
      async sendFederatedPost(post, targetDomains) {
        return await this.transport.send({
          post,
          targetDomains,
          federationType: "new_post",
          instanceUrl: this.siteUrl,
          domain: this.getDomain(),
          signPayload: this.signPayload.bind(this)
        });
      }
      async sendFederatedComment(comment, targetDomains) {
        return await this.transport.send({
          post: comment,
          targetDomains,
          federationType: "comment",
          instanceUrl: this.siteUrl,
          domain: this.getDomain(),
          signPayload: this.signPayload.bind(this)
        });
      }
      async processIncomingFederation(data) {
        return await this.transport.receive({
          emailData: data,
          db: this.db,
          verifySignature: this.verifyFederationSignature.bind(this)
        });
      }
      async testFederation() {
        const domains = await this.getConnectedDomains();
        const dummy = {
          id: 0,
          title: "Federation Test",
          content: "Hello Fediverse!",
          author: "system",
          published_at: (/* @__PURE__ */ new Date()).toISOString(),
          source_url: this.siteUrl
        };
        this.logger.info("Running federation test", { domains });
        return await this.sendFederatedPost(dummy, [domains[0]?.domain || "example.com"]);
      }
      async syncNetwork() {
        const domains = await this.getConnectedDomains();
        let imported = 0;
        const newPosts = [];
        for (const { domain } of domains) {
          try {
            const outbox = await fetch(`https://${domain}/federation/outbox`);
            const { posts } = await outbox.json();
            for (const post of posts) {
              const res = await this.processIncomingFederation({ post });
              if (res.success) {
                imported++;
                newPosts.push(post);
              }
            }
          } catch (err) {
            this.logger.error("Sync error for domain", { domain, error: err.message });
          }
        }
        return { imported, domains: domains.length, newPosts };
      }
      async discoverDomain(domain) {
        const discoveryPayload = {
          requesting_domain: this.getDomain(),
          public_key: await this.getPublicKey(),
          capabilities: ["posts", "comments", "discovery"]
        };
        return await this.transport.send({
          post: discoveryPayload,
          targetDomains: [domain],
          federationType: "discovery_request",
          instanceUrl: this.siteUrl,
          domain: this.getDomain(),
          signPayload: this.signPayload.bind(this)
        });
      }
      async queueFederatedPost(postId, targetDomains) {
        this.logger.info("Queueing federated post", { postId, domains: targetDomains.length });
        const federationMetadata = {
          target_domains: targetDomains,
          queued_at: (/* @__PURE__ */ new Date()).toISOString(),
          status: "pending",
          retry_count: 0
        };
        await this.db.prepare(`
      UPDATE posts 
      SET federation_pending = 1, federation_metadata = ?, retry_count = 0
      WHERE id = ?
    `).bind(JSON.stringify(federationMetadata), postId).run();
        return { success: true, queued: targetDomains.length };
      }
      async processFederationQueue() {
        this.logger.info("Processing federation queue");
        const pendingPosts = await this.db.prepare(`
      SELECT * FROM posts 
      WHERE federation_pending = 1 
      AND published = 1 
      ORDER BY created_at ASC 
      LIMIT 10
    `).all();
        let processed = 0;
        for (const post of pendingPosts.results || []) {
          try {
            const metadata = JSON.parse(post.federation_metadata || "{}");
            const maxRetries = 3;
            if (metadata.retry_count >= maxRetries) {
              await this.db.prepare(`
            UPDATE posts 
            SET federation_pending = 0, 
                last_error = ?,
                last_attempt = ?
            WHERE id = ?
          `).bind("Max retries exceeded", (/* @__PURE__ */ new Date()).toISOString(), post.id).run();
              this.logger.error("Max retries exceeded for federated post", { postId: post.id });
              continue;
            }
            const results = await this.sendFederatedPost(post, metadata.target_domains);
            metadata.sent_at = (/* @__PURE__ */ new Date()).toISOString();
            metadata.status = "sent";
            metadata.results = results;
            metadata.retry_count = (metadata.retry_count || 0) + 1;
            await this.db.prepare(`
          UPDATE posts 
          SET federation_pending = 0, 
              federation_sent_at = ?,
              federation_metadata = ?,
              retry_count = ?,
              last_attempt = ?
          WHERE id = ?
        `).bind(
              (/* @__PURE__ */ new Date()).toISOString(),
              JSON.stringify(metadata),
              metadata.retry_count,
              (/* @__PURE__ */ new Date()).toISOString(),
              post.id
            ).run();
            processed++;
          } catch (error) {
            const metadata = JSON.parse(post.federation_metadata || "{}");
            metadata.retry_count = (metadata.retry_count || 0) + 1;
            await this.db.prepare(`
          UPDATE posts 
          SET federation_metadata = ?, 
              retry_count = ?,
              last_error = ?,
              last_attempt = ?
          WHERE id = ?
        `).bind(
              JSON.stringify(metadata),
              metadata.retry_count,
              error.message,
              (/* @__PURE__ */ new Date()).toISOString(),
              post.id
            ).run();
            this.logger.error("Failed to send federated post", { postId: post.id, error: error.message });
          }
        }
        return { processed };
      }
      async getTrustRelationship(domain, db = this.db) {
        return await db.prepare("SELECT * FROM federation_trust WHERE domain = ?").bind(domain).first();
      }
      async establishTrust(domain, publicKey, trustLevel = "unverified", db = this.db) {
        const existing = await this.getTrustRelationship(domain, db);
        if (existing) {
          await db.prepare(`
        UPDATE federation_trust 
        SET public_key = ?, trust_level = ?, last_seen = ?
        WHERE domain = ?
      `).bind(publicKey, trustLevel, (/* @__PURE__ */ new Date()).toISOString(), domain).run();
        } else {
          await db.prepare(`
        INSERT INTO federation_trust (domain, public_key, trust_level, last_seen)
        VALUES (?, ?, ?, ?)
      `).bind(domain, publicKey, trustLevel, (/* @__PURE__ */ new Date()).toISOString()).run();
        }
        this.logger.info("Trust relationship established", { domain, trustLevel });
      }
      async sendDeleteComment(commentId, targetDomains) {
        const comment = await this.env.DB.prepare(`
      SELECT p.id, p.content, p.author_id, p.parent_id, p.thread_id, p.created_at, u.username as author
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = ? AND p.post_type = 'comment'
    `).bind(commentId).first();
        if (!comment) {
          this.logger.error("Comment not found for deletion", { commentId });
          return new Response("Comment not found", { status: 404 });
        }
        const activity = {
          "@context": "https://www.w3.org/ns/activitystreams",
          type: "Delete",
          actor: `${this.siteUrl}/user/${comment.author}`,
          object: `${this.siteUrl}/comment/${commentId}`,
          to: targetDomains.map((domain) => `${domain}/inbox`)
        };
        const signature = await this.signActivity(activity);
        for (const domain of targetDomains) {
          await this.sendActivity(activity, signature, domain);
        }
      }
      async sendActivity(activity, signature, domain) {
        const url = `${domain}/inbox`;
        await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/activity+json",
            "Signature": signature
          },
          body: JSON.stringify(activity)
        }).catch((err) => this.logger.error(`Failed to send to ${domain}:`, err));
      }
      async signActivity(activity) {
        const { signature, ...payloadToSign } = activity;
        return await this.signPayload(payloadToSign);
      }
      async verifyFederationSignature(payload) {
        try {
          const { signature, ...payloadToVerify } = payload;
          const payloadString = JSON.stringify(payloadToVerify, Object.keys(payloadToVerify).sort());
          const senderDomain = payload.payload?.origin?.domain || payload.payload?.domain;
          if (!senderDomain) return false;
          const trust = await this.getTrustRelationship(senderDomain);
          if (!trust) return false;
          return await verifyPassword(payloadString, signature, trust.public_key);
        } catch (error) {
          this.logger.error("Signature verification failed", { error: error.message });
          return false;
        }
      }
      async signPayload(payload) {
        const { signature, ...payloadToSign } = payload;
        const payloadString = JSON.stringify(payloadToSign, Object.keys(payloadToSign).sort());
        const privateKey = await this.getPrivateKey();
        const { hash, salt } = await hashPassword(payloadString, privateKey);
        return hash;
      }
      async getPrivateKey() {
        return this.env.FEDERATION_PRIVATE_KEY || "default-key-for-dev";
      }
      async getPublicKey() {
        return this.env.FEDERATION_PUBLIC_KEY || "default-public-key-for-dev";
      }
      getDomain() {
        try {
          return new URL(this.siteUrl).hostname;
        } catch {
          return "deadlight.boo";
        }
      }
      async getThreadedComments(postId, limit = 50) {
        const res = await this.db.prepare(`
      SELECT id, content, author_id, created_at, federation_metadata
      FROM posts
      WHERE post_type = 'comment' AND (parent_id = ? OR thread_id = ?)
      ORDER BY created_at ASC
      LIMIT ?
    `).bind(postId, postId, limit).all();
        return (res.results || []).map((row) => {
          const meta = row.federation_metadata ? JSON.parse(row.federation_metadata) : {};
          return {
            id: row.id,
            content: row.content,
            author: meta.author || "Unknown",
            source_domain: meta.source_domain,
            source_url: meta.source_url,
            published_at: row.created_at
          };
        });
      }
    };
  }
});

// ../lib.deadlight/core/src/db/models/post.js
var PostModel;
var init_post = __esm({
  "../lib.deadlight/core/src/db/models/post.js"() {
    init_checked_fetch();
    init_base();
    PostModel = class extends BaseModel {
      static {
        __name(this, "PostModel");
      }
      // Helper to generate slug from title
      generateSlug(title) {
        return title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 200);
      }
      async create({ title, content, slug, excerpt, author_id, published = false }) {
        try {
          const finalSlug = slug || this.generateSlug(title);
          const existing = await this.queryFirst("SELECT id FROM posts WHERE slug = ?", [finalSlug]);
          if (existing) {
            const uniqueSlug = `${finalSlug}-${Date.now()}`;
            return this.create({ title, content, slug: uniqueSlug, excerpt, author_id, published });
          }
          const result = await this.execute(
            "INSERT INTO posts (title, content, slug, excerpt, author_id, published, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            [title, content, finalSlug, excerpt || null, author_id, published ? 1 : 0]
          );
          return await this.getById(result.meta.last_row_id);
        } catch (error) {
          throw new DatabaseError(`Failed to create post: ${error.message}`, "CREATE_ERROR");
        }
      }
      async getById(id, options = {}) {
        let query = "SELECT posts.*";
        if (options.includeAuthor) {
          query += ", users.username as author_username";
        }
        query += " FROM posts";
        if (options.includeAuthor) {
          query += " LEFT JOIN users ON posts.author_id = users.id";
        }
        query += " WHERE posts.id = ?";
        return await this.queryFirst(query, [id]);
      }
      async getBySlug(slug, options = {}) {
        let query = "SELECT posts.*";
        if (options.includeAuthor) {
          query += ", users.username as author_username";
        }
        query += " FROM posts";
        if (options.includeAuthor) {
          query += " LEFT JOIN users ON posts.author_id = users.id";
        }
        query += " WHERE posts.slug = ?";
        return await this.queryFirst(query, [slug]);
      }
      async update(id, { title, content, slug, excerpt, published }) {
        const updates = [];
        const values = [];
        if (title !== void 0) {
          updates.push("title = ?");
          values.push(title);
        }
        if (content !== void 0) {
          updates.push("content = ?");
          values.push(content);
        }
        if (slug !== void 0) {
          updates.push("slug = ?");
          values.push(slug);
        }
        if (excerpt !== void 0) {
          updates.push("excerpt = ?");
          values.push(excerpt);
        }
        if (published !== void 0) {
          updates.push("published = ?");
          values.push(published ? 1 : 0);
        }
        if (updates.length === 0) {
          throw new DatabaseError("No fields to update", "INVALID_UPDATE");
        }
        updates.push("updated_at = CURRENT_TIMESTAMP");
        values.push(id);
        const result = await this.execute(
          `UPDATE posts SET ${updates.join(", ")} WHERE id = ?`,
          values
        );
        if (result.changes === 0) {
          throw new DatabaseError("Post not found", "NOT_FOUND");
        }
        return await this.getById(id);
      }
      async delete(id) {
        const result = await this.execute("DELETE FROM posts WHERE id = ?", [id]);
        if (result.changes === 0) {
          throw new DatabaseError("Post not found", "NOT_FOUND");
        }
        return { success: true };
      }
      async getPaginated({
        page = 1,
        limit = 10,
        includeAuthor = false,
        orderBy = "created_at",
        orderDirection = "DESC",
        publishedOnly = true
      }) {
        const offset = (page - 1) * limit;
        const whereClause = publishedOnly ? " WHERE posts.published = 1" : "";
        const countResult = await this.queryFirst(`SELECT COUNT(*) as total FROM posts${whereClause}`);
        const totalPosts = countResult.total;
        const totalPages = Math.ceil(totalPosts / limit);
        let query = "SELECT posts.*";
        if (includeAuthor) {
          query += ", users.username as author_username";
        }
        query += " FROM posts";
        if (includeAuthor) {
          query += " LEFT JOIN users ON posts.author_id = users.id";
        }
        query += whereClause;
        query += ` ORDER BY posts.${orderBy} ${orderDirection} LIMIT ? OFFSET ?`;
        const result = await this.query(query, [limit, offset]);
        const pagination2 = {
          currentPage: page,
          totalPages,
          totalPosts,
          postsPerPage: limit,
          hasPrevious: page > 1,
          hasNext: page < totalPages,
          previousPage: page - 1,
          nextPage: page + 1
        };
        return {
          posts: result.results || result,
          pagination: pagination2
        };
      }
      async getNavigation(currentId, publishedOnly = true) {
        const whereClause = publishedOnly ? " AND published = 1" : "";
        return await this.queryFirst(`
      SELECT 
        (SELECT id FROM posts WHERE id < ?${whereClause} ORDER BY id DESC LIMIT 1) as prev_id,
        (SELECT title FROM posts WHERE id < ?${whereClause} ORDER BY id DESC LIMIT 1) as prev_title,
        (SELECT slug FROM posts WHERE id < ?${whereClause} ORDER BY id DESC LIMIT 1) as prev_slug,
        (SELECT id FROM posts WHERE id > ?${whereClause} ORDER BY id ASC LIMIT 1) as next_id,
        (SELECT title FROM posts WHERE id > ?${whereClause} ORDER BY id ASC LIMIT 1) as next_title,
        (SELECT slug FROM posts WHERE id > ?${whereClause} ORDER BY id ASC LIMIT 1) as next_slug
    `, [currentId, currentId, currentId, currentId, currentId, currentId]);
      }
      async getByAuthorId(authorId, options = {}) {
        const { limit = 50, offset = 0, publishedOnly = false } = options;
        let query = "SELECT posts.*";
        if (options.includeAuthor) {
          query += ", users.username as author_username";
        }
        query += " FROM posts";
        if (options.includeAuthor) {
          query += " LEFT JOIN users ON posts.author_id = users.id";
        }
        query += " WHERE posts.author_id = ?";
        if (publishedOnly) {
          query += " AND posts.published = 1";
        }
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
        return await this.query(query, [authorId, limit, offset]);
      }
      async count(publishedOnly = false) {
        const whereClause = publishedOnly ? " WHERE published = 1" : "";
        const result = await this.queryFirst(`SELECT COUNT(*) as total FROM posts${whereClause}`);
        return result.total;
      }
      async togglePublished(id) {
        const result = await this.execute(
          "UPDATE posts SET published = NOT published, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
          [id]
        );
        if (result.changes === 0) {
          throw new DatabaseError("Post not found", "NOT_FOUND");
        }
        return await this.getById(id);
      }
    };
  }
});

// ../lib.deadlight/core/src/db/models/settings.js
var SettingsModel;
var init_settings2 = __esm({
  "../lib.deadlight/core/src/db/models/settings.js"() {
    init_checked_fetch();
    init_base();
    SettingsModel = class extends BaseModel {
      static {
        __name(this, "SettingsModel");
      }
      async get(key, defaultValue = null) {
        try {
          const result = await this.queryFirst("SELECT value, type FROM settings WHERE key = ?", [key]);
          if (!result) return defaultValue;
          return this.convertValue(result.value, result.type);
        } catch (error) {
          throw new DatabaseError(`Failed to get setting ${key}: ${error.message}`, "GET_ERROR");
        }
      }
      async getAll() {
        try {
          const result = await this.query("SELECT key, value, type FROM settings ORDER BY key");
          const results = result.results || result;
          const settings = {};
          results.forEach((row) => {
            settings[row.key] = this.convertValue(row.value, row.type);
          });
          return settings;
        } catch (error) {
          throw new DatabaseError(`Failed to get all settings: ${error.message}`, "GET_ALL_ERROR");
        }
      }
      async set(key, value, type = "string") {
        try {
          const stringValue = String(value);
          await this.execute(
            "INSERT OR REPLACE INTO settings (key, value, type, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            [key, stringValue, type]
          );
          return { key, value, type };
        } catch (error) {
          throw new DatabaseError(`Failed to set setting ${key}: ${error.message}`, "SET_ERROR");
        }
      }
      async delete(key) {
        try {
          const result = await this.execute("DELETE FROM settings WHERE key = ?", [key]);
          if (result.changes === 0) {
            throw new DatabaseError("Setting not found", "NOT_FOUND");
          }
          return { success: true };
        } catch (error) {
          throw new DatabaseError(`Failed to delete setting ${key}: ${error.message}`, "DELETE_ERROR");
        }
      }
      // Added method for getting multiple settings efficiently
      async getMany(keys) {
        try {
          const placeholders = keys.map(() => "?").join(",");
          const result = await this.query(
            `SELECT key, value, type FROM settings WHERE key IN (${placeholders})`,
            keys
          );
          const results = result.results || result;
          const settings = {};
          results.forEach((row) => {
            settings[row.key] = this.convertValue(row.value, row.type);
          });
          return settings;
        } catch (error) {
          throw new DatabaseError(`Failed to get multiple settings: ${error.message}`, "GET_MANY_ERROR");
        }
      }
      convertValue(value, type) {
        switch (type) {
          case "number":
            return parseInt(value);
          case "boolean":
            return value === "true";
          case "float":
            return parseFloat(value);
          default:
            return value;
        }
      }
    };
  }
});

// ../lib.deadlight/core/src/db/models/index.js
var models_exports = {};
__export(models_exports, {
  BaseModel: () => BaseModel,
  DatabaseError: () => DatabaseError,
  PostModel: () => PostModel,
  SettingsModel: () => SettingsModel,
  UserModel: () => UserModel
});
var init_models = __esm({
  "../lib.deadlight/core/src/db/models/index.js"() {
    init_checked_fetch();
    init_user();
    init_post();
    init_settings2();
    init_base();
  }
});

// src/services/config.js
var config_exports = {};
__export(config_exports, {
  configService: () => configService
});
var ConfigService, configService;
var init_config2 = __esm({
  "src/services/config.js"() {
    init_checked_fetch();
    init_models();
    ConfigService = class {
      static {
        __name(this, "ConfigService");
      }
      constructor() {
        this.cache = /* @__PURE__ */ new Map();
        this.cacheExpiry = /* @__PURE__ */ new Map();
        this.CACHE_TTL = 5 * 60 * 1e3;
      }
      async getConfig(db) {
        const cacheKey = "site_config";
        const now = Date.now();
        if (this.cache.has(cacheKey) && this.cacheExpiry.get(cacheKey) > now) {
          return this.cache.get(cacheKey);
        }
        try {
          const settingsModel = new SettingsModel(db);
          const dbSettings = await settingsModel.getAll();
          console.log("Retrieved settings from DB:", dbSettings);
          const config2 = {
            title: dbSettings.site_title || "deadlight.boo",
            description: dbSettings.site_description || "A minimal blog framework",
            postsPerPage: parseInt(dbSettings.posts_per_page) || 10,
            // Ensure it's a number
            dateFormat: dbSettings.date_format || "M/D/YYYY",
            timezone: dbSettings.timezone || "UTC",
            enableRegistration: dbSettings.enable_registration || false,
            requireLoginToRead: dbSettings.require_login_to_read || false,
            maintenanceMode: dbSettings.maintenance_mode || false
          };
          console.log("Final config object:", config2);
          this.cache.set(cacheKey, config2);
          this.cacheExpiry.set(cacheKey, now + this.CACHE_TTL);
          return config2;
        } catch (error) {
          console.error("Error loading config from database:", error);
          return {
            title: "deadlight.boo",
            description: "A minimal blog framework",
            postsPerPage: 10,
            dateFormat: "M/D/YYYY",
            timezone: "UTC",
            enableRegistration: false,
            requireLoginToRead: false,
            maintenanceMode: false
          };
        }
      }
      // Clear cache when settings are updated
      clearCache() {
        this.cache.clear();
        this.cacheExpiry.clear();
      }
      // Get a single setting with caching
      async getSetting(db, key, defaultValue = null) {
        try {
          const settingsModel = new SettingsModel(db);
          return await settingsModel.get(key, defaultValue);
        } catch (error) {
          console.error(`Error getting setting ${key}:`, error);
          return defaultValue;
        }
      }
    };
    configService = new ConfigService();
  }
});

// src/templates/admin/comments.js
var comments_exports = {};
__export(comments_exports, {
  renderAddCommentForm: () => renderAddCommentForm,
  renderCommentList: () => renderCommentList,
  renderReplyForm: () => renderReplyForm
});
function renderCommentList(comments, postId, user, config2) {
  const commentHtml = comments.map((comment, index) => `
    <div class="comment" style="margin-left: ${comment.level * 20}px;">
      <p>${comment.content}</p>
      <p class="post-meta">By ${comment.author} | ${new Date(comment.published_at).toLocaleDateString()}</p>
      ${user ? `
        <div class="comment-actions">
          <a href="/admin/comments/edit/${comment.id}" class="button edit-button">Edit</a>
          <a href="/admin/comments/delete/${comment.id}" class="button delete-button">Delete</a>
          <a href="/admin/comments/reply/${comment.id}" class="button reply-button">Reply</a>
        </div>
      ` : ""}
    </div>
  `).join("");
  return renderTemplate("Comments for Post " + postId, `
    <h1>Comments</h1>
    ${commentHtml || '<p class="no-comments">No comments yet.</p>'}
    ${user ? `<a href="/admin/add-comment/${postId}" class="button">Add Comment</a>` : ""}
  `, user, config2);
}
function renderAddCommentForm(postId, user) {
  return renderTemplate("Add Comment", `
    <h1>Add Comment</h1>
    <form action="/admin/add-comment/${postId}" method="POST">
      <textarea name="content" required placeholder="Write your comment..."></textarea>
      <button type="submit" class="button">Submit</button>
    </form>
  `, user);
}
function renderReplyForm(comment, user) {
  const parentUrl = comment.federation_metadata ? JSON.parse(comment.federation_metadata).parent_url : null;
  return renderTemplate("Reply to Comment", `
    <h1>Reply to Comment</h1>
    <p>Replying to: <a href="${parentUrl}">${comment.content.substring(0, 50)}${comment.content.length > 50 ? "..." : ""}</a></p>
    <form action="/admin/comments/reply/${comment.id}" method="POST">
      <textarea name="content" required placeholder="Write your reply..."></textarea>
      <button type="submit" class="button">Submit Reply</button>
    </form>
    <a href="/admin/comments/${comment.parent_id || comment.thread_id}" class="button">Back to Comments</a>
  `, user);
}
var init_comments = __esm({
  "src/templates/admin/comments.js"() {
    init_checked_fetch();
    init_base2();
    __name(renderCommentList, "renderCommentList");
    __name(renderAddCommentForm, "renderAddCommentForm");
    __name(renderReplyForm, "renderReplyForm");
  }
});

// src/services/outbox.js
var outbox_exports = {};
__export(outbox_exports, {
  OutboxService: () => OutboxService
});
var OutboxService;
var init_outbox = __esm({
  "src/services/outbox.js"() {
    init_checked_fetch();
    init_proxy();
    init_logger();
    init_federation();
    OutboxService = class {
      static {
        __name(this, "OutboxService");
      }
      constructor(env) {
        this.env = env;
        this.logger = new Logger({ context: "outbox" });
        this.proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL });
      }
      // Main queue processing method
      async processQueue() {
        try {
          this.logger.info("Starting outbox queue processing");
          const healthCheck = await this.proxyService.healthCheck();
          if (!healthCheck.proxy_connected) {
            this.logger.info("Proxy offline, keeping operations queued");
            return {
              processed: 0,
              queued: await this.getQueuedCount(),
              status: "proxy_offline",
              message: "Proxy is offline - operations remain queued"
            };
          }
          this.logger.info("Proxy is online, processing queued operations");
          const results = await Promise.allSettled([
            this.processPendingReplies(),
            this.processPendingFederatedPosts()
            // Future: this.processPendingNewsletters(),
            // Future: this.processPendingNotifications(),
          ]);
          const totalProcessed = results.reduce((sum, result) => {
            if (result.status === "fulfilled") {
              return sum + (result.value || 0);
            }
            return sum;
          }, 0);
          results.forEach((result, index) => {
            if (result.status === "rejected") {
              this.logger.error(`Queue processor ${index} failed`, {
                error: result.reason?.message
              });
            }
          });
          const remainingQueued = await this.getQueuedCount();
          this.logger.info("Outbox processing completed", {
            processed: totalProcessed,
            queued: remainingQueued
          });
          return {
            processed: totalProcessed,
            queued: remainingQueued,
            status: "success",
            message: `Successfully processed ${totalProcessed} operations`
          };
        } catch (error) {
          this.logger.error("Outbox processing failed", { error: error.message });
          return {
            processed: 0,
            error: error.message,
            status: "error",
            message: `Processing failed: ${error.message}`
          };
        }
      }
      // Process pending email replies
      async processPendingReplies() {
        this.logger.info("Processing pending email replies");
        const pendingReplies = await this.getPendingReplies();
        let processed = 0;
        for (const reply of pendingReplies) {
          try {
            const metadata = JSON.parse(reply.email_metadata || "{}");
            const emailData = {
              to: metadata.to,
              from: metadata.from || "noreply@deadlight.boo",
              subject: reply.title,
              body: reply.content
            };
            this.logger.info("Sending queued reply", {
              replyId: reply.id,
              to: emailData.to,
              subject: emailData.subject
            });
            const result = await this.proxyService.sendEmail(emailData);
            await this.markReplySent(reply.id, result);
            processed++;
            this.logger.info("Successfully sent queued reply", {
              replyId: reply.id,
              to: emailData.to
            });
          } catch (error) {
            this.logger.error("Failed to send queued reply", {
              replyId: reply.id,
              error: error.message
            });
            await this.incrementRetryCount(reply.id, error.message);
          }
        }
        return processed;
      }
      async queueMessage(type, data) {
        if (type === "email") return this.queueEmailReply(data);
        if (type === "notification") {
          await this.db.prepare(`
            INSERT INTO notifications (user_id, type, content, related_post_id)
            VALUES (?, ?, ?, ?)
            `).bind(data.user_id, data.type, data.content, data.post_id).run();
          return { success: true };
        }
        if (type === "sms") {
          const smsMetadata = { to: data.to, message: data.message, queued_at: (/* @__PURE__ */ new Date()).toISOString() };
          await this.db.prepare(`
                INSERT INTO notifications (user_id, type, content)
                VALUES (?, ?, ?)
            `).bind(data.user_id, "sms", JSON.stringify(smsMetadata)).run();
          return { success: true };
        }
        throw new Error("Unsupported message type");
      }
      // Process federated posts (for decentralized social media)
      async processPendingFederatedPosts() {
        const fedSvc = new FederationService(this.env);
        const { processed } = await fedSvc.processFederationQueue();
        return processed;
      }
      // Database query helpers
      async getPendingReplies() {
        const result = await this.env.DB.prepare(`
            SELECT * FROM posts 
            WHERE is_reply_draft = 1 
            AND email_metadata LIKE '%"sent":false%'
            AND (retry_count IS NULL OR retry_count < 3)
            ORDER BY created_at ASC
            LIMIT 50
        `).all();
        return result.results || [];
      }
      async getPendingFederatedPosts() {
        try {
          const result = await this.env.DB.prepare(`
                SELECT * FROM posts 
                WHERE federation_pending = 1 
                AND published = 1
                ORDER BY created_at ASC
                LIMIT 20
            `).all();
          return result.results || [];
        } catch (error) {
          this.logger.info("Federation columns not found - skipping federated posts");
          return [];
        }
      }
      async markReplySent(replyId, sendResult = null) {
        const reply = await this.env.DB.prepare(
          "SELECT email_metadata FROM posts WHERE id = ?"
        ).bind(replyId).first();
        if (!reply) return;
        const metadata = JSON.parse(reply.email_metadata || "{}");
        metadata.sent = true;
        metadata.date_sent = (/* @__PURE__ */ new Date()).toISOString();
        metadata.send_result = sendResult;
        await this.env.DB.prepare(`
            UPDATE posts 
            SET email_metadata = ?, updated_at = ? 
            WHERE id = ?
        `).bind(
          JSON.stringify(metadata),
          (/* @__PURE__ */ new Date()).toISOString(),
          replyId
        ).run();
      }
      async markFederationSent(postId) {
        try {
          await this.env.DB.prepare(`
                UPDATE posts 
                SET federation_pending = 0, federation_sent_at = ? 
                WHERE id = ?
            `).bind((/* @__PURE__ */ new Date()).toISOString(), postId).run();
        } catch (error) {
          this.logger.info("Federation columns not found - skipping federation update");
        }
      }
      async incrementRetryCount(replyId, errorMessage) {
        try {
          await this.env.DB.prepare(`
                ALTER TABLE posts ADD COLUMN retry_count INTEGER DEFAULT 0
            `).run().catch(() => {
          });
          await this.env.DB.prepare(`
                UPDATE posts 
                SET retry_count = COALESCE(retry_count, 0) + 1,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
            `).bind(errorMessage, (/* @__PURE__ */ new Date()).toISOString(), replyId).run();
        } catch (error) {
          this.logger.error("Failed to update retry count", { error: error.message });
        }
      }
      async getQueuedCount() {
        try {
          const replies = await this.env.DB.prepare(`
                SELECT COUNT(*) as count FROM posts 
                WHERE is_reply_draft = 1 
                AND email_metadata LIKE '%"sent":false%'
                AND (retry_count IS NULL OR retry_count < 3)
            `).first();
          let federatedCount = 0;
          try {
            const federated = await this.env.DB.prepare(`
                    SELECT COUNT(*) as count FROM posts 
                    WHERE federation_pending = 1 
                    AND published = 1
                `).first();
            federatedCount = federated?.count || 0;
          } catch (error) {
            federatedCount = 0;
          }
          return (replies?.count || 0) + federatedCount;
        } catch (error) {
          this.logger.error("Error getting queue count", { error: error.message });
          return 0;
        }
      }
      // Queue new operations
      async queueEmailReply(replyData) {
        this.logger.info("Queuing email reply", { to: replyData.to });
        const metadata = {
          to: replyData.to,
          from: replyData.from,
          original_id: replyData.originalId,
          date_queued: (/* @__PURE__ */ new Date()).toISOString(),
          sent: false
        };
        return metadata;
      }
      async queueFederatedPost(postId, targetDomains, author) {
        this.logger.info("Queuing federated post", { postId, domains: targetDomains.length });
        try {
          const federationMetadata = {
            target_domains: targetDomains,
            author,
            date_queued: (/* @__PURE__ */ new Date()).toISOString(),
            sent: false
          };
          await this.env.DB.prepare(`
                UPDATE posts 
                SET federation_pending = 1, federation_metadata = ? 
                WHERE id = ?
            `).bind(JSON.stringify(federationMetadata), postId).run();
          return { success: true, queued: targetDomains.length };
        } catch (error) {
          this.logger.error("Failed to queue federated post", { error: error.message });
          return { success: false, error: error.message };
        }
      }
      // Helper methods
      getBlogDomain() {
        try {
          return new URL(this.env.SITE_URL || "https://deadlight.boo").hostname;
        } catch {
          return "deadlight.boo";
        }
      }
      getBlogUrl() {
        return this.env.SITE_URL || "https://deadlight.boo";
      }
      // Health check for the outbox system
      async getStatus() {
        const queuedCount = await this.getQueuedCount();
        const proxyHealth = await this.proxyService.healthCheck();
        return {
          queued_operations: queuedCount,
          proxy_connected: proxyHealth.proxy_connected,
          last_check: (/* @__PURE__ */ new Date()).toISOString(),
          status: queuedCount > 0 ? "pending" : "clear"
        };
      }
    };
  }
});

// ../lib.deadlight/node_modules/marked/lib/marked.esm.js
function L() {
  return { async: false, breaks: false, extensions: null, gfm: true, hooks: null, pedantic: false, renderer: null, silent: false, tokenizer: null, walkTokens: null };
}
function H(l3) {
  O = l3;
}
function h(l3, e = "") {
  let t = typeof l3 == "string" ? l3 : l3.source, n = { replace: /* @__PURE__ */ __name((r, i) => {
    let s = typeof i == "string" ? i : i.source;
    return s = s.replace(m.caret, "$1"), t = t.replace(r, s), n;
  }, "replace"), getRegex: /* @__PURE__ */ __name(() => new RegExp(t, e), "getRegex") };
  return n;
}
function w(l3, e) {
  if (e) {
    if (m.escapeTest.test(l3)) return l3.replace(m.escapeReplace, ke);
  } else if (m.escapeTestNoEncode.test(l3)) return l3.replace(m.escapeReplaceNoEncode, ke);
  return l3;
}
function J(l3) {
  try {
    l3 = encodeURI(l3).replace(m.percentDecode, "%");
  } catch {
    return null;
  }
  return l3;
}
function V(l3, e) {
  let t = l3.replace(m.findPipe, (i, s, o) => {
    let a = false, u = s;
    for (; --u >= 0 && o[u] === "\\"; ) a = !a;
    return a ? "|" : " |";
  }), n = t.split(m.splitPipe), r = 0;
  if (n[0].trim() || n.shift(), n.length > 0 && !n.at(-1)?.trim() && n.pop(), e) if (n.length > e) n.splice(e);
  else for (; n.length < e; ) n.push("");
  for (; r < n.length; r++) n[r] = n[r].trim().replace(m.slashPipe, "|");
  return n;
}
function z(l3, e, t) {
  let n = l3.length;
  if (n === 0) return "";
  let r = 0;
  for (; r < n; ) {
    let i = l3.charAt(n - r - 1);
    if (i === e && !t) r++;
    else if (i !== e && t) r++;
    else break;
  }
  return l3.slice(0, n - r);
}
function ge(l3, e) {
  if (l3.indexOf(e[1]) === -1) return -1;
  let t = 0;
  for (let n = 0; n < l3.length; n++) if (l3[n] === "\\") n++;
  else if (l3[n] === e[0]) t++;
  else if (l3[n] === e[1] && (t--, t < 0)) return n;
  return t > 0 ? -2 : -1;
}
function fe(l3, e, t, n, r) {
  let i = e.href, s = e.title || null, o = l3[1].replace(r.other.outputLinkReplace, "$1");
  n.state.inLink = true;
  let a = { type: l3[0].charAt(0) === "!" ? "image" : "link", raw: t, href: i, title: s, text: o, tokens: n.inlineTokens(o) };
  return n.state.inLink = false, a;
}
function Je(l3, e, t) {
  let n = l3.match(t.other.indentCodeCompensation);
  if (n === null) return e;
  let r = n[1];
  return e.split(`
`).map((i) => {
    let s = i.match(t.other.beginningSpace);
    if (s === null) return i;
    let [o] = s;
    return o.length >= r.length ? i.slice(r.length) : i;
  }).join(`
`);
}
function d(l3, e) {
  return _.parse(l3, e);
}
var O, E, m, xe, be, Re, C, Oe, j, se, ie, Te, F, we, Q, ye, Pe, v, U, Se, oe, $e, K, re, _e, Le, Me, ze, ae, Ae, D, W, le, Ee, ue, Ce, Ie, Be, pe, qe, ve, ce, De, Ze, Ge, He, Ne, je, Fe, q, Qe, he, de, Ue, X, Ke, N, We, I, M, Xe, ke, y, b, P, S, R, $, B, _, Dt, Zt, Gt, Ht, Nt, Ft, Qt;
var init_marked_esm = __esm({
  "../lib.deadlight/node_modules/marked/lib/marked.esm.js"() {
    init_checked_fetch();
    __name(L, "L");
    O = L();
    __name(H, "H");
    E = { exec: /* @__PURE__ */ __name(() => null, "exec") };
    __name(h, "h");
    m = { codeRemoveIndent: /^(?: {1,4}| {0,3}\t)/gm, outputLinkReplace: /\\([\[\]])/g, indentCodeCompensation: /^(\s+)(?:```)/, beginningSpace: /^\s+/, endingHash: /#$/, startingSpaceChar: /^ /, endingSpaceChar: / $/, nonSpaceChar: /[^ ]/, newLineCharGlobal: /\n/g, tabCharGlobal: /\t/g, multipleSpaceGlobal: /\s+/g, blankLine: /^[ \t]*$/, doubleBlankLine: /\n[ \t]*\n[ \t]*$/, blockquoteStart: /^ {0,3}>/, blockquoteSetextReplace: /\n {0,3}((?:=+|-+) *)(?=\n|$)/g, blockquoteSetextReplace2: /^ {0,3}>[ \t]?/gm, listReplaceTabs: /^\t+/, listReplaceNesting: /^ {1,4}(?=( {4})*[^ ])/g, listIsTask: /^\[[ xX]\] /, listReplaceTask: /^\[[ xX]\] +/, anyLine: /\n.*\n/, hrefBrackets: /^<(.*)>$/, tableDelimiter: /[:|]/, tableAlignChars: /^\||\| *$/g, tableRowBlankLine: /\n[ \t]*$/, tableAlignRight: /^ *-+: *$/, tableAlignCenter: /^ *:-+: *$/, tableAlignLeft: /^ *:-+ *$/, startATag: /^<a /i, endATag: /^<\/a>/i, startPreScriptTag: /^<(pre|code|kbd|script)(\s|>)/i, endPreScriptTag: /^<\/(pre|code|kbd|script)(\s|>)/i, startAngleBracket: /^</, endAngleBracket: />$/, pedanticHrefTitle: /^([^'"]*[^\s])\s+(['"])(.*)\2/, unicodeAlphaNumeric: /[\p{L}\p{N}]/u, escapeTest: /[&<>"']/, escapeReplace: /[&<>"']/g, escapeTestNoEncode: /[<>"']|&(?!(#\d{1,7}|#[Xx][a-fA-F0-9]{1,6}|\w+);)/, escapeReplaceNoEncode: /[<>"']|&(?!(#\d{1,7}|#[Xx][a-fA-F0-9]{1,6}|\w+);)/g, unescapeTest: /&(#(?:\d+)|(?:#x[0-9A-Fa-f]+)|(?:\w+));?/ig, caret: /(^|[^\[])\^/g, percentDecode: /%25/g, findPipe: /\|/g, splitPipe: / \|/, slashPipe: /\\\|/g, carriageReturn: /\r\n|\r/g, spaceLine: /^ +$/gm, notSpaceStart: /^\S*/, endingNewline: /\n$/, listItemRegex: /* @__PURE__ */ __name((l3) => new RegExp(`^( {0,3}${l3})((?:[	 ][^\\n]*)?(?:\\n|$))`), "listItemRegex"), nextBulletRegex: /* @__PURE__ */ __name((l3) => new RegExp(`^ {0,${Math.min(3, l3 - 1)}}(?:[*+-]|\\d{1,9}[.)])((?:[ 	][^\\n]*)?(?:\\n|$))`), "nextBulletRegex"), hrRegex: /* @__PURE__ */ __name((l3) => new RegExp(`^ {0,${Math.min(3, l3 - 1)}}((?:- *){3,}|(?:_ *){3,}|(?:\\* *){3,})(?:\\n+|$)`), "hrRegex"), fencesBeginRegex: /* @__PURE__ */ __name((l3) => new RegExp(`^ {0,${Math.min(3, l3 - 1)}}(?:\`\`\`|~~~)`), "fencesBeginRegex"), headingBeginRegex: /* @__PURE__ */ __name((l3) => new RegExp(`^ {0,${Math.min(3, l3 - 1)}}#`), "headingBeginRegex"), htmlBeginRegex: /* @__PURE__ */ __name((l3) => new RegExp(`^ {0,${Math.min(3, l3 - 1)}}<(?:[a-z].*>|!--)`, "i"), "htmlBeginRegex") };
    xe = /^(?:[ \t]*(?:\n|$))+/;
    be = /^((?: {4}| {0,3}\t)[^\n]+(?:\n(?:[ \t]*(?:\n|$))*)?)+/;
    Re = /^ {0,3}(`{3,}(?=[^`\n]*(?:\n|$))|~{3,})([^\n]*)(?:\n|$)(?:|([\s\S]*?)(?:\n|$))(?: {0,3}\1[~`]* *(?=\n|$)|$)/;
    C = /^ {0,3}((?:-[\t ]*){3,}|(?:_[ \t]*){3,}|(?:\*[ \t]*){3,})(?:\n+|$)/;
    Oe = /^ {0,3}(#{1,6})(?=\s|$)(.*)(?:\n+|$)/;
    j = /(?:[*+-]|\d{1,9}[.)])/;
    se = /^(?!bull |blockCode|fences|blockquote|heading|html|table)((?:.|\n(?!\s*?\n|bull |blockCode|fences|blockquote|heading|html|table))+?)\n {0,3}(=+|-+) *(?:\n+|$)/;
    ie = h(se).replace(/bull/g, j).replace(/blockCode/g, /(?: {4}| {0,3}\t)/).replace(/fences/g, / {0,3}(?:`{3,}|~{3,})/).replace(/blockquote/g, / {0,3}>/).replace(/heading/g, / {0,3}#{1,6}/).replace(/html/g, / {0,3}<[^\n>]+>\n/).replace(/\|table/g, "").getRegex();
    Te = h(se).replace(/bull/g, j).replace(/blockCode/g, /(?: {4}| {0,3}\t)/).replace(/fences/g, / {0,3}(?:`{3,}|~{3,})/).replace(/blockquote/g, / {0,3}>/).replace(/heading/g, / {0,3}#{1,6}/).replace(/html/g, / {0,3}<[^\n>]+>\n/).replace(/table/g, / {0,3}\|?(?:[:\- ]*\|)+[\:\- ]*\n/).getRegex();
    F = /^([^\n]+(?:\n(?!hr|heading|lheading|blockquote|fences|list|html|table| +\n)[^\n]+)*)/;
    we = /^[^\n]+/;
    Q = /(?!\s*\])(?:\\.|[^\[\]\\])+/;
    ye = h(/^ {0,3}\[(label)\]: *(?:\n[ \t]*)?([^<\s][^\s]*|<.*?>)(?:(?: +(?:\n[ \t]*)?| *\n[ \t]*)(title))? *(?:\n+|$)/).replace("label", Q).replace("title", /(?:"(?:\\"?|[^"\\])*"|'[^'\n]*(?:\n[^'\n]+)*\n?'|\([^()]*\))/).getRegex();
    Pe = h(/^( {0,3}bull)([ \t][^\n]+?)?(?:\n|$)/).replace(/bull/g, j).getRegex();
    v = "address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|meta|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul";
    U = /<!--(?:-?>|[\s\S]*?(?:-->|$))/;
    Se = h("^ {0,3}(?:<(script|pre|style|textarea)[\\s>][\\s\\S]*?(?:</\\1>[^\\n]*\\n+|$)|comment[^\\n]*(\\n+|$)|<\\?[\\s\\S]*?(?:\\?>\\n*|$)|<![A-Z][\\s\\S]*?(?:>\\n*|$)|<!\\[CDATA\\[[\\s\\S]*?(?:\\]\\]>\\n*|$)|</?(tag)(?: +|\\n|/?>)[\\s\\S]*?(?:(?:\\n[ 	]*)+\\n|$)|<(?!script|pre|style|textarea)([a-z][\\w-]*)(?:attribute)*? */?>(?=[ \\t]*(?:\\n|$))[\\s\\S]*?(?:(?:\\n[ 	]*)+\\n|$)|</(?!script|pre|style|textarea)[a-z][\\w-]*\\s*>(?=[ \\t]*(?:\\n|$))[\\s\\S]*?(?:(?:\\n[ 	]*)+\\n|$))", "i").replace("comment", U).replace("tag", v).replace("attribute", / +[a-zA-Z:_][\w.:-]*(?: *= *"[^"\n]*"| *= *'[^'\n]*'| *= *[^\s"'=<>`]+)?/).getRegex();
    oe = h(F).replace("hr", C).replace("heading", " {0,3}#{1,6}(?:\\s|$)").replace("|lheading", "").replace("|table", "").replace("blockquote", " {0,3}>").replace("fences", " {0,3}(?:`{3,}(?=[^`\\n]*\\n)|~{3,})[^\\n]*\\n").replace("list", " {0,3}(?:[*+-]|1[.)]) ").replace("html", "</?(?:tag)(?: +|\\n|/?>)|<(?:script|pre|style|textarea|!--)").replace("tag", v).getRegex();
    $e = h(/^( {0,3}> ?(paragraph|[^\n]*)(?:\n|$))+/).replace("paragraph", oe).getRegex();
    K = { blockquote: $e, code: be, def: ye, fences: Re, heading: Oe, hr: C, html: Se, lheading: ie, list: Pe, newline: xe, paragraph: oe, table: E, text: we };
    re = h("^ *([^\\n ].*)\\n {0,3}((?:\\| *)?:?-+:? *(?:\\| *:?-+:? *)*(?:\\| *)?)(?:\\n((?:(?! *\\n|hr|heading|blockquote|code|fences|list|html).*(?:\\n|$))*)\\n*|$)").replace("hr", C).replace("heading", " {0,3}#{1,6}(?:\\s|$)").replace("blockquote", " {0,3}>").replace("code", "(?: {4}| {0,3}	)[^\\n]").replace("fences", " {0,3}(?:`{3,}(?=[^`\\n]*\\n)|~{3,})[^\\n]*\\n").replace("list", " {0,3}(?:[*+-]|1[.)]) ").replace("html", "</?(?:tag)(?: +|\\n|/?>)|<(?:script|pre|style|textarea|!--)").replace("tag", v).getRegex();
    _e = { ...K, lheading: Te, table: re, paragraph: h(F).replace("hr", C).replace("heading", " {0,3}#{1,6}(?:\\s|$)").replace("|lheading", "").replace("table", re).replace("blockquote", " {0,3}>").replace("fences", " {0,3}(?:`{3,}(?=[^`\\n]*\\n)|~{3,})[^\\n]*\\n").replace("list", " {0,3}(?:[*+-]|1[.)]) ").replace("html", "</?(?:tag)(?: +|\\n|/?>)|<(?:script|pre|style|textarea|!--)").replace("tag", v).getRegex() };
    Le = { ...K, html: h(`^ *(?:comment *(?:\\n|\\s*$)|<(tag)[\\s\\S]+?</\\1> *(?:\\n{2,}|\\s*$)|<tag(?:"[^"]*"|'[^']*'|\\s[^'"/>\\s]*)*?/?> *(?:\\n{2,}|\\s*$))`).replace("comment", U).replace(/tag/g, "(?!(?:a|em|strong|small|s|cite|q|dfn|abbr|data|time|code|var|samp|kbd|sub|sup|i|b|u|mark|ruby|rt|rp|bdi|bdo|span|br|wbr|ins|del|img)\\b)\\w+(?!:|[^\\w\\s@]*@)\\b").getRegex(), def: /^ *\[([^\]]+)\]: *<?([^\s>]+)>?(?: +(["(][^\n]+[")]))? *(?:\n+|$)/, heading: /^(#{1,6})(.*)(?:\n+|$)/, fences: E, lheading: /^(.+?)\n {0,3}(=+|-+) *(?:\n+|$)/, paragraph: h(F).replace("hr", C).replace("heading", ` *#{1,6} *[^
]`).replace("lheading", ie).replace("|table", "").replace("blockquote", " {0,3}>").replace("|fences", "").replace("|list", "").replace("|html", "").replace("|tag", "").getRegex() };
    Me = /^\\([!"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])/;
    ze = /^(`+)([^`]|[^`][\s\S]*?[^`])\1(?!`)/;
    ae = /^( {2,}|\\)\n(?!\s*$)/;
    Ae = /^(`+|[^`])(?:(?= {2,}\n)|[\s\S]*?(?:(?=[\\<!\[`*_]|\b_|$)|[^ ](?= {2,}\n)))/;
    D = /[\p{P}\p{S}]/u;
    W = /[\s\p{P}\p{S}]/u;
    le = /[^\s\p{P}\p{S}]/u;
    Ee = h(/^((?![*_])punctSpace)/, "u").replace(/punctSpace/g, W).getRegex();
    ue = /(?!~)[\p{P}\p{S}]/u;
    Ce = /(?!~)[\s\p{P}\p{S}]/u;
    Ie = /(?:[^\s\p{P}\p{S}]|~)/u;
    Be = /\[[^[\]]*?\]\((?:\\.|[^\\\(\)]|\((?:\\.|[^\\\(\)])*\))*\)|`[^`]*?`|<(?! )[^<>]*?>/g;
    pe = /^(?:\*+(?:((?!\*)punct)|[^\s*]))|^_+(?:((?!_)punct)|([^\s_]))/;
    qe = h(pe, "u").replace(/punct/g, D).getRegex();
    ve = h(pe, "u").replace(/punct/g, ue).getRegex();
    ce = "^[^_*]*?__[^_*]*?\\*[^_*]*?(?=__)|[^*]+(?=[^*])|(?!\\*)punct(\\*+)(?=[\\s]|$)|notPunctSpace(\\*+)(?!\\*)(?=punctSpace|$)|(?!\\*)punctSpace(\\*+)(?=notPunctSpace)|[\\s](\\*+)(?!\\*)(?=punct)|(?!\\*)punct(\\*+)(?!\\*)(?=punct)|notPunctSpace(\\*+)(?=notPunctSpace)";
    De = h(ce, "gu").replace(/notPunctSpace/g, le).replace(/punctSpace/g, W).replace(/punct/g, D).getRegex();
    Ze = h(ce, "gu").replace(/notPunctSpace/g, Ie).replace(/punctSpace/g, Ce).replace(/punct/g, ue).getRegex();
    Ge = h("^[^_*]*?\\*\\*[^_*]*?_[^_*]*?(?=\\*\\*)|[^_]+(?=[^_])|(?!_)punct(_+)(?=[\\s]|$)|notPunctSpace(_+)(?!_)(?=punctSpace|$)|(?!_)punctSpace(_+)(?=notPunctSpace)|[\\s](_+)(?!_)(?=punct)|(?!_)punct(_+)(?!_)(?=punct)", "gu").replace(/notPunctSpace/g, le).replace(/punctSpace/g, W).replace(/punct/g, D).getRegex();
    He = h(/\\(punct)/, "gu").replace(/punct/g, D).getRegex();
    Ne = h(/^<(scheme:[^\s\x00-\x1f<>]*|email)>/).replace("scheme", /[a-zA-Z][a-zA-Z0-9+.-]{1,31}/).replace("email", /[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+(@)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?![-_])/).getRegex();
    je = h(U).replace("(?:-->|$)", "-->").getRegex();
    Fe = h("^comment|^</[a-zA-Z][\\w:-]*\\s*>|^<[a-zA-Z][\\w-]*(?:attribute)*?\\s*/?>|^<\\?[\\s\\S]*?\\?>|^<![a-zA-Z]+\\s[\\s\\S]*?>|^<!\\[CDATA\\[[\\s\\S]*?\\]\\]>").replace("comment", je).replace("attribute", /\s+[a-zA-Z:_][\w.:-]*(?:\s*=\s*"[^"]*"|\s*=\s*'[^']*'|\s*=\s*[^\s"'=<>`]+)?/).getRegex();
    q = /(?:\[(?:\\.|[^\[\]\\])*\]|\\.|`[^`]*`|[^\[\]\\`])*?/;
    Qe = h(/^!?\[(label)\]\(\s*(href)(?:(?:[ \t]*(?:\n[ \t]*)?)(title))?\s*\)/).replace("label", q).replace("href", /<(?:\\.|[^\n<>\\])+>|[^ \t\n\x00-\x1f]*/).replace("title", /"(?:\\"?|[^"\\])*"|'(?:\\'?|[^'\\])*'|\((?:\\\)?|[^)\\])*\)/).getRegex();
    he = h(/^!?\[(label)\]\[(ref)\]/).replace("label", q).replace("ref", Q).getRegex();
    de = h(/^!?\[(ref)\](?:\[\])?/).replace("ref", Q).getRegex();
    Ue = h("reflink|nolink(?!\\()", "g").replace("reflink", he).replace("nolink", de).getRegex();
    X = { _backpedal: E, anyPunctuation: He, autolink: Ne, blockSkip: Be, br: ae, code: ze, del: E, emStrongLDelim: qe, emStrongRDelimAst: De, emStrongRDelimUnd: Ge, escape: Me, link: Qe, nolink: de, punctuation: Ee, reflink: he, reflinkSearch: Ue, tag: Fe, text: Ae, url: E };
    Ke = { ...X, link: h(/^!?\[(label)\]\((.*?)\)/).replace("label", q).getRegex(), reflink: h(/^!?\[(label)\]\s*\[([^\]]*)\]/).replace("label", q).getRegex() };
    N = { ...X, emStrongRDelimAst: Ze, emStrongLDelim: ve, url: h(/^((?:ftp|https?):\/\/|www\.)(?:[a-zA-Z0-9\-]+\.?)+[^\s<]*|^email/, "i").replace("email", /[A-Za-z0-9._+-]+(@)[a-zA-Z0-9-_]+(?:\.[a-zA-Z0-9-_]*[a-zA-Z0-9])+(?![-_])/).getRegex(), _backpedal: /(?:[^?!.,:;*_'"~()&]+|\([^)]*\)|&(?![a-zA-Z0-9]+;$)|[?!.,:;*_'"~)]+(?!$))+/, del: /^(~~?)(?=[^\s~])((?:\\.|[^\\])*?(?:\\.|[^\s~\\]))\1(?=[^~]|$)/, text: /^([`~]+|[^`~])(?:(?= {2,}\n)|(?=[a-zA-Z0-9.!#$%&'*+\/=?_`{\|}~-]+@)|[\s\S]*?(?:(?=[\\<!\[`*~_]|\b_|https?:\/\/|ftp:\/\/|www\.|$)|[^ ](?= {2,}\n)|[^a-zA-Z0-9.!#$%&'*+\/=?_`{\|}~-](?=[a-zA-Z0-9.!#$%&'*+\/=?_`{\|}~-]+@)))/ };
    We = { ...N, br: h(ae).replace("{2,}", "*").getRegex(), text: h(N.text).replace("\\b_", "\\b_| {2,}\\n").replace(/\{2,\}/g, "*").getRegex() };
    I = { normal: K, gfm: _e, pedantic: Le };
    M = { normal: X, gfm: N, breaks: We, pedantic: Ke };
    Xe = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    ke = /* @__PURE__ */ __name((l3) => Xe[l3], "ke");
    __name(w, "w");
    __name(J, "J");
    __name(V, "V");
    __name(z, "z");
    __name(ge, "ge");
    __name(fe, "fe");
    __name(Je, "Je");
    y = class {
      static {
        __name(this, "y");
      }
      options;
      rules;
      lexer;
      constructor(e) {
        this.options = e || O;
      }
      space(e) {
        let t = this.rules.block.newline.exec(e);
        if (t && t[0].length > 0) return { type: "space", raw: t[0] };
      }
      code(e) {
        let t = this.rules.block.code.exec(e);
        if (t) {
          let n = t[0].replace(this.rules.other.codeRemoveIndent, "");
          return { type: "code", raw: t[0], codeBlockStyle: "indented", text: this.options.pedantic ? n : z(n, `
`) };
        }
      }
      fences(e) {
        let t = this.rules.block.fences.exec(e);
        if (t) {
          let n = t[0], r = Je(n, t[3] || "", this.rules);
          return { type: "code", raw: n, lang: t[2] ? t[2].trim().replace(this.rules.inline.anyPunctuation, "$1") : t[2], text: r };
        }
      }
      heading(e) {
        let t = this.rules.block.heading.exec(e);
        if (t) {
          let n = t[2].trim();
          if (this.rules.other.endingHash.test(n)) {
            let r = z(n, "#");
            (this.options.pedantic || !r || this.rules.other.endingSpaceChar.test(r)) && (n = r.trim());
          }
          return { type: "heading", raw: t[0], depth: t[1].length, text: n, tokens: this.lexer.inline(n) };
        }
      }
      hr(e) {
        let t = this.rules.block.hr.exec(e);
        if (t) return { type: "hr", raw: z(t[0], `
`) };
      }
      blockquote(e) {
        let t = this.rules.block.blockquote.exec(e);
        if (t) {
          let n = z(t[0], `
`).split(`
`), r = "", i = "", s = [];
          for (; n.length > 0; ) {
            let o = false, a = [], u;
            for (u = 0; u < n.length; u++) if (this.rules.other.blockquoteStart.test(n[u])) a.push(n[u]), o = true;
            else if (!o) a.push(n[u]);
            else break;
            n = n.slice(u);
            let p = a.join(`
`), c = p.replace(this.rules.other.blockquoteSetextReplace, `
    $1`).replace(this.rules.other.blockquoteSetextReplace2, "");
            r = r ? `${r}
${p}` : p, i = i ? `${i}
${c}` : c;
            let f = this.lexer.state.top;
            if (this.lexer.state.top = true, this.lexer.blockTokens(c, s, true), this.lexer.state.top = f, n.length === 0) break;
            let k = s.at(-1);
            if (k?.type === "code") break;
            if (k?.type === "blockquote") {
              let x = k, g = x.raw + `
` + n.join(`
`), T = this.blockquote(g);
              s[s.length - 1] = T, r = r.substring(0, r.length - x.raw.length) + T.raw, i = i.substring(0, i.length - x.text.length) + T.text;
              break;
            } else if (k?.type === "list") {
              let x = k, g = x.raw + `
` + n.join(`
`), T = this.list(g);
              s[s.length - 1] = T, r = r.substring(0, r.length - k.raw.length) + T.raw, i = i.substring(0, i.length - x.raw.length) + T.raw, n = g.substring(s.at(-1).raw.length).split(`
`);
              continue;
            }
          }
          return { type: "blockquote", raw: r, tokens: s, text: i };
        }
      }
      list(e) {
        let t = this.rules.block.list.exec(e);
        if (t) {
          let n = t[1].trim(), r = n.length > 1, i = { type: "list", raw: "", ordered: r, start: r ? +n.slice(0, -1) : "", loose: false, items: [] };
          n = r ? `\\d{1,9}\\${n.slice(-1)}` : `\\${n}`, this.options.pedantic && (n = r ? n : "[*+-]");
          let s = this.rules.other.listItemRegex(n), o = false;
          for (; e; ) {
            let u = false, p = "", c = "";
            if (!(t = s.exec(e)) || this.rules.block.hr.test(e)) break;
            p = t[0], e = e.substring(p.length);
            let f = t[2].split(`
`, 1)[0].replace(this.rules.other.listReplaceTabs, (Z) => " ".repeat(3 * Z.length)), k = e.split(`
`, 1)[0], x = !f.trim(), g = 0;
            if (this.options.pedantic ? (g = 2, c = f.trimStart()) : x ? g = t[1].length + 1 : (g = t[2].search(this.rules.other.nonSpaceChar), g = g > 4 ? 1 : g, c = f.slice(g), g += t[1].length), x && this.rules.other.blankLine.test(k) && (p += k + `
`, e = e.substring(k.length + 1), u = true), !u) {
              let Z = this.rules.other.nextBulletRegex(g), ee = this.rules.other.hrRegex(g), te = this.rules.other.fencesBeginRegex(g), ne = this.rules.other.headingBeginRegex(g), me = this.rules.other.htmlBeginRegex(g);
              for (; e; ) {
                let G = e.split(`
`, 1)[0], A;
                if (k = G, this.options.pedantic ? (k = k.replace(this.rules.other.listReplaceNesting, "  "), A = k) : A = k.replace(this.rules.other.tabCharGlobal, "    "), te.test(k) || ne.test(k) || me.test(k) || Z.test(k) || ee.test(k)) break;
                if (A.search(this.rules.other.nonSpaceChar) >= g || !k.trim()) c += `
` + A.slice(g);
                else {
                  if (x || f.replace(this.rules.other.tabCharGlobal, "    ").search(this.rules.other.nonSpaceChar) >= 4 || te.test(f) || ne.test(f) || ee.test(f)) break;
                  c += `
` + k;
                }
                !x && !k.trim() && (x = true), p += G + `
`, e = e.substring(G.length + 1), f = A.slice(g);
              }
            }
            i.loose || (o ? i.loose = true : this.rules.other.doubleBlankLine.test(p) && (o = true));
            let T = null, Y;
            this.options.gfm && (T = this.rules.other.listIsTask.exec(c), T && (Y = T[0] !== "[ ] ", c = c.replace(this.rules.other.listReplaceTask, ""))), i.items.push({ type: "list_item", raw: p, task: !!T, checked: Y, loose: false, text: c, tokens: [] }), i.raw += p;
          }
          let a = i.items.at(-1);
          if (a) a.raw = a.raw.trimEnd(), a.text = a.text.trimEnd();
          else return;
          i.raw = i.raw.trimEnd();
          for (let u = 0; u < i.items.length; u++) if (this.lexer.state.top = false, i.items[u].tokens = this.lexer.blockTokens(i.items[u].text, []), !i.loose) {
            let p = i.items[u].tokens.filter((f) => f.type === "space"), c = p.length > 0 && p.some((f) => this.rules.other.anyLine.test(f.raw));
            i.loose = c;
          }
          if (i.loose) for (let u = 0; u < i.items.length; u++) i.items[u].loose = true;
          return i;
        }
      }
      html(e) {
        let t = this.rules.block.html.exec(e);
        if (t) return { type: "html", block: true, raw: t[0], pre: t[1] === "pre" || t[1] === "script" || t[1] === "style", text: t[0] };
      }
      def(e) {
        let t = this.rules.block.def.exec(e);
        if (t) {
          let n = t[1].toLowerCase().replace(this.rules.other.multipleSpaceGlobal, " "), r = t[2] ? t[2].replace(this.rules.other.hrefBrackets, "$1").replace(this.rules.inline.anyPunctuation, "$1") : "", i = t[3] ? t[3].substring(1, t[3].length - 1).replace(this.rules.inline.anyPunctuation, "$1") : t[3];
          return { type: "def", tag: n, raw: t[0], href: r, title: i };
        }
      }
      table(e) {
        let t = this.rules.block.table.exec(e);
        if (!t || !this.rules.other.tableDelimiter.test(t[2])) return;
        let n = V(t[1]), r = t[2].replace(this.rules.other.tableAlignChars, "").split("|"), i = t[3]?.trim() ? t[3].replace(this.rules.other.tableRowBlankLine, "").split(`
`) : [], s = { type: "table", raw: t[0], header: [], align: [], rows: [] };
        if (n.length === r.length) {
          for (let o of r) this.rules.other.tableAlignRight.test(o) ? s.align.push("right") : this.rules.other.tableAlignCenter.test(o) ? s.align.push("center") : this.rules.other.tableAlignLeft.test(o) ? s.align.push("left") : s.align.push(null);
          for (let o = 0; o < n.length; o++) s.header.push({ text: n[o], tokens: this.lexer.inline(n[o]), header: true, align: s.align[o] });
          for (let o of i) s.rows.push(V(o, s.header.length).map((a, u) => ({ text: a, tokens: this.lexer.inline(a), header: false, align: s.align[u] })));
          return s;
        }
      }
      lheading(e) {
        let t = this.rules.block.lheading.exec(e);
        if (t) return { type: "heading", raw: t[0], depth: t[2].charAt(0) === "=" ? 1 : 2, text: t[1], tokens: this.lexer.inline(t[1]) };
      }
      paragraph(e) {
        let t = this.rules.block.paragraph.exec(e);
        if (t) {
          let n = t[1].charAt(t[1].length - 1) === `
` ? t[1].slice(0, -1) : t[1];
          return { type: "paragraph", raw: t[0], text: n, tokens: this.lexer.inline(n) };
        }
      }
      text(e) {
        let t = this.rules.block.text.exec(e);
        if (t) return { type: "text", raw: t[0], text: t[0], tokens: this.lexer.inline(t[0]) };
      }
      escape(e) {
        let t = this.rules.inline.escape.exec(e);
        if (t) return { type: "escape", raw: t[0], text: t[1] };
      }
      tag(e) {
        let t = this.rules.inline.tag.exec(e);
        if (t) return !this.lexer.state.inLink && this.rules.other.startATag.test(t[0]) ? this.lexer.state.inLink = true : this.lexer.state.inLink && this.rules.other.endATag.test(t[0]) && (this.lexer.state.inLink = false), !this.lexer.state.inRawBlock && this.rules.other.startPreScriptTag.test(t[0]) ? this.lexer.state.inRawBlock = true : this.lexer.state.inRawBlock && this.rules.other.endPreScriptTag.test(t[0]) && (this.lexer.state.inRawBlock = false), { type: "html", raw: t[0], inLink: this.lexer.state.inLink, inRawBlock: this.lexer.state.inRawBlock, block: false, text: t[0] };
      }
      link(e) {
        let t = this.rules.inline.link.exec(e);
        if (t) {
          let n = t[2].trim();
          if (!this.options.pedantic && this.rules.other.startAngleBracket.test(n)) {
            if (!this.rules.other.endAngleBracket.test(n)) return;
            let s = z(n.slice(0, -1), "\\");
            if ((n.length - s.length) % 2 === 0) return;
          } else {
            let s = ge(t[2], "()");
            if (s === -2) return;
            if (s > -1) {
              let a = (t[0].indexOf("!") === 0 ? 5 : 4) + t[1].length + s;
              t[2] = t[2].substring(0, s), t[0] = t[0].substring(0, a).trim(), t[3] = "";
            }
          }
          let r = t[2], i = "";
          if (this.options.pedantic) {
            let s = this.rules.other.pedanticHrefTitle.exec(r);
            s && (r = s[1], i = s[3]);
          } else i = t[3] ? t[3].slice(1, -1) : "";
          return r = r.trim(), this.rules.other.startAngleBracket.test(r) && (this.options.pedantic && !this.rules.other.endAngleBracket.test(n) ? r = r.slice(1) : r = r.slice(1, -1)), fe(t, { href: r && r.replace(this.rules.inline.anyPunctuation, "$1"), title: i && i.replace(this.rules.inline.anyPunctuation, "$1") }, t[0], this.lexer, this.rules);
        }
      }
      reflink(e, t) {
        let n;
        if ((n = this.rules.inline.reflink.exec(e)) || (n = this.rules.inline.nolink.exec(e))) {
          let r = (n[2] || n[1]).replace(this.rules.other.multipleSpaceGlobal, " "), i = t[r.toLowerCase()];
          if (!i) {
            let s = n[0].charAt(0);
            return { type: "text", raw: s, text: s };
          }
          return fe(n, i, n[0], this.lexer, this.rules);
        }
      }
      emStrong(e, t, n = "") {
        let r = this.rules.inline.emStrongLDelim.exec(e);
        if (!r || r[3] && n.match(this.rules.other.unicodeAlphaNumeric)) return;
        if (!(r[1] || r[2] || "") || !n || this.rules.inline.punctuation.exec(n)) {
          let s = [...r[0]].length - 1, o, a, u = s, p = 0, c = r[0][0] === "*" ? this.rules.inline.emStrongRDelimAst : this.rules.inline.emStrongRDelimUnd;
          for (c.lastIndex = 0, t = t.slice(-1 * e.length + s); (r = c.exec(t)) != null; ) {
            if (o = r[1] || r[2] || r[3] || r[4] || r[5] || r[6], !o) continue;
            if (a = [...o].length, r[3] || r[4]) {
              u += a;
              continue;
            } else if ((r[5] || r[6]) && s % 3 && !((s + a) % 3)) {
              p += a;
              continue;
            }
            if (u -= a, u > 0) continue;
            a = Math.min(a, a + u + p);
            let f = [...r[0]][0].length, k = e.slice(0, s + r.index + f + a);
            if (Math.min(s, a) % 2) {
              let g = k.slice(1, -1);
              return { type: "em", raw: k, text: g, tokens: this.lexer.inlineTokens(g) };
            }
            let x = k.slice(2, -2);
            return { type: "strong", raw: k, text: x, tokens: this.lexer.inlineTokens(x) };
          }
        }
      }
      codespan(e) {
        let t = this.rules.inline.code.exec(e);
        if (t) {
          let n = t[2].replace(this.rules.other.newLineCharGlobal, " "), r = this.rules.other.nonSpaceChar.test(n), i = this.rules.other.startingSpaceChar.test(n) && this.rules.other.endingSpaceChar.test(n);
          return r && i && (n = n.substring(1, n.length - 1)), { type: "codespan", raw: t[0], text: n };
        }
      }
      br(e) {
        let t = this.rules.inline.br.exec(e);
        if (t) return { type: "br", raw: t[0] };
      }
      del(e) {
        let t = this.rules.inline.del.exec(e);
        if (t) return { type: "del", raw: t[0], text: t[2], tokens: this.lexer.inlineTokens(t[2]) };
      }
      autolink(e) {
        let t = this.rules.inline.autolink.exec(e);
        if (t) {
          let n, r;
          return t[2] === "@" ? (n = t[1], r = "mailto:" + n) : (n = t[1], r = n), { type: "link", raw: t[0], text: n, href: r, tokens: [{ type: "text", raw: n, text: n }] };
        }
      }
      url(e) {
        let t;
        if (t = this.rules.inline.url.exec(e)) {
          let n, r;
          if (t[2] === "@") n = t[0], r = "mailto:" + n;
          else {
            let i;
            do
              i = t[0], t[0] = this.rules.inline._backpedal.exec(t[0])?.[0] ?? "";
            while (i !== t[0]);
            n = t[0], t[1] === "www." ? r = "http://" + t[0] : r = t[0];
          }
          return { type: "link", raw: t[0], text: n, href: r, tokens: [{ type: "text", raw: n, text: n }] };
        }
      }
      inlineText(e) {
        let t = this.rules.inline.text.exec(e);
        if (t) {
          let n = this.lexer.state.inRawBlock;
          return { type: "text", raw: t[0], text: t[0], escaped: n };
        }
      }
    };
    b = class l {
      static {
        __name(this, "l");
      }
      tokens;
      options;
      state;
      tokenizer;
      inlineQueue;
      constructor(e) {
        this.tokens = [], this.tokens.links = /* @__PURE__ */ Object.create(null), this.options = e || O, this.options.tokenizer = this.options.tokenizer || new y(), this.tokenizer = this.options.tokenizer, this.tokenizer.options = this.options, this.tokenizer.lexer = this, this.inlineQueue = [], this.state = { inLink: false, inRawBlock: false, top: true };
        let t = { other: m, block: I.normal, inline: M.normal };
        this.options.pedantic ? (t.block = I.pedantic, t.inline = M.pedantic) : this.options.gfm && (t.block = I.gfm, this.options.breaks ? t.inline = M.breaks : t.inline = M.gfm), this.tokenizer.rules = t;
      }
      static get rules() {
        return { block: I, inline: M };
      }
      static lex(e, t) {
        return new l(t).lex(e);
      }
      static lexInline(e, t) {
        return new l(t).inlineTokens(e);
      }
      lex(e) {
        e = e.replace(m.carriageReturn, `
`), this.blockTokens(e, this.tokens);
        for (let t = 0; t < this.inlineQueue.length; t++) {
          let n = this.inlineQueue[t];
          this.inlineTokens(n.src, n.tokens);
        }
        return this.inlineQueue = [], this.tokens;
      }
      blockTokens(e, t = [], n = false) {
        for (this.options.pedantic && (e = e.replace(m.tabCharGlobal, "    ").replace(m.spaceLine, "")); e; ) {
          let r;
          if (this.options.extensions?.block?.some((s) => (r = s.call({ lexer: this }, e, t)) ? (e = e.substring(r.raw.length), t.push(r), true) : false)) continue;
          if (r = this.tokenizer.space(e)) {
            e = e.substring(r.raw.length);
            let s = t.at(-1);
            r.raw.length === 1 && s !== void 0 ? s.raw += `
` : t.push(r);
            continue;
          }
          if (r = this.tokenizer.code(e)) {
            e = e.substring(r.raw.length);
            let s = t.at(-1);
            s?.type === "paragraph" || s?.type === "text" ? (s.raw += (s.raw.endsWith(`
`) ? "" : `
`) + r.raw, s.text += `
` + r.text, this.inlineQueue.at(-1).src = s.text) : t.push(r);
            continue;
          }
          if (r = this.tokenizer.fences(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          if (r = this.tokenizer.heading(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          if (r = this.tokenizer.hr(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          if (r = this.tokenizer.blockquote(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          if (r = this.tokenizer.list(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          if (r = this.tokenizer.html(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          if (r = this.tokenizer.def(e)) {
            e = e.substring(r.raw.length);
            let s = t.at(-1);
            s?.type === "paragraph" || s?.type === "text" ? (s.raw += (s.raw.endsWith(`
`) ? "" : `
`) + r.raw, s.text += `
` + r.raw, this.inlineQueue.at(-1).src = s.text) : this.tokens.links[r.tag] || (this.tokens.links[r.tag] = { href: r.href, title: r.title }, t.push(r));
            continue;
          }
          if (r = this.tokenizer.table(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          if (r = this.tokenizer.lheading(e)) {
            e = e.substring(r.raw.length), t.push(r);
            continue;
          }
          let i = e;
          if (this.options.extensions?.startBlock) {
            let s = 1 / 0, o = e.slice(1), a;
            this.options.extensions.startBlock.forEach((u) => {
              a = u.call({ lexer: this }, o), typeof a == "number" && a >= 0 && (s = Math.min(s, a));
            }), s < 1 / 0 && s >= 0 && (i = e.substring(0, s + 1));
          }
          if (this.state.top && (r = this.tokenizer.paragraph(i))) {
            let s = t.at(-1);
            n && s?.type === "paragraph" ? (s.raw += (s.raw.endsWith(`
`) ? "" : `
`) + r.raw, s.text += `
` + r.text, this.inlineQueue.pop(), this.inlineQueue.at(-1).src = s.text) : t.push(r), n = i.length !== e.length, e = e.substring(r.raw.length);
            continue;
          }
          if (r = this.tokenizer.text(e)) {
            e = e.substring(r.raw.length);
            let s = t.at(-1);
            s?.type === "text" ? (s.raw += (s.raw.endsWith(`
`) ? "" : `
`) + r.raw, s.text += `
` + r.text, this.inlineQueue.pop(), this.inlineQueue.at(-1).src = s.text) : t.push(r);
            continue;
          }
          if (e) {
            let s = "Infinite loop on byte: " + e.charCodeAt(0);
            if (this.options.silent) {
              console.error(s);
              break;
            } else throw new Error(s);
          }
        }
        return this.state.top = true, t;
      }
      inline(e, t = []) {
        return this.inlineQueue.push({ src: e, tokens: t }), t;
      }
      inlineTokens(e, t = []) {
        let n = e, r = null;
        if (this.tokens.links) {
          let o = Object.keys(this.tokens.links);
          if (o.length > 0) for (; (r = this.tokenizer.rules.inline.reflinkSearch.exec(n)) != null; ) o.includes(r[0].slice(r[0].lastIndexOf("[") + 1, -1)) && (n = n.slice(0, r.index) + "[" + "a".repeat(r[0].length - 2) + "]" + n.slice(this.tokenizer.rules.inline.reflinkSearch.lastIndex));
        }
        for (; (r = this.tokenizer.rules.inline.anyPunctuation.exec(n)) != null; ) n = n.slice(0, r.index) + "++" + n.slice(this.tokenizer.rules.inline.anyPunctuation.lastIndex);
        for (; (r = this.tokenizer.rules.inline.blockSkip.exec(n)) != null; ) n = n.slice(0, r.index) + "[" + "a".repeat(r[0].length - 2) + "]" + n.slice(this.tokenizer.rules.inline.blockSkip.lastIndex);
        let i = false, s = "";
        for (; e; ) {
          i || (s = ""), i = false;
          let o;
          if (this.options.extensions?.inline?.some((u) => (o = u.call({ lexer: this }, e, t)) ? (e = e.substring(o.raw.length), t.push(o), true) : false)) continue;
          if (o = this.tokenizer.escape(e)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (o = this.tokenizer.tag(e)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (o = this.tokenizer.link(e)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (o = this.tokenizer.reflink(e, this.tokens.links)) {
            e = e.substring(o.raw.length);
            let u = t.at(-1);
            o.type === "text" && u?.type === "text" ? (u.raw += o.raw, u.text += o.text) : t.push(o);
            continue;
          }
          if (o = this.tokenizer.emStrong(e, n, s)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (o = this.tokenizer.codespan(e)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (o = this.tokenizer.br(e)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (o = this.tokenizer.del(e)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (o = this.tokenizer.autolink(e)) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          if (!this.state.inLink && (o = this.tokenizer.url(e))) {
            e = e.substring(o.raw.length), t.push(o);
            continue;
          }
          let a = e;
          if (this.options.extensions?.startInline) {
            let u = 1 / 0, p = e.slice(1), c;
            this.options.extensions.startInline.forEach((f) => {
              c = f.call({ lexer: this }, p), typeof c == "number" && c >= 0 && (u = Math.min(u, c));
            }), u < 1 / 0 && u >= 0 && (a = e.substring(0, u + 1));
          }
          if (o = this.tokenizer.inlineText(a)) {
            e = e.substring(o.raw.length), o.raw.slice(-1) !== "_" && (s = o.raw.slice(-1)), i = true;
            let u = t.at(-1);
            u?.type === "text" ? (u.raw += o.raw, u.text += o.text) : t.push(o);
            continue;
          }
          if (e) {
            let u = "Infinite loop on byte: " + e.charCodeAt(0);
            if (this.options.silent) {
              console.error(u);
              break;
            } else throw new Error(u);
          }
        }
        return t;
      }
    };
    P = class {
      static {
        __name(this, "P");
      }
      options;
      parser;
      constructor(e) {
        this.options = e || O;
      }
      space(e) {
        return "";
      }
      code({ text: e, lang: t, escaped: n }) {
        let r = (t || "").match(m.notSpaceStart)?.[0], i = e.replace(m.endingNewline, "") + `
`;
        return r ? '<pre><code class="language-' + w(r) + '">' + (n ? i : w(i, true)) + `</code></pre>
` : "<pre><code>" + (n ? i : w(i, true)) + `</code></pre>
`;
      }
      blockquote({ tokens: e }) {
        return `<blockquote>
${this.parser.parse(e)}</blockquote>
`;
      }
      html({ text: e }) {
        return e;
      }
      def(e) {
        return "";
      }
      heading({ tokens: e, depth: t }) {
        return `<h${t}>${this.parser.parseInline(e)}</h${t}>
`;
      }
      hr(e) {
        return `<hr>
`;
      }
      list(e) {
        let t = e.ordered, n = e.start, r = "";
        for (let o = 0; o < e.items.length; o++) {
          let a = e.items[o];
          r += this.listitem(a);
        }
        let i = t ? "ol" : "ul", s = t && n !== 1 ? ' start="' + n + '"' : "";
        return "<" + i + s + `>
` + r + "</" + i + `>
`;
      }
      listitem(e) {
        let t = "";
        if (e.task) {
          let n = this.checkbox({ checked: !!e.checked });
          e.loose ? e.tokens[0]?.type === "paragraph" ? (e.tokens[0].text = n + " " + e.tokens[0].text, e.tokens[0].tokens && e.tokens[0].tokens.length > 0 && e.tokens[0].tokens[0].type === "text" && (e.tokens[0].tokens[0].text = n + " " + w(e.tokens[0].tokens[0].text), e.tokens[0].tokens[0].escaped = true)) : e.tokens.unshift({ type: "text", raw: n + " ", text: n + " ", escaped: true }) : t += n + " ";
        }
        return t += this.parser.parse(e.tokens, !!e.loose), `<li>${t}</li>
`;
      }
      checkbox({ checked: e }) {
        return "<input " + (e ? 'checked="" ' : "") + 'disabled="" type="checkbox">';
      }
      paragraph({ tokens: e }) {
        return `<p>${this.parser.parseInline(e)}</p>
`;
      }
      table(e) {
        let t = "", n = "";
        for (let i = 0; i < e.header.length; i++) n += this.tablecell(e.header[i]);
        t += this.tablerow({ text: n });
        let r = "";
        for (let i = 0; i < e.rows.length; i++) {
          let s = e.rows[i];
          n = "";
          for (let o = 0; o < s.length; o++) n += this.tablecell(s[o]);
          r += this.tablerow({ text: n });
        }
        return r && (r = `<tbody>${r}</tbody>`), `<table>
<thead>
` + t + `</thead>
` + r + `</table>
`;
      }
      tablerow({ text: e }) {
        return `<tr>
${e}</tr>
`;
      }
      tablecell(e) {
        let t = this.parser.parseInline(e.tokens), n = e.header ? "th" : "td";
        return (e.align ? `<${n} align="${e.align}">` : `<${n}>`) + t + `</${n}>
`;
      }
      strong({ tokens: e }) {
        return `<strong>${this.parser.parseInline(e)}</strong>`;
      }
      em({ tokens: e }) {
        return `<em>${this.parser.parseInline(e)}</em>`;
      }
      codespan({ text: e }) {
        return `<code>${w(e, true)}</code>`;
      }
      br(e) {
        return "<br>";
      }
      del({ tokens: e }) {
        return `<del>${this.parser.parseInline(e)}</del>`;
      }
      link({ href: e, title: t, tokens: n }) {
        let r = this.parser.parseInline(n), i = J(e);
        if (i === null) return r;
        e = i;
        let s = '<a href="' + e + '"';
        return t && (s += ' title="' + w(t) + '"'), s += ">" + r + "</a>", s;
      }
      image({ href: e, title: t, text: n, tokens: r }) {
        r && (n = this.parser.parseInline(r, this.parser.textRenderer));
        let i = J(e);
        if (i === null) return w(n);
        e = i;
        let s = `<img src="${e}" alt="${n}"`;
        return t && (s += ` title="${w(t)}"`), s += ">", s;
      }
      text(e) {
        return "tokens" in e && e.tokens ? this.parser.parseInline(e.tokens) : "escaped" in e && e.escaped ? e.text : w(e.text);
      }
    };
    S = class {
      static {
        __name(this, "S");
      }
      strong({ text: e }) {
        return e;
      }
      em({ text: e }) {
        return e;
      }
      codespan({ text: e }) {
        return e;
      }
      del({ text: e }) {
        return e;
      }
      html({ text: e }) {
        return e;
      }
      text({ text: e }) {
        return e;
      }
      link({ text: e }) {
        return "" + e;
      }
      image({ text: e }) {
        return "" + e;
      }
      br() {
        return "";
      }
    };
    R = class l2 {
      static {
        __name(this, "l");
      }
      options;
      renderer;
      textRenderer;
      constructor(e) {
        this.options = e || O, this.options.renderer = this.options.renderer || new P(), this.renderer = this.options.renderer, this.renderer.options = this.options, this.renderer.parser = this, this.textRenderer = new S();
      }
      static parse(e, t) {
        return new l2(t).parse(e);
      }
      static parseInline(e, t) {
        return new l2(t).parseInline(e);
      }
      parse(e, t = true) {
        let n = "";
        for (let r = 0; r < e.length; r++) {
          let i = e[r];
          if (this.options.extensions?.renderers?.[i.type]) {
            let o = i, a = this.options.extensions.renderers[o.type].call({ parser: this }, o);
            if (a !== false || !["space", "hr", "heading", "code", "table", "blockquote", "list", "html", "def", "paragraph", "text"].includes(o.type)) {
              n += a || "";
              continue;
            }
          }
          let s = i;
          switch (s.type) {
            case "space": {
              n += this.renderer.space(s);
              continue;
            }
            case "hr": {
              n += this.renderer.hr(s);
              continue;
            }
            case "heading": {
              n += this.renderer.heading(s);
              continue;
            }
            case "code": {
              n += this.renderer.code(s);
              continue;
            }
            case "table": {
              n += this.renderer.table(s);
              continue;
            }
            case "blockquote": {
              n += this.renderer.blockquote(s);
              continue;
            }
            case "list": {
              n += this.renderer.list(s);
              continue;
            }
            case "html": {
              n += this.renderer.html(s);
              continue;
            }
            case "def": {
              n += this.renderer.def(s);
              continue;
            }
            case "paragraph": {
              n += this.renderer.paragraph(s);
              continue;
            }
            case "text": {
              let o = s, a = this.renderer.text(o);
              for (; r + 1 < e.length && e[r + 1].type === "text"; ) o = e[++r], a += `
` + this.renderer.text(o);
              t ? n += this.renderer.paragraph({ type: "paragraph", raw: a, text: a, tokens: [{ type: "text", raw: a, text: a, escaped: true }] }) : n += a;
              continue;
            }
            default: {
              let o = 'Token with "' + s.type + '" type was not found.';
              if (this.options.silent) return console.error(o), "";
              throw new Error(o);
            }
          }
        }
        return n;
      }
      parseInline(e, t = this.renderer) {
        let n = "";
        for (let r = 0; r < e.length; r++) {
          let i = e[r];
          if (this.options.extensions?.renderers?.[i.type]) {
            let o = this.options.extensions.renderers[i.type].call({ parser: this }, i);
            if (o !== false || !["escape", "html", "link", "image", "strong", "em", "codespan", "br", "del", "text"].includes(i.type)) {
              n += o || "";
              continue;
            }
          }
          let s = i;
          switch (s.type) {
            case "escape": {
              n += t.text(s);
              break;
            }
            case "html": {
              n += t.html(s);
              break;
            }
            case "link": {
              n += t.link(s);
              break;
            }
            case "image": {
              n += t.image(s);
              break;
            }
            case "strong": {
              n += t.strong(s);
              break;
            }
            case "em": {
              n += t.em(s);
              break;
            }
            case "codespan": {
              n += t.codespan(s);
              break;
            }
            case "br": {
              n += t.br(s);
              break;
            }
            case "del": {
              n += t.del(s);
              break;
            }
            case "text": {
              n += t.text(s);
              break;
            }
            default: {
              let o = 'Token with "' + s.type + '" type was not found.';
              if (this.options.silent) return console.error(o), "";
              throw new Error(o);
            }
          }
        }
        return n;
      }
    };
    $ = class {
      static {
        __name(this, "$");
      }
      options;
      block;
      constructor(e) {
        this.options = e || O;
      }
      static passThroughHooks = /* @__PURE__ */ new Set(["preprocess", "postprocess", "processAllTokens"]);
      preprocess(e) {
        return e;
      }
      postprocess(e) {
        return e;
      }
      processAllTokens(e) {
        return e;
      }
      provideLexer() {
        return this.block ? b.lex : b.lexInline;
      }
      provideParser() {
        return this.block ? R.parse : R.parseInline;
      }
    };
    B = class {
      static {
        __name(this, "B");
      }
      defaults = L();
      options = this.setOptions;
      parse = this.parseMarkdown(true);
      parseInline = this.parseMarkdown(false);
      Parser = R;
      Renderer = P;
      TextRenderer = S;
      Lexer = b;
      Tokenizer = y;
      Hooks = $;
      constructor(...e) {
        this.use(...e);
      }
      walkTokens(e, t) {
        let n = [];
        for (let r of e) switch (n = n.concat(t.call(this, r)), r.type) {
          case "table": {
            let i = r;
            for (let s of i.header) n = n.concat(this.walkTokens(s.tokens, t));
            for (let s of i.rows) for (let o of s) n = n.concat(this.walkTokens(o.tokens, t));
            break;
          }
          case "list": {
            let i = r;
            n = n.concat(this.walkTokens(i.items, t));
            break;
          }
          default: {
            let i = r;
            this.defaults.extensions?.childTokens?.[i.type] ? this.defaults.extensions.childTokens[i.type].forEach((s) => {
              let o = i[s].flat(1 / 0);
              n = n.concat(this.walkTokens(o, t));
            }) : i.tokens && (n = n.concat(this.walkTokens(i.tokens, t)));
          }
        }
        return n;
      }
      use(...e) {
        let t = this.defaults.extensions || { renderers: {}, childTokens: {} };
        return e.forEach((n) => {
          let r = { ...n };
          if (r.async = this.defaults.async || r.async || false, n.extensions && (n.extensions.forEach((i) => {
            if (!i.name) throw new Error("extension name required");
            if ("renderer" in i) {
              let s = t.renderers[i.name];
              s ? t.renderers[i.name] = function(...o) {
                let a = i.renderer.apply(this, o);
                return a === false && (a = s.apply(this, o)), a;
              } : t.renderers[i.name] = i.renderer;
            }
            if ("tokenizer" in i) {
              if (!i.level || i.level !== "block" && i.level !== "inline") throw new Error("extension level must be 'block' or 'inline'");
              let s = t[i.level];
              s ? s.unshift(i.tokenizer) : t[i.level] = [i.tokenizer], i.start && (i.level === "block" ? t.startBlock ? t.startBlock.push(i.start) : t.startBlock = [i.start] : i.level === "inline" && (t.startInline ? t.startInline.push(i.start) : t.startInline = [i.start]));
            }
            "childTokens" in i && i.childTokens && (t.childTokens[i.name] = i.childTokens);
          }), r.extensions = t), n.renderer) {
            let i = this.defaults.renderer || new P(this.defaults);
            for (let s in n.renderer) {
              if (!(s in i)) throw new Error(`renderer '${s}' does not exist`);
              if (["options", "parser"].includes(s)) continue;
              let o = s, a = n.renderer[o], u = i[o];
              i[o] = (...p) => {
                let c = a.apply(i, p);
                return c === false && (c = u.apply(i, p)), c || "";
              };
            }
            r.renderer = i;
          }
          if (n.tokenizer) {
            let i = this.defaults.tokenizer || new y(this.defaults);
            for (let s in n.tokenizer) {
              if (!(s in i)) throw new Error(`tokenizer '${s}' does not exist`);
              if (["options", "rules", "lexer"].includes(s)) continue;
              let o = s, a = n.tokenizer[o], u = i[o];
              i[o] = (...p) => {
                let c = a.apply(i, p);
                return c === false && (c = u.apply(i, p)), c;
              };
            }
            r.tokenizer = i;
          }
          if (n.hooks) {
            let i = this.defaults.hooks || new $();
            for (let s in n.hooks) {
              if (!(s in i)) throw new Error(`hook '${s}' does not exist`);
              if (["options", "block"].includes(s)) continue;
              let o = s, a = n.hooks[o], u = i[o];
              $.passThroughHooks.has(s) ? i[o] = (p) => {
                if (this.defaults.async) return Promise.resolve(a.call(i, p)).then((f) => u.call(i, f));
                let c = a.call(i, p);
                return u.call(i, c);
              } : i[o] = (...p) => {
                let c = a.apply(i, p);
                return c === false && (c = u.apply(i, p)), c;
              };
            }
            r.hooks = i;
          }
          if (n.walkTokens) {
            let i = this.defaults.walkTokens, s = n.walkTokens;
            r.walkTokens = function(o) {
              let a = [];
              return a.push(s.call(this, o)), i && (a = a.concat(i.call(this, o))), a;
            };
          }
          this.defaults = { ...this.defaults, ...r };
        }), this;
      }
      setOptions(e) {
        return this.defaults = { ...this.defaults, ...e }, this;
      }
      lexer(e, t) {
        return b.lex(e, t ?? this.defaults);
      }
      parser(e, t) {
        return R.parse(e, t ?? this.defaults);
      }
      parseMarkdown(e) {
        return (n, r) => {
          let i = { ...r }, s = { ...this.defaults, ...i }, o = this.onError(!!s.silent, !!s.async);
          if (this.defaults.async === true && i.async === false) return o(new Error("marked(): The async option was set to true by an extension. Remove async: false from the parse options object to return a Promise."));
          if (typeof n > "u" || n === null) return o(new Error("marked(): input parameter is undefined or null"));
          if (typeof n != "string") return o(new Error("marked(): input parameter is of type " + Object.prototype.toString.call(n) + ", string expected"));
          s.hooks && (s.hooks.options = s, s.hooks.block = e);
          let a = s.hooks ? s.hooks.provideLexer() : e ? b.lex : b.lexInline, u = s.hooks ? s.hooks.provideParser() : e ? R.parse : R.parseInline;
          if (s.async) return Promise.resolve(s.hooks ? s.hooks.preprocess(n) : n).then((p) => a(p, s)).then((p) => s.hooks ? s.hooks.processAllTokens(p) : p).then((p) => s.walkTokens ? Promise.all(this.walkTokens(p, s.walkTokens)).then(() => p) : p).then((p) => u(p, s)).then((p) => s.hooks ? s.hooks.postprocess(p) : p).catch(o);
          try {
            s.hooks && (n = s.hooks.preprocess(n));
            let p = a(n, s);
            s.hooks && (p = s.hooks.processAllTokens(p)), s.walkTokens && this.walkTokens(p, s.walkTokens);
            let c = u(p, s);
            return s.hooks && (c = s.hooks.postprocess(c)), c;
          } catch (p) {
            return o(p);
          }
        };
      }
      onError(e, t) {
        return (n) => {
          if (n.message += `
Please report this to https://github.com/markedjs/marked.`, e) {
            let r = "<p>An error occurred:</p><pre>" + w(n.message + "", true) + "</pre>";
            return t ? Promise.resolve(r) : r;
          }
          if (t) return Promise.reject(n);
          throw n;
        };
      }
    };
    _ = new B();
    __name(d, "d");
    d.options = d.setOptions = function(l3) {
      return _.setOptions(l3), d.defaults = _.defaults, H(d.defaults), d;
    };
    d.getDefaults = L;
    d.defaults = O;
    d.use = function(...l3) {
      return _.use(...l3), d.defaults = _.defaults, H(d.defaults), d;
    };
    d.walkTokens = function(l3, e) {
      return _.walkTokens(l3, e);
    };
    d.parseInline = _.parseInline;
    d.Parser = R;
    d.parser = R.parse;
    d.Renderer = P;
    d.TextRenderer = S;
    d.Lexer = b;
    d.lexer = b.lex;
    d.Tokenizer = y;
    d.Hooks = $;
    d.parse = d;
    Dt = d.options;
    Zt = d.setOptions;
    Gt = d.use;
    Ht = d.walkTokens;
    Nt = d.parseInline;
    Ft = R.parse;
    Qt = b.lex;
  }
});

// ../lib.deadlight/node_modules/cssfilter/lib/default.js
var require_default = __commonJS({
  "../lib.deadlight/node_modules/cssfilter/lib/default.js"(exports) {
    init_checked_fetch();
    function getDefaultWhiteList() {
      var whiteList = {};
      whiteList["align-content"] = false;
      whiteList["align-items"] = false;
      whiteList["align-self"] = false;
      whiteList["alignment-adjust"] = false;
      whiteList["alignment-baseline"] = false;
      whiteList["all"] = false;
      whiteList["anchor-point"] = false;
      whiteList["animation"] = false;
      whiteList["animation-delay"] = false;
      whiteList["animation-direction"] = false;
      whiteList["animation-duration"] = false;
      whiteList["animation-fill-mode"] = false;
      whiteList["animation-iteration-count"] = false;
      whiteList["animation-name"] = false;
      whiteList["animation-play-state"] = false;
      whiteList["animation-timing-function"] = false;
      whiteList["azimuth"] = false;
      whiteList["backface-visibility"] = false;
      whiteList["background"] = true;
      whiteList["background-attachment"] = true;
      whiteList["background-clip"] = true;
      whiteList["background-color"] = true;
      whiteList["background-image"] = true;
      whiteList["background-origin"] = true;
      whiteList["background-position"] = true;
      whiteList["background-repeat"] = true;
      whiteList["background-size"] = true;
      whiteList["baseline-shift"] = false;
      whiteList["binding"] = false;
      whiteList["bleed"] = false;
      whiteList["bookmark-label"] = false;
      whiteList["bookmark-level"] = false;
      whiteList["bookmark-state"] = false;
      whiteList["border"] = true;
      whiteList["border-bottom"] = true;
      whiteList["border-bottom-color"] = true;
      whiteList["border-bottom-left-radius"] = true;
      whiteList["border-bottom-right-radius"] = true;
      whiteList["border-bottom-style"] = true;
      whiteList["border-bottom-width"] = true;
      whiteList["border-collapse"] = true;
      whiteList["border-color"] = true;
      whiteList["border-image"] = true;
      whiteList["border-image-outset"] = true;
      whiteList["border-image-repeat"] = true;
      whiteList["border-image-slice"] = true;
      whiteList["border-image-source"] = true;
      whiteList["border-image-width"] = true;
      whiteList["border-left"] = true;
      whiteList["border-left-color"] = true;
      whiteList["border-left-style"] = true;
      whiteList["border-left-width"] = true;
      whiteList["border-radius"] = true;
      whiteList["border-right"] = true;
      whiteList["border-right-color"] = true;
      whiteList["border-right-style"] = true;
      whiteList["border-right-width"] = true;
      whiteList["border-spacing"] = true;
      whiteList["border-style"] = true;
      whiteList["border-top"] = true;
      whiteList["border-top-color"] = true;
      whiteList["border-top-left-radius"] = true;
      whiteList["border-top-right-radius"] = true;
      whiteList["border-top-style"] = true;
      whiteList["border-top-width"] = true;
      whiteList["border-width"] = true;
      whiteList["bottom"] = false;
      whiteList["box-decoration-break"] = true;
      whiteList["box-shadow"] = true;
      whiteList["box-sizing"] = true;
      whiteList["box-snap"] = true;
      whiteList["box-suppress"] = true;
      whiteList["break-after"] = true;
      whiteList["break-before"] = true;
      whiteList["break-inside"] = true;
      whiteList["caption-side"] = false;
      whiteList["chains"] = false;
      whiteList["clear"] = true;
      whiteList["clip"] = false;
      whiteList["clip-path"] = false;
      whiteList["clip-rule"] = false;
      whiteList["color"] = true;
      whiteList["color-interpolation-filters"] = true;
      whiteList["column-count"] = false;
      whiteList["column-fill"] = false;
      whiteList["column-gap"] = false;
      whiteList["column-rule"] = false;
      whiteList["column-rule-color"] = false;
      whiteList["column-rule-style"] = false;
      whiteList["column-rule-width"] = false;
      whiteList["column-span"] = false;
      whiteList["column-width"] = false;
      whiteList["columns"] = false;
      whiteList["contain"] = false;
      whiteList["content"] = false;
      whiteList["counter-increment"] = false;
      whiteList["counter-reset"] = false;
      whiteList["counter-set"] = false;
      whiteList["crop"] = false;
      whiteList["cue"] = false;
      whiteList["cue-after"] = false;
      whiteList["cue-before"] = false;
      whiteList["cursor"] = false;
      whiteList["direction"] = false;
      whiteList["display"] = true;
      whiteList["display-inside"] = true;
      whiteList["display-list"] = true;
      whiteList["display-outside"] = true;
      whiteList["dominant-baseline"] = false;
      whiteList["elevation"] = false;
      whiteList["empty-cells"] = false;
      whiteList["filter"] = false;
      whiteList["flex"] = false;
      whiteList["flex-basis"] = false;
      whiteList["flex-direction"] = false;
      whiteList["flex-flow"] = false;
      whiteList["flex-grow"] = false;
      whiteList["flex-shrink"] = false;
      whiteList["flex-wrap"] = false;
      whiteList["float"] = false;
      whiteList["float-offset"] = false;
      whiteList["flood-color"] = false;
      whiteList["flood-opacity"] = false;
      whiteList["flow-from"] = false;
      whiteList["flow-into"] = false;
      whiteList["font"] = true;
      whiteList["font-family"] = true;
      whiteList["font-feature-settings"] = true;
      whiteList["font-kerning"] = true;
      whiteList["font-language-override"] = true;
      whiteList["font-size"] = true;
      whiteList["font-size-adjust"] = true;
      whiteList["font-stretch"] = true;
      whiteList["font-style"] = true;
      whiteList["font-synthesis"] = true;
      whiteList["font-variant"] = true;
      whiteList["font-variant-alternates"] = true;
      whiteList["font-variant-caps"] = true;
      whiteList["font-variant-east-asian"] = true;
      whiteList["font-variant-ligatures"] = true;
      whiteList["font-variant-numeric"] = true;
      whiteList["font-variant-position"] = true;
      whiteList["font-weight"] = true;
      whiteList["grid"] = false;
      whiteList["grid-area"] = false;
      whiteList["grid-auto-columns"] = false;
      whiteList["grid-auto-flow"] = false;
      whiteList["grid-auto-rows"] = false;
      whiteList["grid-column"] = false;
      whiteList["grid-column-end"] = false;
      whiteList["grid-column-start"] = false;
      whiteList["grid-row"] = false;
      whiteList["grid-row-end"] = false;
      whiteList["grid-row-start"] = false;
      whiteList["grid-template"] = false;
      whiteList["grid-template-areas"] = false;
      whiteList["grid-template-columns"] = false;
      whiteList["grid-template-rows"] = false;
      whiteList["hanging-punctuation"] = false;
      whiteList["height"] = true;
      whiteList["hyphens"] = false;
      whiteList["icon"] = false;
      whiteList["image-orientation"] = false;
      whiteList["image-resolution"] = false;
      whiteList["ime-mode"] = false;
      whiteList["initial-letters"] = false;
      whiteList["inline-box-align"] = false;
      whiteList["justify-content"] = false;
      whiteList["justify-items"] = false;
      whiteList["justify-self"] = false;
      whiteList["left"] = false;
      whiteList["letter-spacing"] = true;
      whiteList["lighting-color"] = true;
      whiteList["line-box-contain"] = false;
      whiteList["line-break"] = false;
      whiteList["line-grid"] = false;
      whiteList["line-height"] = false;
      whiteList["line-snap"] = false;
      whiteList["line-stacking"] = false;
      whiteList["line-stacking-ruby"] = false;
      whiteList["line-stacking-shift"] = false;
      whiteList["line-stacking-strategy"] = false;
      whiteList["list-style"] = true;
      whiteList["list-style-image"] = true;
      whiteList["list-style-position"] = true;
      whiteList["list-style-type"] = true;
      whiteList["margin"] = true;
      whiteList["margin-bottom"] = true;
      whiteList["margin-left"] = true;
      whiteList["margin-right"] = true;
      whiteList["margin-top"] = true;
      whiteList["marker-offset"] = false;
      whiteList["marker-side"] = false;
      whiteList["marks"] = false;
      whiteList["mask"] = false;
      whiteList["mask-box"] = false;
      whiteList["mask-box-outset"] = false;
      whiteList["mask-box-repeat"] = false;
      whiteList["mask-box-slice"] = false;
      whiteList["mask-box-source"] = false;
      whiteList["mask-box-width"] = false;
      whiteList["mask-clip"] = false;
      whiteList["mask-image"] = false;
      whiteList["mask-origin"] = false;
      whiteList["mask-position"] = false;
      whiteList["mask-repeat"] = false;
      whiteList["mask-size"] = false;
      whiteList["mask-source-type"] = false;
      whiteList["mask-type"] = false;
      whiteList["max-height"] = true;
      whiteList["max-lines"] = false;
      whiteList["max-width"] = true;
      whiteList["min-height"] = true;
      whiteList["min-width"] = true;
      whiteList["move-to"] = false;
      whiteList["nav-down"] = false;
      whiteList["nav-index"] = false;
      whiteList["nav-left"] = false;
      whiteList["nav-right"] = false;
      whiteList["nav-up"] = false;
      whiteList["object-fit"] = false;
      whiteList["object-position"] = false;
      whiteList["opacity"] = false;
      whiteList["order"] = false;
      whiteList["orphans"] = false;
      whiteList["outline"] = false;
      whiteList["outline-color"] = false;
      whiteList["outline-offset"] = false;
      whiteList["outline-style"] = false;
      whiteList["outline-width"] = false;
      whiteList["overflow"] = false;
      whiteList["overflow-wrap"] = false;
      whiteList["overflow-x"] = false;
      whiteList["overflow-y"] = false;
      whiteList["padding"] = true;
      whiteList["padding-bottom"] = true;
      whiteList["padding-left"] = true;
      whiteList["padding-right"] = true;
      whiteList["padding-top"] = true;
      whiteList["page"] = false;
      whiteList["page-break-after"] = false;
      whiteList["page-break-before"] = false;
      whiteList["page-break-inside"] = false;
      whiteList["page-policy"] = false;
      whiteList["pause"] = false;
      whiteList["pause-after"] = false;
      whiteList["pause-before"] = false;
      whiteList["perspective"] = false;
      whiteList["perspective-origin"] = false;
      whiteList["pitch"] = false;
      whiteList["pitch-range"] = false;
      whiteList["play-during"] = false;
      whiteList["position"] = false;
      whiteList["presentation-level"] = false;
      whiteList["quotes"] = false;
      whiteList["region-fragment"] = false;
      whiteList["resize"] = false;
      whiteList["rest"] = false;
      whiteList["rest-after"] = false;
      whiteList["rest-before"] = false;
      whiteList["richness"] = false;
      whiteList["right"] = false;
      whiteList["rotation"] = false;
      whiteList["rotation-point"] = false;
      whiteList["ruby-align"] = false;
      whiteList["ruby-merge"] = false;
      whiteList["ruby-position"] = false;
      whiteList["shape-image-threshold"] = false;
      whiteList["shape-outside"] = false;
      whiteList["shape-margin"] = false;
      whiteList["size"] = false;
      whiteList["speak"] = false;
      whiteList["speak-as"] = false;
      whiteList["speak-header"] = false;
      whiteList["speak-numeral"] = false;
      whiteList["speak-punctuation"] = false;
      whiteList["speech-rate"] = false;
      whiteList["stress"] = false;
      whiteList["string-set"] = false;
      whiteList["tab-size"] = false;
      whiteList["table-layout"] = false;
      whiteList["text-align"] = true;
      whiteList["text-align-last"] = true;
      whiteList["text-combine-upright"] = true;
      whiteList["text-decoration"] = true;
      whiteList["text-decoration-color"] = true;
      whiteList["text-decoration-line"] = true;
      whiteList["text-decoration-skip"] = true;
      whiteList["text-decoration-style"] = true;
      whiteList["text-emphasis"] = true;
      whiteList["text-emphasis-color"] = true;
      whiteList["text-emphasis-position"] = true;
      whiteList["text-emphasis-style"] = true;
      whiteList["text-height"] = true;
      whiteList["text-indent"] = true;
      whiteList["text-justify"] = true;
      whiteList["text-orientation"] = true;
      whiteList["text-overflow"] = true;
      whiteList["text-shadow"] = true;
      whiteList["text-space-collapse"] = true;
      whiteList["text-transform"] = true;
      whiteList["text-underline-position"] = true;
      whiteList["text-wrap"] = true;
      whiteList["top"] = false;
      whiteList["transform"] = false;
      whiteList["transform-origin"] = false;
      whiteList["transform-style"] = false;
      whiteList["transition"] = false;
      whiteList["transition-delay"] = false;
      whiteList["transition-duration"] = false;
      whiteList["transition-property"] = false;
      whiteList["transition-timing-function"] = false;
      whiteList["unicode-bidi"] = false;
      whiteList["vertical-align"] = false;
      whiteList["visibility"] = false;
      whiteList["voice-balance"] = false;
      whiteList["voice-duration"] = false;
      whiteList["voice-family"] = false;
      whiteList["voice-pitch"] = false;
      whiteList["voice-range"] = false;
      whiteList["voice-rate"] = false;
      whiteList["voice-stress"] = false;
      whiteList["voice-volume"] = false;
      whiteList["volume"] = false;
      whiteList["white-space"] = false;
      whiteList["widows"] = false;
      whiteList["width"] = true;
      whiteList["will-change"] = false;
      whiteList["word-break"] = true;
      whiteList["word-spacing"] = true;
      whiteList["word-wrap"] = true;
      whiteList["wrap-flow"] = false;
      whiteList["wrap-through"] = false;
      whiteList["writing-mode"] = false;
      whiteList["z-index"] = false;
      return whiteList;
    }
    __name(getDefaultWhiteList, "getDefaultWhiteList");
    function onAttr(name, value, options) {
    }
    __name(onAttr, "onAttr");
    function onIgnoreAttr(name, value, options) {
    }
    __name(onIgnoreAttr, "onIgnoreAttr");
    var REGEXP_URL_JAVASCRIPT = /javascript\s*\:/img;
    function safeAttrValue(name, value) {
      if (REGEXP_URL_JAVASCRIPT.test(value)) return "";
      return value;
    }
    __name(safeAttrValue, "safeAttrValue");
    exports.whiteList = getDefaultWhiteList();
    exports.getDefaultWhiteList = getDefaultWhiteList;
    exports.onAttr = onAttr;
    exports.onIgnoreAttr = onIgnoreAttr;
    exports.safeAttrValue = safeAttrValue;
  }
});

// ../lib.deadlight/node_modules/cssfilter/lib/util.js
var require_util = __commonJS({
  "../lib.deadlight/node_modules/cssfilter/lib/util.js"(exports, module) {
    init_checked_fetch();
    module.exports = {
      indexOf: /* @__PURE__ */ __name(function(arr, item) {
        var i, j2;
        if (Array.prototype.indexOf) {
          return arr.indexOf(item);
        }
        for (i = 0, j2 = arr.length; i < j2; i++) {
          if (arr[i] === item) {
            return i;
          }
        }
        return -1;
      }, "indexOf"),
      forEach: /* @__PURE__ */ __name(function(arr, fn, scope) {
        var i, j2;
        if (Array.prototype.forEach) {
          return arr.forEach(fn, scope);
        }
        for (i = 0, j2 = arr.length; i < j2; i++) {
          fn.call(scope, arr[i], i, arr);
        }
      }, "forEach"),
      trim: /* @__PURE__ */ __name(function(str) {
        if (String.prototype.trim) {
          return str.trim();
        }
        return str.replace(/(^\s*)|(\s*$)/g, "");
      }, "trim"),
      trimRight: /* @__PURE__ */ __name(function(str) {
        if (String.prototype.trimRight) {
          return str.trimRight();
        }
        return str.replace(/(\s*$)/g, "");
      }, "trimRight")
    };
  }
});

// ../lib.deadlight/node_modules/cssfilter/lib/parser.js
var require_parser = __commonJS({
  "../lib.deadlight/node_modules/cssfilter/lib/parser.js"(exports, module) {
    init_checked_fetch();
    var _2 = require_util();
    function parseStyle(css, onAttr) {
      css = _2.trimRight(css);
      if (css[css.length - 1] !== ";") css += ";";
      var cssLength = css.length;
      var isParenthesisOpen = false;
      var lastPos = 0;
      var i = 0;
      var retCSS = "";
      function addNewAttr() {
        if (!isParenthesisOpen) {
          var source = _2.trim(css.slice(lastPos, i));
          var j3 = source.indexOf(":");
          if (j3 !== -1) {
            var name = _2.trim(source.slice(0, j3));
            var value = _2.trim(source.slice(j3 + 1));
            if (name) {
              var ret = onAttr(lastPos, retCSS.length, name, value, source);
              if (ret) retCSS += ret + "; ";
            }
          }
        }
        lastPos = i + 1;
      }
      __name(addNewAttr, "addNewAttr");
      for (; i < cssLength; i++) {
        var c = css[i];
        if (c === "/" && css[i + 1] === "*") {
          var j2 = css.indexOf("*/", i + 2);
          if (j2 === -1) break;
          i = j2 + 1;
          lastPos = i + 1;
          isParenthesisOpen = false;
        } else if (c === "(") {
          isParenthesisOpen = true;
        } else if (c === ")") {
          isParenthesisOpen = false;
        } else if (c === ";") {
          if (isParenthesisOpen) {
          } else {
            addNewAttr();
          }
        } else if (c === "\n") {
          addNewAttr();
        }
      }
      return _2.trim(retCSS);
    }
    __name(parseStyle, "parseStyle");
    module.exports = parseStyle;
  }
});

// ../lib.deadlight/node_modules/cssfilter/lib/css.js
var require_css = __commonJS({
  "../lib.deadlight/node_modules/cssfilter/lib/css.js"(exports, module) {
    init_checked_fetch();
    var DEFAULT = require_default();
    var parseStyle = require_parser();
    var _2 = require_util();
    function isNull(obj) {
      return obj === void 0 || obj === null;
    }
    __name(isNull, "isNull");
    function shallowCopyObject(obj) {
      var ret = {};
      for (var i in obj) {
        ret[i] = obj[i];
      }
      return ret;
    }
    __name(shallowCopyObject, "shallowCopyObject");
    function FilterCSS(options) {
      options = shallowCopyObject(options || {});
      options.whiteList = options.whiteList || DEFAULT.whiteList;
      options.onAttr = options.onAttr || DEFAULT.onAttr;
      options.onIgnoreAttr = options.onIgnoreAttr || DEFAULT.onIgnoreAttr;
      options.safeAttrValue = options.safeAttrValue || DEFAULT.safeAttrValue;
      this.options = options;
    }
    __name(FilterCSS, "FilterCSS");
    FilterCSS.prototype.process = function(css) {
      css = css || "";
      css = css.toString();
      if (!css) return "";
      var me = this;
      var options = me.options;
      var whiteList = options.whiteList;
      var onAttr = options.onAttr;
      var onIgnoreAttr = options.onIgnoreAttr;
      var safeAttrValue = options.safeAttrValue;
      var retCSS = parseStyle(css, function(sourcePosition, position, name, value, source) {
        var check = whiteList[name];
        var isWhite = false;
        if (check === true) isWhite = check;
        else if (typeof check === "function") isWhite = check(value);
        else if (check instanceof RegExp) isWhite = check.test(value);
        if (isWhite !== true) isWhite = false;
        value = safeAttrValue(name, value);
        if (!value) return;
        var opts = {
          position,
          sourcePosition,
          source,
          isWhite
        };
        if (isWhite) {
          var ret = onAttr(name, value, opts);
          if (isNull(ret)) {
            return name + ":" + value;
          } else {
            return ret;
          }
        } else {
          var ret = onIgnoreAttr(name, value, opts);
          if (!isNull(ret)) {
            return ret;
          }
        }
      });
      return retCSS;
    };
    module.exports = FilterCSS;
  }
});

// ../lib.deadlight/node_modules/cssfilter/lib/index.js
var require_lib = __commonJS({
  "../lib.deadlight/node_modules/cssfilter/lib/index.js"(exports, module) {
    init_checked_fetch();
    var DEFAULT = require_default();
    var FilterCSS = require_css();
    function filterCSS(html, options) {
      var xss = new FilterCSS(options);
      return xss.process(html);
    }
    __name(filterCSS, "filterCSS");
    exports = module.exports = filterCSS;
    exports.FilterCSS = FilterCSS;
    for (i in DEFAULT) exports[i] = DEFAULT[i];
    var i;
    if (typeof window !== "undefined") {
      window.filterCSS = module.exports;
    }
  }
});

// ../lib.deadlight/node_modules/xss/lib/util.js
var require_util2 = __commonJS({
  "../lib.deadlight/node_modules/xss/lib/util.js"(exports, module) {
    init_checked_fetch();
    module.exports = {
      indexOf: /* @__PURE__ */ __name(function(arr, item) {
        var i, j2;
        if (Array.prototype.indexOf) {
          return arr.indexOf(item);
        }
        for (i = 0, j2 = arr.length; i < j2; i++) {
          if (arr[i] === item) {
            return i;
          }
        }
        return -1;
      }, "indexOf"),
      forEach: /* @__PURE__ */ __name(function(arr, fn, scope) {
        var i, j2;
        if (Array.prototype.forEach) {
          return arr.forEach(fn, scope);
        }
        for (i = 0, j2 = arr.length; i < j2; i++) {
          fn.call(scope, arr[i], i, arr);
        }
      }, "forEach"),
      trim: /* @__PURE__ */ __name(function(str) {
        if (String.prototype.trim) {
          return str.trim();
        }
        return str.replace(/(^\s*)|(\s*$)/g, "");
      }, "trim"),
      spaceIndex: /* @__PURE__ */ __name(function(str) {
        var reg = /\s|\n|\t/;
        var match = reg.exec(str);
        return match ? match.index : -1;
      }, "spaceIndex")
    };
  }
});

// ../lib.deadlight/node_modules/xss/lib/default.js
var require_default2 = __commonJS({
  "../lib.deadlight/node_modules/xss/lib/default.js"(exports) {
    init_checked_fetch();
    var FilterCSS = require_lib().FilterCSS;
    var getDefaultCSSWhiteList = require_lib().getDefaultWhiteList;
    var _2 = require_util2();
    function getDefaultWhiteList() {
      return {
        a: ["target", "href", "title"],
        abbr: ["title"],
        address: [],
        area: ["shape", "coords", "href", "alt"],
        article: [],
        aside: [],
        audio: [
          "autoplay",
          "controls",
          "crossorigin",
          "loop",
          "muted",
          "preload",
          "src"
        ],
        b: [],
        bdi: ["dir"],
        bdo: ["dir"],
        big: [],
        blockquote: ["cite"],
        br: [],
        caption: [],
        center: [],
        cite: [],
        code: [],
        col: ["align", "valign", "span", "width"],
        colgroup: ["align", "valign", "span", "width"],
        dd: [],
        del: ["datetime"],
        details: ["open"],
        div: [],
        dl: [],
        dt: [],
        em: [],
        figcaption: [],
        figure: [],
        font: ["color", "size", "face"],
        footer: [],
        h1: [],
        h2: [],
        h3: [],
        h4: [],
        h5: [],
        h6: [],
        header: [],
        hr: [],
        i: [],
        img: ["src", "alt", "title", "width", "height", "loading"],
        ins: ["datetime"],
        kbd: [],
        li: [],
        mark: [],
        nav: [],
        ol: [],
        p: [],
        pre: [],
        s: [],
        section: [],
        small: [],
        span: [],
        sub: [],
        summary: [],
        sup: [],
        strong: [],
        strike: [],
        table: ["width", "border", "align", "valign"],
        tbody: ["align", "valign"],
        td: ["width", "rowspan", "colspan", "align", "valign"],
        tfoot: ["align", "valign"],
        th: ["width", "rowspan", "colspan", "align", "valign"],
        thead: ["align", "valign"],
        tr: ["rowspan", "align", "valign"],
        tt: [],
        u: [],
        ul: [],
        video: [
          "autoplay",
          "controls",
          "crossorigin",
          "loop",
          "muted",
          "playsinline",
          "poster",
          "preload",
          "src",
          "height",
          "width"
        ]
      };
    }
    __name(getDefaultWhiteList, "getDefaultWhiteList");
    var defaultCSSFilter = new FilterCSS();
    function onTag(tag, html, options) {
    }
    __name(onTag, "onTag");
    function onIgnoreTag(tag, html, options) {
    }
    __name(onIgnoreTag, "onIgnoreTag");
    function onTagAttr(tag, name, value) {
    }
    __name(onTagAttr, "onTagAttr");
    function onIgnoreTagAttr(tag, name, value) {
    }
    __name(onIgnoreTagAttr, "onIgnoreTagAttr");
    function escapeHtml2(html) {
      return html.replace(REGEXP_LT, "&lt;").replace(REGEXP_GT, "&gt;");
    }
    __name(escapeHtml2, "escapeHtml");
    function safeAttrValue(tag, name, value, cssFilter) {
      value = friendlyAttrValue(value);
      if (name === "href" || name === "src") {
        value = _2.trim(value);
        if (value === "#") return "#";
        if (!(value.substr(0, 7) === "http://" || value.substr(0, 8) === "https://" || value.substr(0, 7) === "mailto:" || value.substr(0, 4) === "tel:" || value.substr(0, 11) === "data:image/" || value.substr(0, 6) === "ftp://" || value.substr(0, 2) === "./" || value.substr(0, 3) === "../" || value[0] === "#" || value[0] === "/")) {
          return "";
        }
      } else if (name === "background") {
        REGEXP_DEFAULT_ON_TAG_ATTR_4.lastIndex = 0;
        if (REGEXP_DEFAULT_ON_TAG_ATTR_4.test(value)) {
          return "";
        }
      } else if (name === "style") {
        REGEXP_DEFAULT_ON_TAG_ATTR_7.lastIndex = 0;
        if (REGEXP_DEFAULT_ON_TAG_ATTR_7.test(value)) {
          return "";
        }
        REGEXP_DEFAULT_ON_TAG_ATTR_8.lastIndex = 0;
        if (REGEXP_DEFAULT_ON_TAG_ATTR_8.test(value)) {
          REGEXP_DEFAULT_ON_TAG_ATTR_4.lastIndex = 0;
          if (REGEXP_DEFAULT_ON_TAG_ATTR_4.test(value)) {
            return "";
          }
        }
        if (cssFilter !== false) {
          cssFilter = cssFilter || defaultCSSFilter;
          value = cssFilter.process(value);
        }
      }
      value = escapeAttrValue(value);
      return value;
    }
    __name(safeAttrValue, "safeAttrValue");
    var REGEXP_LT = /</g;
    var REGEXP_GT = />/g;
    var REGEXP_QUOTE = /"/g;
    var REGEXP_QUOTE_2 = /&quot;/g;
    var REGEXP_ATTR_VALUE_1 = /&#([a-zA-Z0-9]*);?/gim;
    var REGEXP_ATTR_VALUE_COLON = /&colon;?/gim;
    var REGEXP_ATTR_VALUE_NEWLINE = /&newline;?/gim;
    var REGEXP_DEFAULT_ON_TAG_ATTR_4 = /((j\s*a\s*v\s*a|v\s*b|l\s*i\s*v\s*e)\s*s\s*c\s*r\s*i\s*p\s*t\s*|m\s*o\s*c\s*h\s*a):/gi;
    var REGEXP_DEFAULT_ON_TAG_ATTR_7 = /e\s*x\s*p\s*r\s*e\s*s\s*s\s*i\s*o\s*n\s*\(.*/gi;
    var REGEXP_DEFAULT_ON_TAG_ATTR_8 = /u\s*r\s*l\s*\(.*/gi;
    function escapeQuote(str) {
      return str.replace(REGEXP_QUOTE, "&quot;");
    }
    __name(escapeQuote, "escapeQuote");
    function unescapeQuote(str) {
      return str.replace(REGEXP_QUOTE_2, '"');
    }
    __name(unescapeQuote, "unescapeQuote");
    function escapeHtmlEntities(str) {
      return str.replace(REGEXP_ATTR_VALUE_1, /* @__PURE__ */ __name(function replaceUnicode(str2, code) {
        return code[0] === "x" || code[0] === "X" ? String.fromCharCode(parseInt(code.substr(1), 16)) : String.fromCharCode(parseInt(code, 10));
      }, "replaceUnicode"));
    }
    __name(escapeHtmlEntities, "escapeHtmlEntities");
    function escapeDangerHtml5Entities(str) {
      return str.replace(REGEXP_ATTR_VALUE_COLON, ":").replace(REGEXP_ATTR_VALUE_NEWLINE, " ");
    }
    __name(escapeDangerHtml5Entities, "escapeDangerHtml5Entities");
    function clearNonPrintableCharacter(str) {
      var str2 = "";
      for (var i = 0, len = str.length; i < len; i++) {
        str2 += str.charCodeAt(i) < 32 ? " " : str.charAt(i);
      }
      return _2.trim(str2);
    }
    __name(clearNonPrintableCharacter, "clearNonPrintableCharacter");
    function friendlyAttrValue(str) {
      str = unescapeQuote(str);
      str = escapeHtmlEntities(str);
      str = escapeDangerHtml5Entities(str);
      str = clearNonPrintableCharacter(str);
      return str;
    }
    __name(friendlyAttrValue, "friendlyAttrValue");
    function escapeAttrValue(str) {
      str = escapeQuote(str);
      str = escapeHtml2(str);
      return str;
    }
    __name(escapeAttrValue, "escapeAttrValue");
    function onIgnoreTagStripAll() {
      return "";
    }
    __name(onIgnoreTagStripAll, "onIgnoreTagStripAll");
    function StripTagBody(tags, next) {
      if (typeof next !== "function") {
        next = /* @__PURE__ */ __name(function() {
        }, "next");
      }
      var isRemoveAllTag = !Array.isArray(tags);
      function isRemoveTag(tag) {
        if (isRemoveAllTag) return true;
        return _2.indexOf(tags, tag) !== -1;
      }
      __name(isRemoveTag, "isRemoveTag");
      var removeList = [];
      var posStart = false;
      return {
        onIgnoreTag: /* @__PURE__ */ __name(function(tag, html, options) {
          if (isRemoveTag(tag)) {
            if (options.isClosing) {
              var ret = "[/removed]";
              var end = options.position + ret.length;
              removeList.push([
                posStart !== false ? posStart : options.position,
                end
              ]);
              posStart = false;
              return ret;
            } else {
              if (!posStart) {
                posStart = options.position;
              }
              return "[removed]";
            }
          } else {
            return next(tag, html, options);
          }
        }, "onIgnoreTag"),
        remove: /* @__PURE__ */ __name(function(html) {
          var rethtml = "";
          var lastPos = 0;
          _2.forEach(removeList, function(pos) {
            rethtml += html.slice(lastPos, pos[0]);
            lastPos = pos[1];
          });
          rethtml += html.slice(lastPos);
          return rethtml;
        }, "remove")
      };
    }
    __name(StripTagBody, "StripTagBody");
    function stripCommentTag(html) {
      var retHtml = "";
      var lastPos = 0;
      while (lastPos < html.length) {
        var i = html.indexOf("<!--", lastPos);
        if (i === -1) {
          retHtml += html.slice(lastPos);
          break;
        }
        retHtml += html.slice(lastPos, i);
        var j2 = html.indexOf("-->", i);
        if (j2 === -1) {
          break;
        }
        lastPos = j2 + 3;
      }
      return retHtml;
    }
    __name(stripCommentTag, "stripCommentTag");
    function stripBlankChar(html) {
      var chars = html.split("");
      chars = chars.filter(function(char) {
        var c = char.charCodeAt(0);
        if (c === 127) return false;
        if (c <= 31) {
          if (c === 10 || c === 13) return true;
          return false;
        }
        return true;
      });
      return chars.join("");
    }
    __name(stripBlankChar, "stripBlankChar");
    exports.whiteList = getDefaultWhiteList();
    exports.getDefaultWhiteList = getDefaultWhiteList;
    exports.onTag = onTag;
    exports.onIgnoreTag = onIgnoreTag;
    exports.onTagAttr = onTagAttr;
    exports.onIgnoreTagAttr = onIgnoreTagAttr;
    exports.safeAttrValue = safeAttrValue;
    exports.escapeHtml = escapeHtml2;
    exports.escapeQuote = escapeQuote;
    exports.unescapeQuote = unescapeQuote;
    exports.escapeHtmlEntities = escapeHtmlEntities;
    exports.escapeDangerHtml5Entities = escapeDangerHtml5Entities;
    exports.clearNonPrintableCharacter = clearNonPrintableCharacter;
    exports.friendlyAttrValue = friendlyAttrValue;
    exports.escapeAttrValue = escapeAttrValue;
    exports.onIgnoreTagStripAll = onIgnoreTagStripAll;
    exports.StripTagBody = StripTagBody;
    exports.stripCommentTag = stripCommentTag;
    exports.stripBlankChar = stripBlankChar;
    exports.attributeWrapSign = '"';
    exports.cssFilter = defaultCSSFilter;
    exports.getDefaultCSSWhiteList = getDefaultCSSWhiteList;
  }
});

// ../lib.deadlight/node_modules/xss/lib/parser.js
var require_parser2 = __commonJS({
  "../lib.deadlight/node_modules/xss/lib/parser.js"(exports) {
    init_checked_fetch();
    var _2 = require_util2();
    function getTagName(html) {
      var i = _2.spaceIndex(html);
      var tagName;
      if (i === -1) {
        tagName = html.slice(1, -1);
      } else {
        tagName = html.slice(1, i + 1);
      }
      tagName = _2.trim(tagName).toLowerCase();
      if (tagName.slice(0, 1) === "/") tagName = tagName.slice(1);
      if (tagName.slice(-1) === "/") tagName = tagName.slice(0, -1);
      return tagName;
    }
    __name(getTagName, "getTagName");
    function isClosing(html) {
      return html.slice(0, 2) === "</";
    }
    __name(isClosing, "isClosing");
    function parseTag(html, onTag, escapeHtml2) {
      "use strict";
      var rethtml = "";
      var lastPos = 0;
      var tagStart = false;
      var quoteStart = false;
      var currentPos = 0;
      var len = html.length;
      var currentTagName = "";
      var currentHtml = "";
      chariterator: for (currentPos = 0; currentPos < len; currentPos++) {
        var c = html.charAt(currentPos);
        if (tagStart === false) {
          if (c === "<") {
            tagStart = currentPos;
            continue;
          }
        } else {
          if (quoteStart === false) {
            if (c === "<") {
              rethtml += escapeHtml2(html.slice(lastPos, currentPos));
              tagStart = currentPos;
              lastPos = currentPos;
              continue;
            }
            if (c === ">" || currentPos === len - 1) {
              rethtml += escapeHtml2(html.slice(lastPos, tagStart));
              currentHtml = html.slice(tagStart, currentPos + 1);
              currentTagName = getTagName(currentHtml);
              rethtml += onTag(
                tagStart,
                rethtml.length,
                currentTagName,
                currentHtml,
                isClosing(currentHtml)
              );
              lastPos = currentPos + 1;
              tagStart = false;
              continue;
            }
            if (c === '"' || c === "'") {
              var i = 1;
              var ic = html.charAt(currentPos - i);
              while (ic.trim() === "" || ic === "=") {
                if (ic === "=") {
                  quoteStart = c;
                  continue chariterator;
                }
                ic = html.charAt(currentPos - ++i);
              }
            }
          } else {
            if (c === quoteStart) {
              quoteStart = false;
              continue;
            }
          }
        }
      }
      if (lastPos < len) {
        rethtml += escapeHtml2(html.substr(lastPos));
      }
      return rethtml;
    }
    __name(parseTag, "parseTag");
    var REGEXP_ILLEGAL_ATTR_NAME = /[^a-zA-Z0-9\\_:.-]/gim;
    function parseAttr(html, onAttr) {
      "use strict";
      var lastPos = 0;
      var lastMarkPos = 0;
      var retAttrs = [];
      var tmpName = false;
      var len = html.length;
      function addAttr(name, value) {
        name = _2.trim(name);
        name = name.replace(REGEXP_ILLEGAL_ATTR_NAME, "").toLowerCase();
        if (name.length < 1) return;
        var ret = onAttr(name, value || "");
        if (ret) retAttrs.push(ret);
      }
      __name(addAttr, "addAttr");
      for (var i = 0; i < len; i++) {
        var c = html.charAt(i);
        var v2, j2;
        if (tmpName === false && c === "=") {
          tmpName = html.slice(lastPos, i);
          lastPos = i + 1;
          lastMarkPos = html.charAt(lastPos) === '"' || html.charAt(lastPos) === "'" ? lastPos : findNextQuotationMark(html, i + 1);
          continue;
        }
        if (tmpName !== false) {
          if (i === lastMarkPos) {
            j2 = html.indexOf(c, i + 1);
            if (j2 === -1) {
              break;
            } else {
              v2 = _2.trim(html.slice(lastMarkPos + 1, j2));
              addAttr(tmpName, v2);
              tmpName = false;
              i = j2;
              lastPos = i + 1;
              continue;
            }
          }
        }
        if (/\s|\n|\t/.test(c)) {
          html = html.replace(/\s|\n|\t/g, " ");
          if (tmpName === false) {
            j2 = findNextEqual(html, i);
            if (j2 === -1) {
              v2 = _2.trim(html.slice(lastPos, i));
              addAttr(v2);
              tmpName = false;
              lastPos = i + 1;
              continue;
            } else {
              i = j2 - 1;
              continue;
            }
          } else {
            j2 = findBeforeEqual(html, i - 1);
            if (j2 === -1) {
              v2 = _2.trim(html.slice(lastPos, i));
              v2 = stripQuoteWrap(v2);
              addAttr(tmpName, v2);
              tmpName = false;
              lastPos = i + 1;
              continue;
            } else {
              continue;
            }
          }
        }
      }
      if (lastPos < html.length) {
        if (tmpName === false) {
          addAttr(html.slice(lastPos));
        } else {
          addAttr(tmpName, stripQuoteWrap(_2.trim(html.slice(lastPos))));
        }
      }
      return _2.trim(retAttrs.join(" "));
    }
    __name(parseAttr, "parseAttr");
    function findNextEqual(str, i) {
      for (; i < str.length; i++) {
        var c = str[i];
        if (c === " ") continue;
        if (c === "=") return i;
        return -1;
      }
    }
    __name(findNextEqual, "findNextEqual");
    function findNextQuotationMark(str, i) {
      for (; i < str.length; i++) {
        var c = str[i];
        if (c === " ") continue;
        if (c === "'" || c === '"') return i;
        return -1;
      }
    }
    __name(findNextQuotationMark, "findNextQuotationMark");
    function findBeforeEqual(str, i) {
      for (; i > 0; i--) {
        var c = str[i];
        if (c === " ") continue;
        if (c === "=") return i;
        return -1;
      }
    }
    __name(findBeforeEqual, "findBeforeEqual");
    function isQuoteWrapString(text) {
      if (text[0] === '"' && text[text.length - 1] === '"' || text[0] === "'" && text[text.length - 1] === "'") {
        return true;
      } else {
        return false;
      }
    }
    __name(isQuoteWrapString, "isQuoteWrapString");
    function stripQuoteWrap(text) {
      if (isQuoteWrapString(text)) {
        return text.substr(1, text.length - 2);
      } else {
        return text;
      }
    }
    __name(stripQuoteWrap, "stripQuoteWrap");
    exports.parseTag = parseTag;
    exports.parseAttr = parseAttr;
  }
});

// ../lib.deadlight/node_modules/xss/lib/xss.js
var require_xss = __commonJS({
  "../lib.deadlight/node_modules/xss/lib/xss.js"(exports, module) {
    init_checked_fetch();
    var FilterCSS = require_lib().FilterCSS;
    var DEFAULT = require_default2();
    var parser = require_parser2();
    var parseTag = parser.parseTag;
    var parseAttr = parser.parseAttr;
    var _2 = require_util2();
    function isNull(obj) {
      return obj === void 0 || obj === null;
    }
    __name(isNull, "isNull");
    function getAttrs(html) {
      var i = _2.spaceIndex(html);
      if (i === -1) {
        return {
          html: "",
          closing: html[html.length - 2] === "/"
        };
      }
      html = _2.trim(html.slice(i + 1, -1));
      var isClosing = html[html.length - 1] === "/";
      if (isClosing) html = _2.trim(html.slice(0, -1));
      return {
        html,
        closing: isClosing
      };
    }
    __name(getAttrs, "getAttrs");
    function shallowCopyObject(obj) {
      var ret = {};
      for (var i in obj) {
        ret[i] = obj[i];
      }
      return ret;
    }
    __name(shallowCopyObject, "shallowCopyObject");
    function keysToLowerCase(obj) {
      var ret = {};
      for (var i in obj) {
        if (Array.isArray(obj[i])) {
          ret[i.toLowerCase()] = obj[i].map(function(item) {
            return item.toLowerCase();
          });
        } else {
          ret[i.toLowerCase()] = obj[i];
        }
      }
      return ret;
    }
    __name(keysToLowerCase, "keysToLowerCase");
    function FilterXSS(options) {
      options = shallowCopyObject(options || {});
      if (options.stripIgnoreTag) {
        if (options.onIgnoreTag) {
          console.error(
            'Notes: cannot use these two options "stripIgnoreTag" and "onIgnoreTag" at the same time'
          );
        }
        options.onIgnoreTag = DEFAULT.onIgnoreTagStripAll;
      }
      if (options.whiteList || options.allowList) {
        options.whiteList = keysToLowerCase(options.whiteList || options.allowList);
      } else {
        options.whiteList = DEFAULT.whiteList;
      }
      this.attributeWrapSign = options.singleQuotedAttributeValue === true ? "'" : DEFAULT.attributeWrapSign;
      options.onTag = options.onTag || DEFAULT.onTag;
      options.onTagAttr = options.onTagAttr || DEFAULT.onTagAttr;
      options.onIgnoreTag = options.onIgnoreTag || DEFAULT.onIgnoreTag;
      options.onIgnoreTagAttr = options.onIgnoreTagAttr || DEFAULT.onIgnoreTagAttr;
      options.safeAttrValue = options.safeAttrValue || DEFAULT.safeAttrValue;
      options.escapeHtml = options.escapeHtml || DEFAULT.escapeHtml;
      this.options = options;
      if (options.css === false) {
        this.cssFilter = false;
      } else {
        options.css = options.css || {};
        this.cssFilter = new FilterCSS(options.css);
      }
    }
    __name(FilterXSS, "FilterXSS");
    FilterXSS.prototype.process = function(html) {
      html = html || "";
      html = html.toString();
      if (!html) return "";
      var me = this;
      var options = me.options;
      var whiteList = options.whiteList;
      var onTag = options.onTag;
      var onIgnoreTag = options.onIgnoreTag;
      var onTagAttr = options.onTagAttr;
      var onIgnoreTagAttr = options.onIgnoreTagAttr;
      var safeAttrValue = options.safeAttrValue;
      var escapeHtml2 = options.escapeHtml;
      var attributeWrapSign = me.attributeWrapSign;
      var cssFilter = me.cssFilter;
      if (options.stripBlankChar) {
        html = DEFAULT.stripBlankChar(html);
      }
      if (!options.allowCommentTag) {
        html = DEFAULT.stripCommentTag(html);
      }
      var stripIgnoreTagBody = false;
      if (options.stripIgnoreTagBody) {
        stripIgnoreTagBody = DEFAULT.StripTagBody(
          options.stripIgnoreTagBody,
          onIgnoreTag
        );
        onIgnoreTag = stripIgnoreTagBody.onIgnoreTag;
      }
      var retHtml = parseTag(
        html,
        function(sourcePosition, position, tag, html2, isClosing) {
          var info = {
            sourcePosition,
            position,
            isClosing,
            isWhite: Object.prototype.hasOwnProperty.call(whiteList, tag)
          };
          var ret = onTag(tag, html2, info);
          if (!isNull(ret)) return ret;
          if (info.isWhite) {
            if (info.isClosing) {
              return "</" + tag + ">";
            }
            var attrs = getAttrs(html2);
            var whiteAttrList = whiteList[tag];
            var attrsHtml = parseAttr(attrs.html, function(name, value) {
              var isWhiteAttr = _2.indexOf(whiteAttrList, name) !== -1;
              var ret2 = onTagAttr(tag, name, value, isWhiteAttr);
              if (!isNull(ret2)) return ret2;
              if (isWhiteAttr) {
                value = safeAttrValue(tag, name, value, cssFilter);
                if (value) {
                  return name + "=" + attributeWrapSign + value + attributeWrapSign;
                } else {
                  return name;
                }
              } else {
                ret2 = onIgnoreTagAttr(tag, name, value, isWhiteAttr);
                if (!isNull(ret2)) return ret2;
                return;
              }
            });
            html2 = "<" + tag;
            if (attrsHtml) html2 += " " + attrsHtml;
            if (attrs.closing) html2 += " /";
            html2 += ">";
            return html2;
          } else {
            ret = onIgnoreTag(tag, html2, info);
            if (!isNull(ret)) return ret;
            return escapeHtml2(html2);
          }
        },
        escapeHtml2
      );
      if (stripIgnoreTagBody) {
        retHtml = stripIgnoreTagBody.remove(retHtml);
      }
      return retHtml;
    };
    module.exports = FilterXSS;
  }
});

// ../lib.deadlight/node_modules/xss/lib/index.js
var require_lib2 = __commonJS({
  "../lib.deadlight/node_modules/xss/lib/index.js"(exports, module) {
    init_checked_fetch();
    var DEFAULT = require_default2();
    var parser = require_parser2();
    var FilterXSS = require_xss();
    function filterXSS2(html, options) {
      var xss = new FilterXSS(options);
      return xss.process(html);
    }
    __name(filterXSS2, "filterXSS");
    exports = module.exports = filterXSS2;
    exports.filterXSS = filterXSS2;
    exports.FilterXSS = FilterXSS;
    (function() {
      for (var i in DEFAULT) {
        exports[i] = DEFAULT[i];
      }
      for (var j2 in parser) {
        exports[j2] = parser[j2];
      }
    })();
    if (typeof window !== "undefined") {
      window.filterXSS = module.exports;
    }
    function isWorkerEnv() {
      return typeof self !== "undefined" && typeof DedicatedWorkerGlobalScope !== "undefined" && self instanceof DedicatedWorkerGlobalScope;
    }
    __name(isWorkerEnv, "isWorkerEnv");
    if (isWorkerEnv()) {
      self.filterXSS = module.exports;
    }
  }
});

// ../lib.deadlight/core/src/markdown/processor.js
function renderMarkdown(content) {
  return defaultProcessor.render(content);
}
var import_xss, MarkdownProcessor, defaultProcessor;
var init_processor = __esm({
  "../lib.deadlight/core/src/markdown/processor.js"() {
    init_checked_fetch();
    init_marked_esm();
    import_xss = __toESM(require_lib2(), 1);
    MarkdownProcessor = class {
      static {
        __name(this, "MarkdownProcessor");
      }
      constructor(options = {}) {
        this.options = {
          gfm: true,
          breaks: true,
          headerIds: false,
          mangle: false,
          ...options
        };
        this.xssOptions = options.xssOptions || {
          whiteList: {
            h1: [],
            h2: [],
            h3: [],
            h4: [],
            h5: [],
            h6: [],
            p: [],
            br: [],
            hr: [],
            a: ["href", "title", "target", "rel"],
            strong: [],
            em: [],
            del: [],
            ul: [],
            ol: [],
            li: [],
            code: ["class"],
            pre: [],
            blockquote: [],
            table: [],
            thead: [],
            tbody: [],
            tr: [],
            th: [],
            td: []
          },
          stripIgnoreTag: true,
          stripIgnoreTagBody: ["script"]
        };
        this.setupRenderer();
      }
      setupRenderer() {
        d.setOptions(this.options);
        this.renderer = new d.Renderer();
        this.renderer.code = (code, language) => {
          const codeString = String(code || "");
          const lang = language || "";
          const escapedCode = codeString.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
          return `<pre><code class="language-${lang}">${escapedCode}</code></pre>`;
        };
        d.use({ renderer: this.renderer });
      }
      render(content) {
        try {
          const html = d(content);
          return (0, import_xss.filterXSS)(html, this.xssOptions);
        } catch (error) {
          console.error("Markdown rendering error:", error);
          return content;
        }
      }
      stripContent(content) {
        return content.replace(/#{1,6}\s/g, "").replace(/\*\*(.+?)\*\*/g, "$1").replace(/\*(.+?)\*/g, "$1").replace(/\[(.*?)\]\((.*?)\)/g, "$1").replace(/`(.+?)`/g, "$1").trim();
      }
      // Refined excerpt extraction with intra-paragraph truncation
      extractExcerpt(content, maxLength = 300) {
        const moreIndex = content.indexOf("<!--more-->");
        if (moreIndex !== -1) {
          return content.substring(0, moreIndex).trim();
        }
        const sections = [];
        const lines = content.split("\n");
        let insideCodeBlock = false;
        let currentSection = [];
        for (const line of lines) {
          if (line.trim().startsWith("```")) {
            if (insideCodeBlock) {
              insideCodeBlock = false;
              if (currentSection.length > 0) {
                sections.push(currentSection.join("\n"));
              }
            } else {
              insideCodeBlock = true;
              if (currentSection.length > 0) {
                sections.push(currentSection.join("\n"));
                break;
              }
            }
          } else if (!insideCodeBlock) {
            currentSection.push(line);
          }
        }
        if (currentSection.length > 0 && !insideCodeBlock) {
          sections.push(currentSection.join("\n"));
        }
        let fullText = sections.join("\n\n").trim();
        const paragraphs = fullText.split("\n\n").filter((p) => p.trim());
        let excerptParagraphs = [];
        let currentLength = 0;
        for (const paragraph of paragraphs) {
          const textLength = this.stripContent(paragraph).length;
          const remaining = maxLength - currentLength;
          if (remaining <= 0) {
            break;
          }
          if (textLength <= remaining) {
            excerptParagraphs.push(paragraph);
            currentLength += textLength;
          } else {
            let rawSoFar = "";
            for (let i = 0; i < paragraph.length; i++) {
              rawSoFar += paragraph[i];
              const strippedSoFarLength = this.stripContent(rawSoFar).length;
              if (strippedSoFarLength >= remaining) {
                break;
              }
            }
            const cutAt = rawSoFar.lastIndexOf(" ");
            if (cutAt > 0) {
              rawSoFar = rawSoFar.substring(0, cutAt) + "...";
            } else {
              rawSoFar += "...";
            }
            excerptParagraphs.push(rawSoFar);
            break;
          }
        }
        let excerpt = excerptParagraphs.join("\n\n").trim();
        if (excerptParagraphs.length < paragraphs.length || content.length > maxLength) {
          if (!excerpt.endsWith("...")) {
            excerpt += "\n\n...";
          }
        }
        return excerpt || "Read more...";
      }
      hasMore(content, maxLength = 300) {
        if (content.includes("```") || content.includes("<!--more-->")) {
          return true;
        }
        const textLength = this.stripContent(
          content.replace(/```[\s\S]*?```/g, "")
          // Remove code blocks for length check
        ).length;
        return textLength > maxLength * 2;
      }
    };
    defaultProcessor = new MarkdownProcessor();
    __name(renderMarkdown, "renderMarkdown");
  }
});

// src/templates/user/profile.js
var profile_exports = {};
__export(profile_exports, {
  renderUserProfile: () => renderUserProfile
});
function renderUserProfile(user, posts, currentUser, config2, pagination2) {
  function createExcerpt(content2, maxLength = 200) {
    const plainText = content2.replace(/[#*`$$$$]/g, "").trim();
    return plainText.length > maxLength ? plainText.substring(0, maxLength) + "..." : plainText;
  }
  __name(createExcerpt, "createExcerpt");
  const pageTitle = user.profile_title || `${user.username}'s Posts`;
  const content = `
    <div class="user-profile">
      <header class="profile-header">
        <div class="profile-info">
          <h1>${pageTitle}</h1>
          <p class="username">@${user.username}</p>
          ${user.profile_description ? `
            <div class="profile-description">
              ${renderMarkdown(user.profile_description)}
            </div>
          ` : ""}
          <div class="profile-stats">
            <span>${user.post_count} post${user.post_count !== 1 ? "s" : ""}</span>
            ${user.last_post_date ? `
              <span>\u2022</span>
              <span>Last post ${new Date(user.last_post_date).toLocaleDateString()}</span>
            ` : ""}
          </div>
        </div>
        
        ${currentUser && currentUser.id === user.id ? `
          <div class="profile-actions">
            <a href="/admin/add" class="button">Write Post</a>
            <a href="/user/${user.username}/settings" class="button secondary">Edit Profile</a>
          </div>
        ` : ""}
      </header>

      <div class="posts-section">
        <h2>Posts</h2>
        ${posts && posts.length > 0 ? `
          <div class="post-list">
            ${posts.map((post) => `
              <article class="post-preview">
                <header class="post-header">
                  <h3><a href="/post/${post.slug || post.id}">${post.title}</a></h3>
                  <time class="post-date" datetime="${post.created_at}">
                    ${new Date(post.created_at).toLocaleDateString()}
                  </time>
                </header>
                <div class="post-excerpt">
                  ${post.excerpt ? renderMarkdown(post.excerpt) : `
                    <p>${createExcerpt(post.content)}</p>
                  `}
                </div>
                <footer class="post-footer">
                  <a href="/post/${post.slug || post.id}" class="read-more">Read more \u2192</a>
                </footer>
              </article>
            `).join("")}
          </div>
          
          ${pagination2.totalPages > 1 ? `
            <nav class="pagination">
              ${pagination2.hasPrevious ? `
                <a href="/user/${user.username}?page=${pagination2.previousPage}" class="button secondary">\u2190 Previous</a>
              ` : ""}
              
              <span class="page-info">
                Page ${pagination2.currentPage} of ${pagination2.totalPages}
              </span>
              
              ${pagination2.hasNext ? `
                <a href="/user/${user.username}?page=${pagination2.nextPage}" class="button secondary">Next \u2192</a>
              ` : ""}
            </nav>
          ` : ""}
        ` : `
          <div class="empty-state">
            <p>${user.username} hasn't posted anything yet.</p>
            ${currentUser && currentUser.id === user.id ? `
              <a href="/admin/add" class="button">Write your first post</a>
            ` : ""}
          </div>
        `}
      </div>
    </div>
  `;
  return renderTemplate(pageTitle, content, currentUser, config2);
}
var init_profile = __esm({
  "src/templates/user/profile.js"() {
    init_checked_fetch();
    init_base2();
    init_processor();
    __name(renderUserProfile, "renderUserProfile");
  }
});

// .wrangler/tmp/bundle-Q0vcA9/middleware-loader.entry.ts
init_checked_fetch();

// .wrangler/tmp/bundle-Q0vcA9/middleware-insertion-facade.js
init_checked_fetch();

// src/index.js
init_checked_fetch();

// src/routes/index.js
init_checked_fetch();
var Router = class {
  static {
    __name(this, "Router");
  }
  constructor() {
    this.routes = /* @__PURE__ */ new Map();
    this.middlewares = [];
  }
  use(middleware) {
    if (typeof middleware !== "function") {
      throw new Error("Middleware must be a function");
    }
    this.middlewares.push(middleware);
    return this;
  }
  register(path, handlers) {
    console.log("Registering route:", path);
    const routePattern = path.replace(/\/:(\w+)/g, "/(?<$1>[^/]+)");
    this.routes.set(routePattern, {
      pattern: new RegExp(`^${routePattern}$`),
      handlers
    });
  }
  async handle(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    console.log("Handling request for path:", pathname);
    console.log("Available routes:", Array.from(this.routes.keys()));
    let matchedRoute = null;
    let params = {};
    for (const [_2, route] of this.routes) {
      const match = pathname.match(route.pattern);
      if (match) {
        const handler2 = route.handlers[request.method];
        if (handler2) {
          matchedRoute = handler2;
          params = match.groups || {};
          break;
        }
      }
    }
    if (!matchedRoute) {
      throw new Error("Not Found");
    }
    request.params = params;
    request.query = Object.fromEntries(url.searchParams);
    const chain = [...this.middlewares];
    let handler = matchedRoute;
    for (let i = chain.length - 1; i >= 0; i--) {
      const middleware = chain[i];
      const nextHandler = handler;
      handler = /* @__PURE__ */ __name(async (req, env2) => {
        return await middleware(req, env2, async () => {
          return await nextHandler(req, env2);
        });
      }, "handler");
    }
    return await handler(request, env);
  }
};

// src/routes/styles.js
init_checked_fetch();
var CACHE_HEADERS = {
  "Content-Type": "text/css",
  "Cache-Control": "public, max-age=3600"
};
var baseStyles = `
  /* CSS Variables for theming */
  :root {
    --font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --max-width: 900px;
    --border-radius: 4px;
    --transition: all 0.2s ease;
  }

  /* Base Reset */
  * {
    box-sizing: border-box;
  }

  body {
    font-family: var(--font-family);
    background-color: var(--bg-primary);
    color: var(--text-primary);
    margin: 0;
    padding: 20px;
    line-height: 1.6;
  }

  /* Layout */
  .container {
    max-width: var(--max-width);
    margin: 0 auto;
    padding: 20px;
  }

  .auth-container {
    max-width: 400px;
    margin: 0 auto;
    padding: 20px;
  }

  /* Header */
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border-color);
  }

  header h1 {
    margin: 0;
    font-size: 1.8rem;
  }

  header h1 a {
    color: var(--text-primary);
    text-decoration: none;
  }

  /* Navigation */
  nav {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  nav a {
    color: var(--link-color);
    text-decoration: none;
    padding: 0.5rem 1rem;
    border-radius: var(--border-radius);
    transition: var(--transition);
  }

  nav a:hover {
    background-color: var(--nav-hover-bg);
    color: var(--nav-hover-color);
  }

  /* Typography */
  h1, h2, h3, h4, h5, h6 {
    color: var(--text-primary);
    margin-top: 0;
  }

  a {
    color: var(--link-color);
    text-decoration: none;
    transition: var(--transition);
  }

  a:hover {
    color: var(--link-hover);
    text-decoration: underline;
  }

  /* Forms */
  input, textarea {
    width: 100%;
    padding: 10px;
    margin: 10px 0;
    border: 1px solid var(--input-border);
    background-color: var(--input-bg);
    color: var(--text-primary);
    font-size: 1em;
    border-radius: var(--border-radius);
    font-family: var(--font-family);
  }

  textarea {
    min-height: 200px;
    resize: vertical;
  }

  /* Buttons - Ensure consistency */
  button,
  .button,
  a.button,
  .edit-button,
  .delete-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 8px 16px;
    margin: 0;
    border: none;
    border-radius: var(--border-radius);
    font-size: 0.875rem;
    font-weight: 500;
    line-height: 1.2;
    cursor: pointer;
    transition: var(--transition);
    text-decoration: none;
    font-family: var(--font-family);
  }

  /* Primary button style */
  button:not(.delete-button),
  .button:not(.edit-button):not(.delete-button) {
    background-color: var(--button-primary-bg);
    color: var(--button-primary-text);
  }

  button:not(.delete-button):hover,
  .button:not(.edit-button):not(.delete-button):hover {
    background-color: var(--button-primary-hover);
  }

  /* Edit buttons */
  .edit-button,
  a.edit-button {
    background-color: var(--button-secondary-bg);
    color: var(--button-secondary-text);
  }

  .edit-button:hover,
  a.edit-button:hover {
    background-color: var(--button-secondary-hover);
    color: var(--button-secondary-text);
  }

  /* Delete buttons */
  .delete-button,
  button.delete-button,
  .delete-link button {
    background-color: var(--button-danger-bg);
    color: var(--button-danger-text);
  }

  .delete-button:hover,
  button.delete-button:hover,
  .delete-link button:hover {
    background-color: var(--button-danger-hover);
    color: var(--button-danger-text);
  }

  /* Post Styles */
  article,
  .post-preview {
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 2rem;
    margin-bottom: 2rem;
  }

  article:last-child,
  .post-preview:last-child {
    border-bottom: none;
  }

  article h2,
  .post-preview h2 {
    margin-bottom: 0.5rem;
    font-size: 1.5rem;
  }

  .post-preview h2 a {
    color: var(--text-primary);
    text-decoration: none;
  }

  .post-preview h2 a:hover {
    color: var(--link-color);
  }

  .post-meta {
    color: var(--text-secondary);
    font-size: 0.9rem;
    margin-bottom: 1rem;
  }

  /* Add to baseStyles */
  .post-excerpt {
    margin: 1rem 0;
    color: var(--text-primary);
    line-height: 1.6;
    max-width: 100%;  /* Ensure it doesn't overflow */
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border-secondary);
    margin-bottom: 1rem;
  }

  /* For really long single-line excerpts */
  .post-excerpt p {
    margin-bottom: 1em; /* Or adjust to 1.5em etc. to match your theme's "blank line" feel */
    word-wrap: break-word;
    overflow-wrap: break-word;
  }

  time {
    color: var(--text-secondary);
  }

  /* Post Content */
  .post-content {
    color: var(--text-primary);
    margin-bottom: 1rem;
  }

  .post-content h1 { font-size: 2em; margin: 0.67em 0; }
  .post-content h2 { font-size: 1.5em; margin: 0.83em 0; }
  .post-content h3 { font-size: 1.17em; margin: 1em 0; }
  .post-content h4 { font-size: 1em; margin: 1.33em 0; }
  .post-content h5 { font-size: 0.83em; margin: 1.67em 0; }
  .post-content h6 { font-size: 0.67em; margin: 2.33em 0; }

  .post-content pre {
    background: var(--code-bg);
    padding: 1rem;
    border-radius: var(--border-radius);
    overflow-x: auto;
    margin: 1em 0;
  }

  .post-content code {
    background: var(--code-bg);
    padding: 0.2em 0.4em;
    border-radius: 3px;
    font-size: 0.9em;
  }

  .post-content blockquote {
    border-left: 4px solid var(--border-color);
    margin: 1em 0;
    padding-left: 1em;
    color: var(--text-secondary);
  }

  /* Post actions container */
  .post-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 1rem;
    flex-wrap: nowrap;  /* Prevent wrapping */
  }

  .post-actions {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    flex-shrink: 0;  /* Prevent shrinking */
  }

  .delete-link {
    display: inline-flex;
    margin: 0;
  }

  .read-more {
    color: var(--link-color);
    font-weight: 500;
  }

  /* Single Post */
  .single-post {
    max-width: 800px;
    margin: 0 auto;
  }

  .single-post .post-header {
    text-align: center;
    margin-bottom: 3rem;
  }

  .single-post h1 {
    font-size: 2.5rem;
    margin-bottom: 1rem;
  }

  .single-post .post-content {
    font-size: 1.1rem;
    line-height: 1.8;
  }

  .single-post .post-actions {
    margin-top: 2rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border-color);
  }

  /* Post Navigation */
  .post-navigation {
    display: flex;
    justify-content: space-between;
    margin-top: 3rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border-color);
  }

  .nav-prev, .nav-next {
    display: flex;
    flex-direction: column;
    text-decoration: none;
    color: var(--text-primary);
    max-width: 45%;
  }

  .nav-next {
    text-align: right;
    align-items: flex-end;
  }

  .nav-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin-bottom: 0.25rem;
  }

  .nav-title {
    font-weight: 500;
    color: var(--text-primary);
  }

  /* Pagination */
  .pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 0.5rem;
    margin-top: 3rem;
    padding: 1rem;
  }

  .pagination-link {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 2.5rem;
    height: 2.5rem;
    padding: 0.5rem;
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    text-decoration: none;
    color: var(--text-primary);
    background-color: var(--bg-primary);
    transition: var(--transition);
    font-weight: 500;
  }

  .pagination-link:hover:not(.pagination-disabled):not(.pagination-current) {
    background-color: var(--bg-secondary);
    border-color: var(--border-hover);
    text-decoration: none;
  }

  .pagination-current {
    background-color: var(--button-primary-bg);
    color: var(--button-primary-text);
    border-color: var(--button-primary-bg);
  }

  .pagination-disabled {
    opacity: 0.5;
    cursor: not-allowed;
    pointer-events: none;
  }

  /* Theme Toggle - back to bottom right */
  .theme-toggle-container {
    position: fixed;
    bottom: 20px;
    right: 20px;
    z-index: 1000;
  }


  .theme-toggle {
    border: 2px solid var(--border-color);
    border-radius: 50%;
    width: 50px;
    height: 50px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition);
  }

  .theme-toggle:hover {
    transform: scale(1.05);
  }

  /* Messages */
  .success-message,
  .error-message {
    padding: 1rem;
    margin: 1rem 0;
    border-radius: var(--border-radius);
  }

  .success-message {
    background-color: var(--success-bg);
    color: var(--success-text);
    border: 1px solid var(--success-border);
  }

  .error-message {
    background-color: var(--error-bg);
    color: var(--error-text);
    border: 1px solid var(--error-border);
  }

  /* Mobile */
  @media (max-width: 600px) {
    body {
      padding: 10px;
    }
    
    .container {
      padding: 10px;
    }
    
    header {
      flex-direction: column;
      text-align: center;
      gap: 1rem;
    }
    
    nav {
      flex-wrap: wrap;
      justify-content: center;
    }
  }

  /* Admin Dashboard */
  .admin-dashboard {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
  }

  .stat-card {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
    text-align: center;
  }

  .stat-card h3 {
    margin: 0 0 0.5rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stat-number {
    font-size: 2.5rem;
    font-weight: bold;
    color: var(--text-primary);
  }

  .quick-actions {
    margin-bottom: 3rem;
  }

  .action-buttons {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
  }

  /* Simple Chart */
  .chart-section {
    margin-bottom: 3rem;
  }

  .simple-chart {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    height: 200px;
    padding: 1rem;
    background: var(--bg-secondary);
    border-radius: var(--border-radius);
    gap: 0.5rem;
  }

  .chart-bar {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-end;
    position: relative;
    height: 100%;
  }

  .chart-bar .bar {
    width: 100%;
    background: var(--button-primary-bg);
    border-radius: var(--border-radius) var(--border-radius) 0 0;
    height: var(--height);
    transition: height 0.3s ease;
  }

  .chart-bar .label {
    font-size: 0.75rem;
    margin-top: 0.5rem;
    color: var(--text-secondary);
  }

  .chart-bar .value {
    position: absolute;
    bottom: calc(var(--height) + 0.25rem);
    font-size: 0.75rem;
    font-weight: bold;
  }

  /* Data Table */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-secondary);
    border-radius: var(--border-radius);
    overflow: hidden;
  }

  .data-table th,
  .data-table td {
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
  }

  .data-table th {
    background: var(--bg-primary);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-size: 0.875rem;
  }

  .data-table tr:last-child td {
    border-bottom: none;
  }

  .data-table tr:hover {
    background: var(--bg-primary);
  }

  .small-button {
    padding: 0.25rem 0.75rem;
    font-size: 0.875rem;
    margin-right: 0.5rem;
  }

  /* Mobile Responsive */
  @media (max-width: 768px) {
    .stats-grid {
      grid-template-columns: 1fr 1fr;
    }
    
    .simple-chart {
      padding: 0.5rem;
    }
    
    .chart-bar .value {
      font-size: 0.625rem;
    }
    
    .data-table {
      font-size: 0.875rem;
    }
    
    .data-table th,
    .data-table td {
      padding: 0.5rem;
    }
  }

  /* Page Header */
  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }

  /* Badge */
  .badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    font-size: 0.75rem;
    background: var(--button-primary-bg);
    color: var(--button-primary-text);
    border-radius: var(--border-radius);
    margin-left: 0.5rem;
  }

  /* Info Box */
  .info-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    padding: 1rem;
    margin: 2rem 0;
  }

  .info-box p {
    margin: 0;
    color: var(--text-secondary);
  }

  /* Settings */
  .settings-grid {
    display: grid;
    gap: 2rem;
    margin-bottom: 2rem;
  }

  .setting-group {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
  }

  .setting-group h3 {
    margin-top: 0;
    margin-bottom: 1rem;
    color: var(--text-primary);
  }

  .setting-item {
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
    align-items: center;
  }

  .setting-item:last-child {
    margin-bottom: 0;
  }

  .setting-item label {
    font-weight: 500;
    color: var(--text-secondary);
  }

  .setting-value {
    color: var(--text-primary);
  }

  .future-settings ul {
    list-style: none;
    padding: 0;
  }

  .future-settings li {
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border-color);
  }

  .muted {
    color: var(--text-secondary);
  }

  .link-button {
    background: none;
    border: none;
    color: inherit;
    text-decoration: underline;
    cursor: pointer;
    font: inherit;
    padding: 0;
  }

  /* Admin Dashboard Specific */
  .page-header {
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border-color);
  }

  .page-header h1 {
    margin: 0 0 1rem 0;
    font-size: 2rem;
    font-weight: 600;
  }

  .admin-nav {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 0.9rem;
  }

  .admin-nav a {
    color: var(--link-color);
    text-decoration: none;
    padding: 0.25rem 0;
    transition: var(--transition);
  }

  .admin-nav a:hover {
    color: var(--link-hover);
  }

  .admin-nav a.active {
    font-weight: 600;
    color: var(--text-primary);
  }

  .nav-separator {
    color: var(--text-secondary);
    user-select: none;
  }

  /* Stats Grid */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
  }

  .stat-card {
    background: var(--bg-secondary);
    padding: 2rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
    text-align: center;
    transition: var(--transition);
  }

  .stat-card:hover {
    border-color: var(--border-hover);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  }

  .stat-card h3 {
    margin: 0 0 1rem;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }

  .stat-number {
    font-size: 3rem;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1;
  }

  /* Quick Actions */
  .quick-actions {
    margin-bottom: 3rem;
  }

  .quick-actions h2 {
    margin-bottom: 1rem;
    font-size: 1.5rem;
    font-weight: 600;
  }

  .action-buttons {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
  }

  /* Chart Section */
  .chart-section {
    margin-bottom: 3rem;
  }

  .chart-section h2 {
    margin-bottom: 1.5rem;
    font-size: 1.5rem;
    font-weight: 600;
  }

  .simple-chart {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    height: 250px;
    padding: 1.5rem;
    background: var(--bg-secondary);
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
    gap: 1rem;
  }

  .chart-bar {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-end;
    position: relative;
    height: 100%;
  }

  .chart-bar .bar {
    width: 100%;
    background: var(--button-primary-bg);
    border-radius: var(--border-radius) var(--border-radius) 0 0;
    transition: height 0.3s ease;
    min-height: 2px;
  }

  .chart-bar .value {
    position: absolute;
    bottom: calc(100% + 0.5rem);
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-primary);
  }

  .chart-bar .label {
    font-size: 0.75rem;
    margin-top: 0.5rem;
    color: var(--text-secondary);
    font-weight: 500;
  }

  /* Recent Posts Section */
  .recent-posts-section {
    margin-bottom: 3rem;
  }

  .recent-posts-section h2 {
    margin-bottom: 1.5rem;
    font-size: 1.5rem;
    font-weight: 600;
  }

  /* Data Table */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-secondary);
    border-radius: var(--border-radius);
    overflow: hidden;
    border: 1px solid var(--border-color);
  }

  .data-table th,
  .data-table td {
    padding: 1rem 1.5rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
  }

  .data-table th {
    background: var(--bg-primary);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
  }

  .data-table tbody tr:hover {
    background: var(--bg-primary);
  }

  .data-table tbody tr:last-child td {
    border-bottom: none;
  }

  .post-title-link {
    color: var(--text-primary);
    text-decoration: none;
    font-weight: 500;
  }

  .post-title-link:hover {
    color: var(--link-color);
  }

  .action-cell {
    white-space: nowrap;
  }

  .small-button {
    padding: 0.375rem 0.875rem;
    font-size: 0.8125rem;
    margin-right: 0.5rem;
  }

  /* Empty State */
  .empty-state {
    text-align: center;
    padding: 3rem;
    background: var(--bg-secondary);
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
  }

  .empty-state p {
    margin-bottom: 1rem;
    color: var(--text-secondary);
  }

  .no-data {
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem;
  }

  /* Form improvements */
  .admin-form-container {
    max-width: 800px;
    margin: 0 auto;
    padding: 2rem;
  }

  .post-form {
    background: var(--bg-secondary);
    padding: 2rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
  }

  .post-meta {
    background: var(--bg-secondary);
    padding: 1rem;
    border-radius: var(--border-radius);
    margin-bottom: 2rem;
    font-size: 0.9rem;
    color: var(--text-secondary);
  }

  .post-meta p {
    margin: 0.25rem 0;
  }

  .checkbox-group {
    background: var(--bg-primary);
    padding: 1rem;
    border-radius: var(--border-radius);
    border: 2px solid var(--border-color);
    margin: 1.5rem 0;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    cursor: pointer;
    font-weight: 500;
  }

  .checkbox-label input[type="checkbox"] {
    width: auto;
    height: 1.2rem;
    margin: 0 0.75rem 0 0;
    cursor: pointer;
  }

  .checkbox-label span {
    user-select: none;
  }

  .form-actions {
    display: flex;
    gap: 1rem;
    margin-top: 2rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border-color);
  }

  .button.primary {
    background-color: var(--link-color);
    color: white;
  }

  .button.primary:hover {
    background-color: var(--link-hover);
  }

    /* Reply Form */
  .reply-form-container {
    max-width: 800px;
    margin: 2rem auto;
  }

  .reply-form {
    background: var(--bg-secondary);
    padding: 2rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
  }

  .reply-form .form-group {
    margin-bottom: 1.5rem;
  }

  .reply-form .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
    color: var(--text-primary);
  }

  .reply-form .form-input, .reply-form .form-textarea {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--input-border);
    background-color: var(--input-bg);
    color: var(--text-primary);
    font-size: 1em;
    border-radius: var(--border-radius);
    font-family: var(--font-family);
    transition: var(--transition);
  }

  .reply-form .form-textarea {
    min-height: 250px;
    resize: vertical;
  }

  .reply-form .readonly {
    background-color: var(--bg-primary);
    opacity: 0.8;
    cursor: not-allowed;
  }

  .reply-form .form-actions {
    display: flex;
    gap: 1rem;
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-color);
  }

  .reply-form .send-button {
    background-color: var(--button-primary-bg);
    color: var(--button-primary-text);
  }

  .reply-form .send-button:hover {
    background-color: var(--button-primary-hover);
  }

  .reply-form .cancel-button {
    background-color: var(--button-secondary-bg);
    color: var(--button-secondary-text);
  }

  .reply-form .cancel-button:hover {
    background-color: var(--button-secondary-hover);
  }
  
  /* User Profile Styles */
  .user-profile {
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
  }
  
  .profile-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 40px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border-color);
  }
  
  .profile-info h1 {
    margin: 0 0 5px 0;
    color: var(--text-primary);
  }
  
  .username {
    color: var(--text-secondary);
    font-size: 1.1em;
    margin: 0 0 15px 0;
  }
  
  .profile-description {
    margin: 15px 0;
    line-height: 1.6;
    color: var(--text-primary);
  }
  
  .profile-stats {
    color: var(--text-secondary);
    font-size: 0.9em;
  }
  
  .profile-actions {
    display: flex;
    gap: 10px;
  }
  
  .posts-section h2 {
    margin-bottom: 20px;
    color: var(--text-primary);
  }
  
  .post-list {
    margin-top: 10px;
  }
  
  .post-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 15px;
    border-bottom: 1px solid var(--border-color);
    background: var(--bg-secondary);
    margin-bottom: 5px;
    border-radius: var(--border-radius);
  }
  
  .post-info h4 {
    margin: 0 0 5px 0;
  }
  
  .post-info h4 a {
    text-decoration: none;
    color: var(--text-primary);
  }
  
  .post-info h4 a:hover {
    color: var(--link-color);
  }
  
  .post-date {
    color: var(--text-secondary);
    font-size: 0.9em;
    margin-right: 10px;
  }
  
  .post-status {
    font-size: 0.8em;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    font-weight: bold;
  }
  
  .post-status.published {
    background: #d4edda;
    color: #155724;
  }
  
  .post-status.draft {
    background: #fff3cd;
    color: #856404;
  }
  
  /* Dark theme adjustments for profile status badges */
  :root[data-theme="dark"] .post-status.published {
    background: #0a4f0a;
    color: #90ee90;
  }
  
  :root[data-theme="dark"] .post-status.draft {
    background: #4f4a0a;
    color: #f0e090;
  }
  
  /* Author links - make usernames clickable throughout the site */
  .author-link {
    color: var(--text-primary);
    text-decoration: none;
    font-weight: 500;
  }
  
  .author-link:hover {
    color: var(--link-color);
    text-decoration: underline;
  }
  
  /* Mobile responsive for user profiles */
  @media (max-width: 600px) {
    .profile-header {
      flex-direction: column;
      text-align: center;
      gap: 1rem;
    }
    
    .profile-actions {
      justify-content: center;
    }
    
    .post-item {
      flex-direction: column;
      align-items: flex-start;
      gap: 10px;
    }
  }

  // Add to the end of baseStyles, before the closing backtick

/* Proxy Dashboard */
.proxy-dashboard {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border-color);
}

.dashboard-header h2 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 600;
}

.status-indicator {
  padding: 0.5rem 1rem;
  border-radius: var(--border-radius);
  font-weight: 500;
  font-size: 0.875rem;
  border: 1px solid var(--border-color);
}

.status-indicator.connected {
  background: var(--bg-secondary);
  color: var(--text-primary);
  border-color: var(--border-color);
}

.status-indicator.disconnected {
  background: var(--bg-secondary);
  color: var(--text-secondary);
  border-color: var(--border-color);
}

.proxy-services-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.service-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  padding: 1.5rem;
  transition: var(--transition);
}

.service-card:hover {
  border-color: var(--border-hover);
}

.service-card h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
  font-weight: 600;
}

.service-status {
  font-weight: 500;
  margin-bottom: 1rem;
  padding: 0.5rem;
  background: var(--bg-primary);
  border-radius: var(--border-radius);
}

.service-status.healthy {
  color: var(--text-primary);
}

.service-status.error {
  color: var(--text-secondary);
}

.error-banner {
  background: var(--error-bg);
  color: var(--error-text);
  border: 1px solid var(--error-border);
  padding: 1rem;
  border-radius: var(--border-radius);
  margin-bottom: 2rem;
}

.error-banner h3 {
  margin: 0 0 0.5rem 0;
}

.error-banner p {
  margin: 0.5rem 0;
}

.proxy-actions {
  background: var(--bg-secondary);
  border-radius: var(--border-radius);
  padding: 1.5rem;
  margin-bottom: 2rem;
  border: 1px solid var(--border-color);
}

.proxy-actions h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
}

.action-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.integration-guide {
  background: var(--bg-secondary);
  border-radius: var(--border-radius);
  padding: 1.5rem;
  border: 1px solid var(--border-color);
}

.integration-guide h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
}

.guide-section h4 {
  color: var(--text-primary);
  margin: 1rem 0 0.5rem 0;
  font-size: 1rem;
}

.guide-section h4:first-child {
  margin-top: 0;
}

.guide-section p {
  color: var(--text-secondary);
  line-height: 1.5;
  margin: 0 0 0.75rem 0;
}

/* Queue Status */
.queue-status {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  padding: 1.5rem;
  margin-bottom: 2rem;
}

.queue-status h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
}

.queue-waiting {
  color: var(--text-secondary);
  font-style: italic;
  margin: 0;
}

/* Loading indicator */
.loading-indicator {
  position: fixed;
  top: 20px;
  right: 20px;
  background: var(--button-primary-bg);
  color: var(--button-primary-text);
  padding: 0.75rem 1rem;
  border-radius: var(--border-radius);
  z-index: 1000;
  font-weight: 500;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

/* Mobile responsive */
@media (max-width: 768px) {
  .proxy-dashboard {
    padding: 1rem;
  }
  
  .dashboard-header {
    flex-direction: column;
    gap: 1rem;
    text-align: center;
  }
  
  .proxy-services-grid {
    grid-template-columns: 1fr;
  }
  
  .action-buttons {
    justify-content: center;
  }

  /* Comment Styles */
  .comment-list {
    margin-top: 20px;
    border-top: 1px solid var(--border-color);
    padding-top: 20px;
  }

  .comment {
    margin-left: 20px;
    padding: 10px;
    border-left: 2px solid var(--border-color);
    margin-bottom: 10px;
  }

  .comment.nested {
    margin-left: 40px;
    background-color: rgba(0, 0, 0, 0.05);
  }

  .no-comments {
    color: var(--text-secondary);
    font-style: italic;
  }

  .comment-actions .button {
    padding: 5px 10px;
    font-size: 0.85em;
    margin-right: 5px;
  }

  .edit-button { background-color: #28a745; }
  .edit-button:hover { background-color: #218838; }
  .delete-button { background-color: #dc3545; }
  .delete-button:hover { background-color: #c82333; }
  .reply-button { background-color: #17a2b8; }
  .reply-button:hover { background-color: #138496; }

  .no-comments {
    color: var(--text-secondary);
    font-style: italic;
  }

  @media (max-width: 600px) {
    .comment {
      margin-left: 10px;
    }
    .comment.nested {
      margin-left: 20px;
    }
    .comment-actions .button {
      display: block;
      margin-bottom: 5px;
    }
  }

  }`;
var darkTheme = `
  :root[data-theme="dark"] {
    /* Colors */
    --bg-primary: #000;
    --bg-secondary: #1a1a1a;
    --text-primary: #fff;
    --text-secondary: #888;
    --border-color: #333;
    --border-hover: #555;
    
    /* Links */
    --link-color: #8ba3c7;
    --link-hover: #adc3e7;
    
    /* Navigation */
    --nav-hover-bg: #333;
    --nav-hover-color: #fff;
    
    /* Buttons - monochrome only */
    --button-primary-bg: #333;
    --button-primary-text: #fff;
    --button-primary-hover: #555;
    
    --button-secondary-bg: #444;  /* Edit button - slightly lighter */
    --button-secondary-text: #fff;
    --button-secondary-hover: #666;
    
    --button-danger-bg: #614f4fff;  /* Delete button - pure black */
    --button-danger-text: #fff;
    --button-danger-hover: #ada6a6;

    --theme-toggle-box-shadow: #ffffffff;
    --theme-toggle-background-color: #000;
    
    /* Forms */
    --input-bg: #121212;
    --input-border: #333;
    
    /* Code */
    --code-bg: #1a1a1a;
    
    /* Messages */
    --success-bg: #0a4f0a;
    --success-text: #90ee90;
    --success-border: #0f7f0f;
    
    --error-bg: #4f0a0a;
    --error-text: #ff9090;
    --error-border: #7f0f0f;
  }
  `;
var lightTheme = `
    :root[data-theme="light"] {
      /* Colors */
      --bg-primary: #fff;
      --bg-secondary: #f5f5f5;
      --text-primary: #333;
      --text-secondary: #666;
      --border-color: #ddd;
      --border-hover: #999;
      
      /* Links */
      --link-color: #0066cc;
      --link-hover: #0052a3;
      
      /* Navigation */
      --nav-hover-bg: #f0f0f0;
      --nav-hover-color: #333;
      
      /* Buttons - monochrome only */
      --button-primary-bg: #333;
      --button-primary-text: #fff;
      --button-primary-hover: #555;
      
      --button-secondary-bg: #666;  /* Edit button - grey */
      --button-secondary-text: #fff;
      --button-secondary-hover: #888;
      
      --button-danger-bg: #000;  /* Delete button - black in light mode too */
      --button-danger-text: #fff;
      --button-danger-hover: #333;

      --theme-toggle-box-shadow: #ffffffff;
      --theme-toggle-box-shadow: #00000000;
      
      /* Forms */
      --input-bg: #fff;
      --input-border: #ccc;
      
      /* Code */
      --code-bg: #f4f4f4;
      
      /* Messages */
      --success-bg: #d4edda;
      --success-text: #155724;
      --success-border: #c3e6cb;
      
      --error-bg: #f8d7da;
      --error-text: #721c24;
      --error-border: #f5c6cb;
    }
`;
var styleRoutes = {
  "/styles/dark_min.css": {
    GET: /* @__PURE__ */ __name(() => new Response(baseStyles + darkTheme, {
      headers: CACHE_HEADERS
    }), "GET")
  },
  "/styles/light_min.css": {
    GET: /* @__PURE__ */ __name(() => new Response(baseStyles + lightTheme, {
      headers: CACHE_HEADERS
    }), "GET")
  },
  "/styles/theme.css": {
    GET: /* @__PURE__ */ __name(() => new Response(baseStyles + darkTheme, {
      headers: CACHE_HEADERS
    }), "GET")
  }
};

// src/routes/static.js
init_checked_fetch();
var staticRoutes = {
  "/favicon.ico": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      try {
        const asset = await env.ASSETS.fetch(new URL("/favicon.ico", request.url));
        if (asset.status === 200) {
          return new Response(await asset.arrayBuffer(), {
            headers: {
              "Content-Type": "image/x-icon",
              "Cache-Control": "public, max-age=31536000"
              // Cache for 1 year
            }
          });
        }
        const svgFavicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
          <rect width="32" height="32" fill="#1a1a1a"/>
          <path d="M16 4l-2 2v4l-4 4v10l4 4h4l4-4V14l-4-4V6l-2-2z" fill="white"/>
        </svg>`;
        return new Response(svgFavicon, {
          headers: {
            "Content-Type": "image/svg+xml",
            "Cache-Control": "public, max-age=86400"
          }
        });
      } catch (error) {
        console.error("Favicon error:", error);
        const svgFavicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
          <rect width="32" height="32" fill="#1a1a1a"/>
          <path d="M16 4l-2 2v4l-4 4v10l4 4h4l4-4V14l-4-4V6l-2-2z" fill="white"/>
        </svg>`;
        return new Response(svgFavicon, {
          headers: {
            "Content-Type": "image/svg+xml",
            "Cache-Control": "public, max-age=86400"
          }
        });
      }
    }, "GET")
  },
  // Also add support for apple-touch-icon if you created one
  "/apple-touch-icon.png": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      try {
        const asset = await env.ASSETS.fetch(new URL("/apple-touch-icon.png", request.url));
        if (asset.status === 200) {
          return new Response(await asset.arrayBuffer(), {
            headers: {
              "Content-Type": "image/png",
              "Cache-Control": "public, max-age=31536000"
            }
          });
        }
        return new Response(null, { status: 404 });
      } catch (error) {
        console.error("Apple touch icon error:", error);
        return new Response(null, { status: 404 });
      }
    }, "GET")
  }
};

// src/routes/auth.js
init_checked_fetch();

// src/templates/auth/index.js
init_checked_fetch();

// src/templates/auth/login.js
init_checked_fetch();

// src/templates/auth/base.js
init_checked_fetch();
function renderAuthTemplate(title, bodyContent) {
  return `
    <!DOCTYPE html>
    <html lang="en" data-theme="dark">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title}</title>
      <link rel="stylesheet" href="/styles/theme.css">
      <link rel="stylesheet" href="/styles/dark_min.css" id="theme-stylesheet">
    </head>
    <body>
      <header>
        <h1><a href="/">${title}</a></h1>
        <div class="theme-toggle-container">
          <button id="theme-toggle" class="theme-toggle" aria-label="Toggle theme">
            <span class="theme-icon">\u2727</span>
          </button>
        </div>
      </header>
      ${bodyContent}
      <script>
        document.addEventListener('DOMContentLoaded', () => {
          const themeToggle = document.getElementById('theme-toggle');
          const html = document.documentElement;
          const stylesheet = document.getElementById('theme-stylesheet');
          
          // Load saved theme
          let currentTheme = localStorage.getItem('theme') || 'dark';
          html.setAttribute('data-theme', currentTheme);
          stylesheet.href = '/styles/' + currentTheme + '_min.css';

          // Update theme icon
          const themeIcon = themeToggle.querySelector('.theme-icon');
          themeIcon.textContent = currentTheme === 'dark' ? '\u2667' : '\u25C7';
          
          // Handle theme toggle
          themeToggle.addEventListener('click', () => {
            currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            // Update localStorage
            localStorage.setItem('theme', currentTheme);
            
            // Update HTML attribute
            html.setAttribute('data-theme', currentTheme);
            
            // Update stylesheet
            stylesheet.href = '/styles/' + currentTheme + '_min.css';
            
            // Update icon
            themeIcon.textContent = currentTheme === 'dark' ? '\u2661' : '\u2664';
          });
        });
      <\/script>
    </body>
    </html>
  `;
}
__name(renderAuthTemplate, "renderAuthTemplate");

// src/templates/auth/login.js
function renderLoginForm(data = {}) {
  const { error, validationErrors, username = "", csrfToken = "" } = data;
  let errorHtml = "";
  if (error) {
    errorHtml = `<div class="error-message">${error}</div>`;
  } else if (validationErrors) {
    const errorMessages = Object.values(validationErrors).join("<br>");
    errorHtml = `<div class="error-message">${errorMessages}</div>`;
  }
  const content = `
    <div class="auth-container">
      ${errorHtml}
      <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="${csrfToken}">
        <input 
          type="text" 
          name="username" 
          placeholder="Username" 
          value="${username}"
          required
          minlength="3"
          maxlength="20"
          pattern="[a-zA-Z0-9_-]+"
          title="Username can only contain letters, numbers, underscores, and hyphens"
        >
        <input 
          type="password" 
          name="password" 
          placeholder="Password" 
          required
          minlength="8"
        >
        <button type="submit">Login</button>
      </form>
    </div>
  `;
  return renderAuthTemplate("Login", content);
}
__name(renderLoginForm, "renderLoginForm");

// src/routes/auth.js
init_password();
init_jwt();
init_user();
init_logger();

// ../lib.deadlight/core/src/security/validation.js
init_checked_fetch();
var Validator = class {
  static {
    __name(this, "Validator");
  }
  // Enhanced email validation
  static email(email) {
    if (!email || typeof email !== "string") return false;
    const re2 = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re2.test(email) && email.length <= 255;
  }
  // Enhanced username validation with error details
  static username(username) {
    if (!username || typeof username !== "string") {
      return { valid: false, error: "Username is required" };
    }
    if (username.length < 3) {
      return { valid: false, error: "Username must be at least 3 characters" };
    }
    if (username.length > 20) {
      return { valid: false, error: "Username must not exceed 20 characters" };
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      return { valid: false, error: "Username can only contain letters, numbers, underscores, and hyphens" };
    }
    return { valid: true };
  }
  // Enhanced password validation
  static password(password) {
    if (!password || typeof password !== "string") {
      return { valid: false, error: "Password is required" };
    }
    if (password.length < 8) {
      return { valid: false, error: "Password must be at least 8 characters" };
    }
    if (password.length > 100) {
      return { valid: false, error: "Password is too long" };
    }
    return { valid: true };
  }
  // Validate blog post fields
  static postTitle(title) {
    if (!title || typeof title !== "string") {
      return { valid: false, error: "Title is required" };
    }
    const trimmed = title.trim();
    if (trimmed.length === 0) {
      return { valid: false, error: "Title cannot be empty" };
    }
    if (trimmed.length > 200) {
      return { valid: false, error: "Title must not exceed 200 characters" };
    }
    return { valid: true, value: trimmed };
  }
  static postContent(content) {
    if (!content || typeof content !== "string") {
      return { valid: false, error: "Content is required" };
    }
    if (content.trim().length === 0) {
      return { valid: false, error: "Content cannot be empty" };
    }
    if (content.length > 5e4) {
      return { valid: false, error: "Content is too long" };
    }
    return { valid: true };
  }
  static postSlug(slug) {
    if (!slug || typeof slug !== "string") {
      return { valid: false, error: "Slug is required" };
    }
    if (!/^[a-z0-9-]+$/.test(slug)) {
      return { valid: false, error: "Slug can only contain lowercase letters, numbers, and hyphens" };
    }
    if (slug.length > 200) {
      return { valid: false, error: "Slug must not exceed 200 characters" };
    }
    return { valid: true };
  }
  // Enhanced sanitization
  static sanitizeString(str, maxLength = 1e3) {
    if (!str || typeof str !== "string") return "";
    return str.slice(0, maxLength).replace(/[<>]/g, "").trim();
  }
  // More robust HTML sanitization
  static sanitizeHTML(input) {
    if (!input || typeof input !== "string") return "";
    return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "").replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "").replace(/<[^>]+>/g, "").replace(/javascript:/gi, "").replace(/on\w+\s*=/gi, "");
  }
  // Escape HTML for safe display
  static escapeHTML(input) {
    if (!input || typeof input !== "string") return "";
    const escapeMap = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
      "/": "&#x2F;"
    };
    return input.replace(/[&<>"'\/]/g, (char) => escapeMap[char]);
  }
  // Sanitize markdown (preserve formatting but remove dangerous content)
  static sanitizeMarkdown(input) {
    if (!input || typeof input !== "string") return "";
    return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "").replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "").replace(/javascript:/gi, "").replace(/on\w+\s*=/gi, "");
  }
  // Generate safe slug from title
  static generateSlug(title) {
    if (!title || typeof title !== "string") return "";
    return title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 200);
  }
  static isValidId(id) {
    return /^\d+$/.test(id);
  }
  // Validate pagination
  static page(page) {
    const num = parseInt(page, 10);
    if (isNaN(num) || num < 1) {
      return { valid: false, error: "Invalid page number", value: 1 };
    }
    return { valid: true, value: num };
  }
  // Validate search query
  static searchQuery(query) {
    if (!query || typeof query !== "string") {
      return { valid: true, value: "" };
    }
    const trimmed = query.trim();
    if (trimmed.length > 100) {
      return { valid: false, error: "Search query too long" };
    }
    return { valid: true, value: trimmed };
  }
};
var CSRFProtection = class {
  static {
    __name(this, "CSRFProtection");
  }
  static generateToken() {
    return crypto.randomUUID();
  }
  static async hashToken(token, secret) {
    const encoder = new TextEncoder();
    const data = encoder.encode(token + secret);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  }
  static getTokenFromCookie(request) {
    const cookieHeader = request.headers.get("Cookie");
    if (!cookieHeader) return null;
    const match = cookieHeader.match(/csrf_token=([^;]+)/);
    return match ? match[1] : null;
  }
};

// ../lib.deadlight/core/src/security/ratelimit.js
init_checked_fetch();
var RateLimiter = class {
  static {
    __name(this, "RateLimiter");
  }
  constructor(options = {}) {
    this.windowMs = options.windowMs || 6e4;
    this.maxRequests = options.maxRequests || 10;
    this.keyPrefix = options.keyPrefix || "rl:";
  }
  async isAllowed(request, env, identifier) {
    const key = this.getKey(identifier || this.getIdentifier(request));
    const now = Date.now();
    const windowStart = now - this.windowMs;
    const attempts = await env.RATE_LIMIT.get(key, { type: "json" }) || [];
    const recentAttempts = attempts.filter((time) => time > windowStart);
    if (recentAttempts.length >= this.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: new Date(recentAttempts[0] + this.windowMs)
      };
    }
    recentAttempts.push(now);
    await env.RATE_LIMIT.put(key, JSON.stringify(recentAttempts), {
      expirationTtl: Math.ceil(this.windowMs / 1e3)
    });
    return {
      allowed: true,
      remaining: this.maxRequests - recentAttempts.length,
      resetAt: new Date(now + this.windowMs)
    };
  }
  getIdentifier(request) {
    return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
  }
  getKey(identifier) {
    return `${this.keyPrefix}${identifier}`;
  }
};
var authLimiter = new RateLimiter({
  windowMs: 15 * 60 * 1e3,
  // 15 minutes
  maxRequests: 5,
  // 5 login attempts per 15 minutes
  keyPrefix: "rl:auth:"
});
var apiLimiter = new RateLimiter({
  windowMs: 60 * 1e3,
  // 1 minute
  maxRequests: 60,
  // 60 requests per minute
  keyPrefix: "rl:api:"
});

// src/services/auth-proxy.js
init_checked_fetch();
var ProxyAuthService = class {
  static {
    __name(this, "ProxyAuthService");
  }
  constructor(proxyUrl = "http://localhost:8080") {
    this.proxyUrl = proxyUrl;
  }
  async login(username, password) {
    const response = await fetch(`${this.proxyUrl}/api/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Real-IP": this.getRealIP()
        // For rate limiting
      },
      body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 429) {
        throw new Error("Too many login attempts. Please try again later.");
      } else if (response.status === 401) {
        throw new Error("Invalid credentials");
      }
      throw new Error(data.error || "Login failed");
    }
    this.storeToken(data.token);
    return {
      success: true,
      token: data.token,
      userId: data.user_id
    };
  }
  async verify(token) {
    const response = await fetch(`${this.proxyUrl}/api/auth/verify`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });
    if (!response.ok) {
      return { valid: false };
    }
    const data = await response.json();
    return {
      valid: true,
      userId: data.user_id,
      username: data.username
    };
  }
  async logout() {
    const token = this.getToken();
    if (!token) return;
    await fetch(`${this.proxyUrl}/api/auth/logout`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });
    this.clearToken();
  }
  // Helper methods
  getRealIP() {
    if (typeof globalThis.CF_CONNECTING_IP !== "undefined") {
      return globalThis.CF_CONNECTING_IP;
    }
    return "127.0.0.1";
  }
  storeToken(token) {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem("deadlight-token", token);
    }
    document.cookie = `deadlight-token=${token}; path=/; max-age=3600; SameSite=Strict`;
  }
  getToken() {
    if (typeof localStorage !== "undefined") {
      return localStorage.getItem("deadlight-token");
    }
    const match = document.cookie.match(/deadlight-token=([^;]+)/);
    return match ? match[1] : null;
  }
  clearToken() {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem("deadlight-token");
    }
    document.cookie = "deadlight-token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  }
};
var authService = new ProxyAuthService();

// src/routes/auth.js
var authRoutes = {
  "/login": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const existingToken = request.headers.get("Cookie")?.match(/token=([^;]+)/)?.[1];
      if (existingToken) {
        try {
          if (env.USE_PROXY_AUTH) {
            const verification = await authService.verify(existingToken);
            if (verification.valid) {
              return new Response(null, {
                status: 302,
                headers: { "Location": "/" }
              });
            }
          } else {
            const { verifyJWT: verifyJWT2 } = await Promise.resolve().then(() => (init_jwt(), jwt_exports));
            const user = await verifyJWT2(existingToken, env.JWT_SECRET);
            if (user) {
              return new Response(null, {
                status: 302,
                headers: { "Location": "/" }
              });
            }
          }
        } catch (error) {
        }
      }
      const csrfToken = CSRFProtection.generateToken();
      const headers = new Headers({
        "Content-Type": "text/html",
        "Set-Cookie": `csrf_token=${csrfToken}; HttpOnly; SameSite=Strict; Path=/`
      });
      return new Response(renderLoginForm({
        csrfToken,
        useProxyAuth: env.USE_PROXY_AUTH
      }), { headers });
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: "auth" });
      logger.info("Login POST request", {
        useProxyAuth: env.USE_PROXY_AUTH,
        hasBody: request.body !== null
      });
      if (!env.USE_PROXY_AUTH) {
        const rateLimitResult = await authLimiter.isAllowed(request, env);
        if (!rateLimitResult.allowed) {
          const retryAfter = Math.ceil((rateLimitResult.resetAt - Date.now()) / 1e3);
          logger.warn("Login rate limit exceeded");
          return new Response(renderLoginForm({
            error: `Too many login attempts. Please try again in ${Math.ceil(retryAfter / 60)} minutes.`
          }), {
            status: 429,
            headers: {
              "Content-Type": "text/html",
              "Retry-After": retryAfter.toString()
            }
          });
        }
      }
      try {
        const formDataRequest = new Request(request.url, {
          method: request.method,
          headers: request.headers,
          body: request.body
        });
        const formData = await formDataRequest.formData();
        logger.info("Login form data received", {
          hasUsername: !!formData.get("username"),
          hasPassword: !!formData.get("password")
        });
        const cookieToken = CSRFProtection.getTokenFromCookie(request);
        const formToken = formData.get("csrf_token");
        if (!cookieToken || !formToken || cookieToken !== formToken) {
          logger.warn("Invalid CSRF token in login attempt");
          const newToken = CSRFProtection.generateToken();
          const headers2 = new Headers({
            "Content-Type": "text/html",
            "Set-Cookie": `csrf_token=${newToken}; HttpOnly; SameSite=Strict; Path=/`
          });
          return new Response(renderLoginForm({
            error: "Session expired. Please try again.",
            csrfToken: newToken
          }), {
            status: 400,
            headers: headers2
          });
        }
        const usernameValidation = Validator.username(formData.get("username"));
        const passwordValidation = Validator.password(formData.get("password"));
        const errors = {};
        if (!usernameValidation.valid) {
          errors.username = usernameValidation.error;
        }
        if (!passwordValidation.valid) {
          errors.password = passwordValidation.error;
        }
        if (Object.keys(errors).length > 0) {
          logger.info("Login validation failed", { errors });
          return new Response(renderLoginForm({
            error: "Please correct the following errors",
            validationErrors: errors,
            username: Validator.escapeHTML(formData.get("username") || ""),
            csrfToken: cookieToken
          }), {
            status: 400,
            headers: { "Content-Type": "text/html" }
          });
        }
        const username = formData.get("username");
        const password = formData.get("password");
        logger.info("Login attempt", { username, passwordLength: password?.length });
        const authResult = await userModel.authenticate(username, password);
        if (!authResult.success) {
          logger.warn("Failed login attempt", { username, reason: authResult.error });
          return new Response(renderLoginForm({
            error: "Invalid username or password",
            username: Validator.escapeHTML(username),
            csrfToken: cookieToken
          }), {
            status: 401,
            headers: { "Content-Type": "text/html" }
          });
        }
        const identifier = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
        const rateLimitKey = `rl:auth:${identifier}`;
        await env.RATE_LIMIT.delete(rateLimitKey);
        logger.info("Cleared rate limit after successful login", { identifier });
        const { user } = authResult;
        await userModel.updateLastLogin(user.id);
        const token = await createJWT(
          { id: user.id, username: user.username, role: user.role || "user" },
          env.JWT_SECRET
        );
        const url = new URL(request.url);
        const isSecure = url.protocol === "https:";
        const headers = new Headers({
          "Location": user.role === "admin" ? "/admin" : "/"
        });
        headers.append("Set-Cookie", `token=${token}; HttpOnly; ${isSecure ? "Secure; " : ""}SameSite=Strict; Path=/`);
        headers.append("Set-Cookie", `csrf_token=; Path=/; Max-Age=0`);
        logger.info("Successful login", {
          userId: user.id,
          username: user.username
        });
        return new Response(null, { status: 303, headers });
      } catch (error) {
        logger.error("Login error", { error: error.message, stack: error.stack });
        const newToken = CSRFProtection.generateToken();
        const headers = new Headers({
          "Content-Type": "text/html",
          "Set-Cookie": `csrf_token=${newToken}; HttpOnly; SameSite=Strict; Path=/`
        });
        return new Response(renderLoginForm({
          error: "An error occurred. Please try again.",
          csrfToken: newToken
        }), {
          status: 500,
          headers
        });
      }
    }, "POST")
  },
  "/auth/refresh": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      if (!env.USE_PROXY_AUTH) {
        return new Response("Not available", { status: 404 });
      }
      const logger = new Logger({ context: "auth-refresh" });
      try {
        const refreshToken = request.headers.get("Cookie")?.match(/refresh_token=([^;]+)/)?.[1];
        if (!refreshToken) {
          return new Response(JSON.stringify({ error: "No refresh token" }), {
            status: 401,
            headers: { "Content-Type": "application/json" }
          });
        }
        const result = await authService.refresh(refreshToken);
        const headers = new Headers({ "Content-Type": "application/json" });
        headers.append(
          "Set-Cookie",
          `token=${result.accessToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`
        );
        if (result.refreshToken) {
          headers.append(
            "Set-Cookie",
            `refresh_token=${result.refreshToken}; HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh; Max-Age=${30 * 24 * 60 * 60}`
          );
        }
        return new Response(JSON.stringify({
          access_token: result.accessToken,
          expires_in: 3600
        }), { headers });
      } catch (error) {
        logger.error("Refresh token error", { error: error.message });
        return new Response(JSON.stringify({ error: "Invalid refresh token" }), {
          status: 401,
          headers: { "Content-Type": "application/json" }
        });
      }
    }, "POST")
  },
  "/logout": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      return authRoutes["/logout"].POST(request, env);
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const logger = new Logger({ context: "auth-logout" });
      if (env.USE_PROXY_AUTH) {
        const token = request.headers.get("Cookie")?.match(/token=([^;]+)/)?.[1];
        if (token) {
          try {
            await authService.logout(token);
          } catch (error) {
            logger.warn("Proxy logout failed", { error: error.message });
          }
        }
      }
      const headers = new Headers({ "Location": "/" });
      headers.append("Set-Cookie", `token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      headers.append("Set-Cookie", `refresh_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      return new Response(null, { status: 302, headers });
    }, "POST")
  },
  // Remove these temporary routes in production
  "/check-users": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const result = await env.DB.prepare("SELECT id, username, role FROM users").all();
      return new Response(JSON.stringify(result.results, null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }, "GET")
  },
  "/generate-admin": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const { hashPassword: hashPassword2 } = await Promise.resolve().then(() => (init_password(), password_exports));
      const password = "gross-gnar";
      const { hash, salt } = await hashPassword2(password);
      const html = `
        <h1>Admin User Creation</h1>
        <p>Password: ${password}</p>
        <p>Hash: ${hash}</p>
        <p>Salt: ${salt}</p>
        <h2>Run this command:</h2>
        <pre>wrangler d1 execute blog_content_v3 --local --command "INSERT INTO users (username, password, salt, role) VALUES ('admin', '${hash}', '${salt}', 'admin')"</pre>
      `;
      return new Response(html, {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET")
  },
  "/clear-login-limit": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const identifier = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
      const key = `rl:auth:${identifier}`;
      await env.RATE_LIMIT.delete(key);
      return new Response('Login rate limit cleared. <a href="/login">Try login again</a>', {
        status: 200,
        headers: { "Content-Type": "text/html" }
      });
    }, "GET")
  }
};

// src/routes/admin.js
init_checked_fetch();

// src/templates/admin/index.js
init_checked_fetch();

// src/templates/admin/addPost.js
init_checked_fetch();
init_base2();
function renderAddPostForm(user, config2 = null) {
  const content = `
    <div class="admin-form-container">
      <h1>Add New Post</h1>
      <form method="POST" action="/admin/add" class="post-form">
        <div class="form-group">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" required autofocus>
        </div>
        
        <div class="form-group">
          <label for="slug">Slug (URL path)</label>
          <input type="text" id="slug" name="slug" 
                 pattern="[a-z0-9-]+" title="Only lowercase letters, numbers, and hyphens allowed">
          <small>Leave blank to auto-generate from title</small>
        </div>
        
        <div class="form-group">
          <label for="content">Content (Markdown supported)</label>
          <textarea id="content" name="content" rows="20" required 
                    placeholder="Write your post content here...

Use **bold** and *italic* text, add [links](https://example.com), and more!

## Headings
### Subheadings

- List items
- Another item

\`\`\`javascript
// Code blocks work too!
console.log('Hello world!');
\`\`\`

Add <!--more--> to create a custom excerpt break point."></textarea>
        </div>
        
        <div class="form-group checkbox-group">
          <label class="checkbox-label">
            <input type="checkbox" name="published" value="true" checked>
            <span>Publish immediately</span>
          </label>
        </div>
        
        <div class="form-actions">
          <button type="submit" class="button primary">Create Post</button>
          <a href="/admin" class="button">Cancel</a>
        </div>
      </form>
    </div>
  `;
  return renderTemplate("Add New Post", content, user, config2);
}
__name(renderAddPostForm, "renderAddPostForm");

// src/templates/admin/editPost.js
init_checked_fetch();
init_base2();
function renderEditPostForm(post, user, config2 = null) {
  const content = `
    <div class="admin-form-container">
      <h1>Edit Post</h1>
      <div class="post-meta">
        <p>Created: ${new Date(post.created_at).toLocaleString()}</p>
        <p>Last Updated: ${new Date(post.updated_at).toLocaleString()}</p>
        <p>URL: <a href="/post/${post.slug}" target="_blank">/post/${post.slug}</a></p>
      </div>
      
      <form method="POST" action="/admin/edit/${post.id}" class="post-form">
        <div class="form-group">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" value="${post.title}" required>
        </div>
        
        <div class="form-group">
          <label for="slug">Slug (URL path)</label>
          <input type="text" id="slug" name="slug" value="${post.slug}" 
                 pattern="[a-z0-9-]+" title="Only lowercase letters, numbers, and hyphens allowed">
          <small>Leave blank to auto-generate from title</small>
        </div>
        
        <div class="form-group">
          <label for="content">Content (Markdown supported)</label>
          <textarea id="content" name="content" rows="20" required>${post.content}</textarea>
        </div>
        
        <div class="form-group checkbox-group">
          <label class="checkbox-label">
            <input type="checkbox" name="published" value="true" ${post.published ? "checked" : ""}>
            <span>${post.published ? "Published" : "Draft"} - uncheck to unpublish</span>
          </label>
        </div>
        
        <div class="form-actions">
          <button type="submit" class="button primary">Update Post</button>
          <a href="/admin" class="button">Cancel</a>
          <a href="/post/${post.slug}" class="button" target="_blank">View Post</a>
        </div>
      </form>
    </div>
  `;
  return renderTemplate("Edit Post", content, user, config2);
}
__name(renderEditPostForm, "renderEditPostForm");

// src/templates/admin/addUser.js
init_checked_fetch();
init_base2();
function renderAddUserForm(user = null, config2 = null) {
  const content = `
    <div class="auth-container">
      <h2>Add New User</h2>
      <form method="POST">
        <input 
          type="text" 
          name="username" 
          placeholder="Username" 
          required
        />
        <input 
          type="password" 
          name="password" 
          placeholder="Password" 
          required
          minlength="8"
        />
        <select name="role" required>
          <option value="user">User</option>
          <option value="editor">Editor</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit">Create User</button>
        <a href="/admin/users" style="display: block; text-align: center; margin-top: 1rem;">Cancel</a>
      </form>
    </div>
  `;
  return renderTemplate("Add User", content, user, config2);
}
__name(renderAddUserForm, "renderAddUserForm");

// src/templates/admin/deletePost.js
init_checked_fetch();
init_base2();

// src/templates/admin/index.js
init_dashboard();
init_userManagement();
init_settings();

// src/templates/admin/federationDashboard.js
init_checked_fetch();
init_base2();
function federationDashboard(federatedPosts, domains, user, config2) {
  const html = `
    <h2>Federation Network</h2>

    <div class="federation-stats">
      <div class="stat-card">
        <h3 id="connected-blogs">${domains.length}</h3>
        <p>Connected Blogs</p>
      </div>
      <div class="stat-card">
        <h3 id="federated-posts-count">${federatedPosts.length}</h3>
        <p>Federated Posts</p>
      </div>
    </div>

    <div class="federation-actions">
      <button id="test-btn">Test Federation</button>
      <button id="sync-btn">Sync Network</button>
      <span id="sync-status" style="margin-left:8px;"></span>
    </div>

    <h3>Recent Posts from Network:</h3>
    <div id="federated-list">
      ${federatedPosts.map((post) => `
        <article class="federated-post" data-id="${post.id}">
          <h4>
            <a href="${post.source_url}" target="_blank">${post.title}</a>
          </h4>
          <p>by ${post.author} from ${post.source_domain}</p>
          <div class="post-content">${post.content.substring(0, 200)}\u2026</div>
        </article>
      `).join("")}
    </div>

    <script>
      // Test Federation button
      document.getElementById('test-btn').onclick = async () => {
        const res = await fetch('/admin/proxy/test-federation');
        const { success, error } = await res.json();
        alert(success ? 'Federation test succeeded' : 'Error: ' + error);
      };

      // Sync Network button
      document.getElementById('sync-btn').onclick = async function() {
        const btn = this;
        const status = document.getElementById('sync-status');

        btn.disabled = true;
        status.textContent = 'Syncing\u2026';

        try {
          const res = await fetch('/admin/federation/sync', { method: 'POST' });
          const data = await res.json();

          alert(data.message);

          // Update stats
          document.getElementById('connected-blogs').textContent = data.domains;
          document.getElementById('federated-posts-count').textContent = 
            parseInt(document.getElementById('federated-posts-count').textContent) 
            + data.imported;

          // Append new posts if provided
          if (Array.isArray(data.newPosts)) {
            const list = document.getElementById('federated-list');
            data.newPosts.forEach(post => {
              const el = document.createElement('article');
              el.className = 'federated-post';
              el.innerHTML = \`
                <h4><a href="\${post.source_url}" target="_blank">\${post.title}</a></h4>
                <p>by \${post.author} from \${post.source_domain}</p>
                <div class="post-content">\${post.content.substring(0,200)}\u2026</div>
              \`;
              list.prepend(el);
            });
          }
        } catch (err) {
          alert('Sync failed: ' + err.message);
        } finally {
          btn.disabled = false;
          status.textContent = '';
        }
      };
    <\/script>
  `;
  return renderTemplate("Federation Network", html, user, config2);
}
__name(federationDashboard, "federationDashboard");

// src/routes/admin.js
init_federation();

// src/services/moderation.js
init_checked_fetch();

// src/routes/proxy.js
init_checked_fetch();
init_proxy();

// src/services/enhanced-outbox.js
init_checked_fetch();
init_proxy();
init_logger();
init_federation();
var EnhancedOutboxService2 = class {
  static {
    __name(this, "EnhancedOutboxService");
  }
  constructor(env) {
    this.env = env;
    this.db = env.DB;
    this.logger = new Logger({ context: "enhanced-outbox" });
    this.proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL });
    this.federationService = new FederationService(env);
  }
  // Enhanced queue processing that works with your existing schema
  async processQueue() {
    try {
      this.logger.info("Starting enhanced outbox queue processing");
      const healthCheck = await this.proxyService.healthCheck();
      if (!healthCheck.proxy_connected) {
        this.logger.info("Proxy offline, keeping operations queued");
        return {
          processed: 0,
          queued: await this.getQueuedCount(),
          status: "proxy_offline",
          message: "Proxy is offline - operations remain queued",
          circuit_state: this.proxyService.getCircuitState()
        };
      }
      this.logger.info("Proxy is online, processing queued operations");
      const results = await Promise.allSettled([
        this.processEmailReplies(),
        // Your existing email reply system
        this.processFederationQueue(),
        // Your existing federation system  
        this.processNotificationQueue(),
        // Enhanced notifications
        this.processSmsQueue()
        // New SMS support
      ]);
      const summary = this.summarizeResults(results);
      this.logger.info("Enhanced outbox processing completed", summary);
      return summary;
    } catch (error) {
      this.logger.error("Enhanced outbox processing failed", { error: error.message });
      return {
        processed: 0,
        error: error.message,
        status: "error",
        message: `Processing failed: ${error.message}`,
        circuit_state: this.proxyService.getCircuitState()
      };
    }
  }
  // Process email replies using your existing system
  async processEmailReplies() {
    const pendingReplies = await this.db.prepare(`
            SELECT * FROM posts 
            WHERE is_reply_draft = 1 
            AND email_metadata LIKE '%"sent":false%'
            AND (retry_count IS NULL OR retry_count < 3)
            ORDER BY created_at ASC
            LIMIT 50
        `).all();
    const replies = pendingReplies.results || [];
    let processed = 0;
    for (const reply of replies) {
      try {
        const metadata = JSON.parse(reply.email_metadata || "{}");
        const emailData = {
          to: metadata.to,
          from: metadata.from || "noreply@deadlight.boo",
          subject: reply.title,
          body: reply.content,
          headers: {
            "In-Reply-To": metadata.message_id,
            "References": metadata.references
          }
        };
        this.logger.info("Sending queued reply", {
          replyId: reply.id,
          to: emailData.to
        });
        const result = await this.proxyService.sendEmail(emailData);
        await this.markReplySent(reply.id, result);
        processed++;
      } catch (error) {
        await this.incrementRetryCount(reply.id, error.message, "email_reply");
        this.logger.error("Failed to send queued reply", {
          replyId: reply.id,
          error: error.message
        });
      }
    }
    return processed;
  }
  // Use your existing federation service
  async processFederationQueue() {
    try {
      const result = await this.federationService.processFederationQueue();
      return result.processed || 0;
    } catch (error) {
      this.logger.error("Federation queue processing failed", { error: error.message });
      return 0;
    }
  }
  // Enhanced notification processing with SMS support
  async processNotificationQueue() {
    const pendingNotifications = await this.db.prepare(`
            SELECT * FROM notifications 
            WHERE message_type IN ('email', 'sms') 
            AND is_read = FALSE 
            ORDER BY created_at ASC 
            LIMIT 20
        `).all();
    const notifications = pendingNotifications.results || [];
    let processed = 0;
    for (const notification of notifications) {
      try {
        if (notification.message_type === "email") {
          await this.sendNotificationEmail(notification);
        } else if (notification.message_type === "sms") {
          await this.sendNotificationSms(notification);
        }
        await this.db.prepare(`
                    UPDATE notifications 
                    SET is_read = TRUE 
                    WHERE id = ?
                `).bind(notification.id).run();
        processed++;
      } catch (error) {
        this.logger.error("Failed to send notification", {
          notificationId: notification.id,
          type: notification.message_type,
          error: error.message
        });
      }
    }
    return processed;
  }
  // New SMS queue processing
  async processSmsQueue() {
    const pendingSms = await this.db.prepare(`
            SELECT * FROM notifications 
            WHERE message_type = 'sms' 
            AND is_read = FALSE 
            ORDER BY created_at ASC 
            LIMIT 10
        `).all();
    const smsMessages = pendingSms.results || [];
    let processed = 0;
    for (const sms of smsMessages) {
      try {
        const smsData = JSON.parse(sms.content || "{}");
        const result = await this.proxyService.sendSms({
          to: smsData.to,
          message: smsData.message,
          from: smsData.from || "Deadlight"
        });
        await this.db.prepare(`
                    UPDATE notifications 
                    SET is_read = TRUE, content = ?
                    WHERE id = ?
                `).bind(
          JSON.stringify({ ...smsData, sent: true, result }),
          sms.id
        ).run();
        processed++;
        this.logger.info("SMS sent successfully", { smsId: sms.id });
      } catch (error) {
        this.logger.error("Failed to send SMS", {
          smsId: sms.id,
          error: error.message
        });
      }
    }
    return processed;
  }
  // Enhanced queue counting that works with your schema
  async getQueuedCount() {
    try {
      const emailReplies = await this.db.prepare(`
                SELECT COUNT(*) as count FROM posts 
                WHERE is_reply_draft = 1 
                AND email_metadata LIKE '%"sent":false%'
                AND (retry_count IS NULL OR retry_count < 3)
            `).first();
      let federationPosts = 0;
      try {
        const fedResult = await this.db.prepare(`
                    SELECT COUNT(*) as count FROM posts 
                    WHERE federation_pending = 1 
                    AND published = 1
                `).first();
        federationPosts = fedResult?.count || 0;
      } catch {
      }
      const notifications = await this.db.prepare(`
                SELECT COUNT(*) as count FROM notifications 
                WHERE message_type IN ('email', 'sms') 
                AND is_read = FALSE
            `).first();
      return {
        total: (emailReplies?.count || 0) + federationPosts + (notifications?.count || 0),
        email_replies: emailReplies?.count || 0,
        federation_posts: federationPosts,
        notifications: notifications?.count || 0
      };
    } catch (error) {
      this.logger.error("Error getting queue count", { error: error.message });
      return { total: 0, email_replies: 0, federation_posts: 0, notifications: 0 };
    }
  }
  // Helper methods that work with your existing patterns
  async markReplySent(replyId, sendResult) {
    const reply = await this.db.prepare(
      "SELECT email_metadata FROM posts WHERE id = ?"
    ).bind(replyId).first();
    if (!reply) return;
    const metadata = JSON.parse(reply.email_metadata || "{}");
    metadata.sent = true;
    metadata.date_sent = (/* @__PURE__ */ new Date()).toISOString();
    metadata.send_result = sendResult;
    await this.db.prepare(`
            UPDATE posts 
            SET email_metadata = ?, updated_at = ? 
            WHERE id = ?
        `).bind(
      JSON.stringify(metadata),
      (/* @__PURE__ */ new Date()).toISOString(),
      replyId
    ).run();
  }
  async incrementRetryCount(itemId, errorMessage, itemType = "post") {
    try {
      await this.db.prepare(`
                UPDATE posts 
                SET retry_count = COALESCE(retry_count, 0) + 1,
                    last_error = ?,
                    last_attempt = ?,
                    updated_at = ?
                WHERE id = ?
            `).bind(
        errorMessage,
        (/* @__PURE__ */ new Date()).toISOString(),
        (/* @__PURE__ */ new Date()).toISOString(),
        itemId
      ).run();
    } catch (error) {
      this.logger.error("Failed to update retry count", {
        itemId,
        itemType,
        error: error.message
      });
    }
  }
  // New notification methods
  async sendNotificationEmail(notification) {
    const content = JSON.parse(notification.content || "{}");
    const emailData = {
      to: content.to,
      from: content.from || "notifications@deadlight.boo",
      subject: content.subject || "Deadlight Notification",
      body: content.message
    };
    return await this.proxyService.sendEmail(emailData);
  }
  async sendNotificationSms(notification) {
    const content = JSON.parse(notification.content || "{}");
    const smsData = {
      to: content.to,
      message: content.message,
      from: content.from || "Deadlight"
    };
    return await this.proxyService.sendSms(smsData);
  }
  // Queue new items using your existing patterns
  async queueSms(userId, phoneNumber, message) {
    const smsData = {
      to: phoneNumber,
      message,
      queued_at: (/* @__PURE__ */ new Date()).toISOString()
    };
    await this.db.prepare(`
            INSERT INTO notifications (user_id, type, message_type, content, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).bind(
      userId,
      "system",
      "sms",
      JSON.stringify(smsData),
      (/* @__PURE__ */ new Date()).toISOString()
    ).run();
    return { success: true, message: "SMS queued for delivery" };
  }
  async queueEmailNotification(userId, emailData) {
    await this.db.prepare(`
            INSERT INTO notifications (user_id, type, message_type, content, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).bind(
      userId,
      "system",
      "email",
      JSON.stringify(emailData),
      (/* @__PURE__ */ new Date()).toISOString()
    ).run();
    return { success: true, message: "Email notification queued" };
  }
  // Results summary helper
  summarizeResults(results) {
    const totalProcessed = results.reduce((sum, result) => {
      if (result.status === "fulfilled") {
        return sum + (result.value || 0);
      }
      return sum;
    }, 0);
    const errors = results.filter((result) => result.status === "rejected").map((result) => result.reason?.message);
    return {
      processed: totalProcessed,
      queued: this.getQueuedCount(),
      status: errors.length > 0 ? "partial_success" : "success",
      message: `Processed ${totalProcessed} operations${errors.length > 0 ? " with some errors" : ""}`,
      errors,
      circuit_state: this.proxyService.getCircuitState()
    };
  }
  // Enhanced status method
  async getStatus() {
    const queueCount = await this.getQueuedCount();
    const proxyHealth = await this.proxyService.healthCheck();
    const circuitState = this.proxyService.getCircuitState();
    return {
      queued_operations: queueCount,
      proxy_connected: proxyHealth.proxy_connected,
      circuit_breaker: circuitState,
      last_check: (/* @__PURE__ */ new Date()).toISOString(),
      status: queueCount.total > 0 ? "pending" : "clear",
      proxy_details: {
        blog_api: proxyHealth.blog_api,
        email_api: proxyHealth.email_api,
        failures: circuitState.failures
      }
    };
  }
};

// src/routes/proxy.js
init_federation();

// src/templates/admin/proxyDashboard.js
init_checked_fetch();
init_base2();
function proxyDashboardTemplate(proxyData, user, config2, queuedCount = 0) {
  const { status, queue, federation, config: proxyConfig, error } = proxyData;
  const proxyConnected = status?.proxy_connected || false;
  const serviceCards = [
    {
      key: "blog-api",
      title: "Blog API",
      status: status?.blog_api ? "running" : "error",
      details: [
        status?.blog_api ? "Version: 5.0.0" : "Not responding",
        `Circuit: ${proxyConfig?.circuitState?.state || "Unknown"}`
      ],
      testHandler: "handleTestBlogApi"
    },
    {
      key: "email-api",
      title: "Email API",
      status: status?.email_api ? "running" : "error",
      details: [
        `Queue Size: ${queue?.status?.queued_operations?.email || 0}`,
        `Last Processed: ${queue?.status?.last_processed || "Never"}`
      ],
      testHandler: "handleTestEmailApi"
    },
    {
      key: "federation",
      title: "Email-based Federation",
      status: federation?.status === "online" ? "healthy" : "error",
      details: [
        "Protocol: Email Bridge",
        `Connected Domains: ${federation?.connected_domains?.length || 0}`,
        "Purpose: Instance-to-instance communication"
      ],
      testHandler: "handleTestFederation"
    },
    {
      key: "config",
      title: "Configuration",
      status: proxyConnected ? "healthy" : "error",
      details: [
        `Proxy URL: ${proxyConfig?.proxyUrl || "Not configured"}`,
        `Connection: ${proxyConnected ? "Active" : "Inactive"}`,
        status?.timestamp ? `Last Check: ${new Date(status.timestamp).toLocaleString()}` : "No recent checks"
      ],
      testHandler: null
    },
    {
      key: "federation-activity",
      title: "Federation Activity",
      status: "healthy",
      details: [
        "Protocol: Email Bridge",
        `Connected Domains: ${federation?.connected_domains?.length || 0}`,
        `Pending Posts: ${federation?.pending_posts || 0}`,
        "Recent Activity: Live monitoring"
      ],
      testHandler: "handleDiscoverDomain"
    }
  ];
  const content = `
        <div class="proxy-dashboard">
            <header class="dashboard-header">
                <h2>Proxy Server Management</h2>
                <div class="status-indicator ${proxyConnected ? "connected" : "disconnected"}">
                    ${proxyConnected ? "\u{1F7E2} Connected" : "\u{1F534} Disconnected"}
                </div>
            </header>

            ${error ? `
                <section class="error-banner">
                    <h3>Connection Error</h3>
                    <p>${error}</p>
                    <button onclick="location.reload()">Retry Connection</button>
                </section>
            ` : ""}

            <section class="queue-status">
                <h3>Outbox Queue</h3>
                <p><span class="queue-count">${queue?.status?.queued_operations?.total || 0}</span> operations pending</p>
                <p class="last-check">Last check: <span class="last-check-time">${(/* @__PURE__ */ new Date()).toLocaleTimeString()}</span></p>
                ${proxyConnected ? `
                    <button onclick="handleProcessQueue()" class="button">Process Queue Now</button>
                ` : `
                    <p class="queue-waiting">Waiting for proxy connection...</p>
                `}
            </section>

            <section class="proxy-services-grid">
                ${serviceCards.map((card) => `
                    <div class="service-card" data-service="${card.key}">
                        <h3>${card.title}</h3>
                        <div class="service-status ${card.status === "running" || card.status === "healthy" ? "healthy" : "error"}">
                            Status: ${card.status || "Unknown"}
                        </div>
                        <div class="service-details">
                            ${card.details.map((d2) => `<p>${d2}</p>`).join("")}
                        </div>
                        ${card.testHandler ? `
                            <button onclick="${card.testHandler}()" class="button small-button">Test</button>
                        ` : `
                            <button onclick="location.reload()" class="button small-button">Refresh</button>
                        `}
                    </div>
                `).join("")}
            </section>

            <section class="federation-live-activity">
                <h3>Live Federation Activity</h3>
                <div class="federation-status">
                    <div class="trust-levels" id="trust-levels">
                        <p>Loading trust relationships...</p>
                    </div>
                </div>
                <div class="activity-stream" id="federation-activity">
                    <p>Connecting to federation activity stream...</p>
                </div>
            </section>

            <section class="proxy-actions">
                <h3>Quick Actions</h3>
                <div class="action-buttons">
                    <button onclick="handleSendTestEmail()" class="button">Send Test Email</button>
                    <button onclick="handleTestFederation()" class="button">Test Federation</button>
                    <button onclick="handleDiscoverDomain()" class="button">Discover New Domain</button>
                    <button onclick="location.reload()" class="button">Refresh All Status</button>
                </div>
            </section>
        </div>

        <script src="/admin/proxyDashboard.js"><\/script>
    `;
  return renderTemplate("Proxy Server Management", content, user, config2);
}
__name(proxyDashboardTemplate, "proxyDashboardTemplate");

// src/routes/proxy.js
init_password();
async function handleProxyRoutes(request, env, user) {
  try {
    const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
    const config2 = await configService2.getConfig(env.DB);
    const proxyUrl = env.PROXY_URL || config2.proxyUrl || "http://localhost:8080";
    const proxyService = new ProxyService2({ PROXY_URL: proxyUrl });
    const outboxService = new EnhancedOutboxService2(env);
    const federationService = new FederationService(env);
    const [proxyStatus, queueStatus, federationStatus] = await Promise.allSettled([
      proxyService.healthCheck(),
      outboxService.getStatus(),
      federationService.getConnectedDomains()
    ]);
    const shouldProcessQueue = proxyStatus.status === "fulfilled" && proxyStatus.value.proxy_connected && queueStatus.status === "fulfilled" && queueStatus.value.queued_operations?.total > 0;
    let queueProcessingResult = null;
    if (shouldProcessQueue) {
      try {
        queueProcessingResult = await outboxService.processQueue();
        console.log("Enhanced queue processing completed:", queueProcessingResult);
      } catch (error) {
        console.error("Enhanced queue processing failed:", error);
      }
    }
    const proxyData = {
      status: proxyStatus.status === "fulfilled" ? proxyStatus.value : {
        proxy_connected: false,
        error: proxyStatus.reason?.message || "Connection failed",
        circuit_state: "UNKNOWN"
      },
      queue: {
        status: queueStatus.status === "fulfilled" ? queueStatus.value : {
          queued_operations: { total: 0 },
          status: "error"
        },
        lastProcessing: queueProcessingResult
      },
      federation: {
        connected_domains: federationStatus.status === "fulfilled" ? federationStatus.value : [],
        status: federationStatus.status === "fulfilled" ? "online" : "error"
      },
      config: {
        proxyUrl,
        enabled: true,
        circuitState: proxyService.getCircuitState()
      }
    };
    return new Response(proxyDashboardTemplate(proxyData, user, config2), {
      headers: { "Content-Type": "text/html" }
    });
  } catch (error) {
    console.error("Proxy dashboard error:", error);
    const errorData = {
      status: {
        proxy_connected: false,
        error: error.message,
        circuit_state: "ERROR"
      },
      queue: {
        status: { queued_operations: { total: 0 }, status: "error" }
      },
      federation: {
        connected_domains: [],
        status: "error"
      },
      config: {
        proxyUrl: env.PROXY_URL || "http://localhost:8080",
        enabled: false
      }
    };
    const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
    const config2 = await configService2.getConfig(env.DB);
    return new Response(proxyDashboardTemplate(errorData, user, config2), {
      headers: { "Content-Type": "text/html" }
    });
  }
}
__name(handleProxyRoutes, "handleProxyRoutes");
var handleProxyTests = {
  async testBlogApi(request, env) {
    try {
      const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
      const result = await proxyService.getBlogStatus();
      return Response.json({
        success: true,
        data: result,
        circuit_state: proxyService.getCircuitState()
      });
    } catch (error) {
      console.error("Blog API test error:", error);
      const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
      return Response.json({
        success: false,
        error: error.message,
        circuit_state: proxyService.getCircuitState()
      });
    }
  },
  async testEmailApi(request, env) {
    try {
      const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
      const result = await proxyService.getEmailStatus();
      return Response.json({
        success: true,
        data: result,
        circuit_state: proxyService.getCircuitState()
      });
    } catch (error) {
      console.error("Email API test error:", error);
      const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
      return Response.json({
        success: false,
        error: error.message,
        circuit_state: proxyService.getCircuitState()
      });
    }
  },
  async sendTestEmail(request, env) {
    const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
    const outboxService = new EnhancedOutboxService2(env);
    try {
      const { email } = await request.json();
      const emailData = {
        to: email,
        from: "noreply@deadlight.boo",
        subject: "Test Email from Deadlight Proxy",
        body: `Hello!

This is a test email sent through the enhanced Deadlight Proxy system.

Timestamp: ${(/* @__PURE__ */ new Date()).toISOString()}
Circuit State: ${proxyService.getCircuitState().state}

Best regards,
Deadlight System`
      };
      try {
        const result = await proxyService.sendEmail(emailData);
        return Response.json({
          success: true,
          data: result,
          sent_immediately: true,
          circuit_state: proxyService.getCircuitState()
        });
      } catch (proxyError) {
        console.log("Proxy unavailable, queuing email via outbox...");
        await outboxService.queueEmailNotification(1, emailData);
        return Response.json({
          success: true,
          data: {
            message: "Email queued for delivery when proxy comes online",
            queued_via: "outbox_service"
          },
          queued: true,
          proxy_error: proxyError.message,
          circuit_state: proxyService.getCircuitState()
        });
      }
    } catch (error) {
      console.error("Test email error:", error);
      return Response.json({
        success: false,
        error: error.message,
        circuit_state: proxyService.getCircuitState()
      });
    }
  },
  async testFederation(request, env) {
    const federationService = new FederationService(env);
    try {
      const results = await federationService.testFederation();
      return Response.json({
        success: true,
        data: results,
        sent_immediately: true,
        federation_domains: (await federationService.getConnectedDomains()).length
      });
    } catch (error) {
      console.error("Federation test error:", error);
      return Response.json({
        success: false,
        error: error.message,
        suggestion: "Check that federation domains are configured and proxy is online"
      });
    }
  },
  async testSms(request, env) {
    const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
    const outboxService = new EnhancedOutboxService2(env);
    try {
      const { phone } = await request.json();
      const smsData = {
        to: phone,
        message: `Test SMS from Deadlight Proxy - ${(/* @__PURE__ */ new Date()).toISOString()}`,
        from: "Deadlight"
      };
      try {
        const result = await proxyService.sendSms(smsData);
        return Response.json({
          success: true,
          data: result,
          sent_immediately: true,
          circuit_state: proxyService.getCircuitState()
        });
      } catch (proxyError) {
        await outboxService.queueSms(1, phone, smsData.message);
        return Response.json({
          success: true,
          data: { message: "SMS queued for delivery when proxy comes online" },
          queued: true,
          proxy_error: proxyError.message,
          circuit_state: proxyService.getCircuitState()
        });
      }
    } catch (error) {
      console.error("Test SMS error:", error);
      return Response.json({
        success: false,
        error: error.message,
        circuit_state: proxyService.getCircuitState()
      });
    }
  },
  async processQueue(request, env) {
    const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
    const outboxService = new EnhancedOutboxService2(env);
    try {
      const isAvailable = await proxyService.isProxyAvailable();
      if (!isAvailable) {
        return Response.json({
          success: false,
          error: "Proxy is not available - cannot process queue",
          circuit_state: proxyService.getCircuitState()
        });
      }
      const result = await outboxService.processQueue();
      return Response.json({
        success: true,
        data: result
      });
    } catch (error) {
      console.error("Manual queue processing error:", error);
      return Response.json({
        success: false,
        error: error.message,
        circuit_state: proxyService.getCircuitState()
      });
    }
  },
  async getQueueStatus(request, env) {
    try {
      const outboxService = new EnhancedOutboxService2(env);
      const status = await outboxService.getStatus();
      return Response.json({
        success: true,
        data: status
      });
    } catch (error) {
      console.error("Queue status error:", error);
      return Response.json({
        success: false,
        error: error.message
      });
    }
  },
  async getFederationStatus(request, env) {
    try {
      const federationService = new FederationService(env);
      const [domains, federatedPosts] = await Promise.allSettled([
        federationService.getConnectedDomains(),
        federationService.getFederatedPosts(10)
      ]);
      return Response.json({
        success: true,
        data: {
          connected_domains: domains.status === "fulfilled" ? domains.value : [],
          recent_federated_posts: federatedPosts.status === "fulfilled" ? federatedPosts.value : [],
          status: "online"
        }
      });
    } catch (error) {
      console.error("Federation status error:", error);
      return Response.json({
        success: false,
        error: error.message
      });
    }
  },
  async discoverDomain(request, env) {
    try {
      const { domain } = await request.json();
      const federationService = new FederationService(env);
      const result = await federationService.discoverDomain(domain);
      return Response.json({
        success: true,
        data: result,
        message: `Discovery request sent to ${domain}`
      });
    } catch (error) {
      console.error("Domain discovery error:", error);
      return Response.json({
        success: false,
        error: error.message
      });
    }
  },
  async statusStream(request, env) {
    const user = await checkAuth(request, env);
    if (!user) {
      return new Response("Unauthorized", { status: 401 });
    }
    const stream = new ReadableStream({
      async start(controller) {
        const encoder = new TextEncoder();
        const sendUpdate = /* @__PURE__ */ __name(async () => {
          try {
            const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
            const outboxService = new EnhancedOutboxService2(env);
            const federationService = new FederationService(env);
            const [proxyStatus, queueStatus, federationStatus] = await Promise.allSettled([
              proxyService.healthCheck(),
              outboxService.getStatus(),
              getFederationRealtimeStatus(env)
              // New function
            ]);
            const data = {
              timestamp: (/* @__PURE__ */ new Date()).toISOString(),
              proxy_connected: proxyStatus.status === "fulfilled" && proxyStatus.value.proxy_connected,
              blogApi: proxyStatus.status === "fulfilled" ? proxyStatus.value.blog_api : null,
              emailApi: proxyStatus.status === "fulfilled" ? proxyStatus.value.email_api : null,
              queueCount: queueStatus.status === "fulfilled" ? queueStatus.value.queued_operations?.total || 0 : 0,
              circuitState: proxyService.getCircuitState(),
              // NEW: Federation real-time status
              federation: federationStatus.status === "fulfilled" ? federationStatus.value : {
                connected_domains: 0,
                pending_posts: 0,
                recent_activity: [],
                trust_relationships: []
              }
            };
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}

`));
          } catch (error) {
            console.error("SSE update error:", error);
            controller.enqueue(encoder.encode(`data: ${JSON.stringify({
              error: error.message,
              timestamp: (/* @__PURE__ */ new Date()).toISOString(),
              proxy_connected: false
            })}

`));
          }
        }, "sendUpdate");
        await sendUpdate();
        const interval = setInterval(sendUpdate, 5e3);
        request.signal?.addEventListener("abort", () => {
          clearInterval(interval);
          controller.close();
        });
        const heartbeat = setInterval(() => {
          try {
            controller.enqueue(encoder.encode(": heartbeat\n\n"));
          } catch (error) {
            clearInterval(heartbeat);
            clearInterval(interval);
          }
        }, 3e4);
      }
    });
    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Cache-Control"
      }
    });
  },
  async getCircuitStatus(request, env) {
    try {
      const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
      const circuitState = proxyService.getCircuitState();
      return Response.json({
        success: true,
        data: {
          circuit_state: circuitState,
          recommendations: this.getCircuitRecommendations(circuitState)
        }
      });
    } catch (error) {
      const proxyService = new ProxyService2({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
      return Response.json({
        success: false,
        error: error.message,
        circuit_state: proxyService.getCircuitState()
      });
    }
  },
  getCircuitRecommendations(circuitState) {
    const recommendations = [];
    if (circuitState.state === "OPEN") {
      recommendations.push("Circuit breaker is OPEN - proxy appears to be down");
      recommendations.push("Check proxy server status and network connectivity");
      recommendations.push("Operations are being queued until proxy recovers");
    } else if (circuitState.state === "HALF_OPEN") {
      recommendations.push("Circuit breaker is testing connectivity");
      recommendations.push("Next request will determine if circuit closes");
    } else if (circuitState.failures > 0) {
      recommendations.push(`${circuitState.failures} recent failures detected`);
      recommendations.push("Monitor proxy health closely");
    } else {
      recommendations.push("All systems operating normally");
    }
    return recommendations;
  }
};
async function getFederationRealtimeStatus(env) {
  const federationService = new FederationService(env);
  const [domains, pendingPosts, recentActivity] = await Promise.allSettled([
    federationService.getConnectedDomains(),
    getPendingFederationPosts(env.DB),
    getRecentFederationActivity(env.DB)
  ]);
  return {
    connected_domains: domains.status === "fulfilled" ? domains.value.length : 0,
    trust_levels: domains.status === "fulfilled" ? domains.value.reduce((acc, d2) => {
      acc[d2.trust_level] = (acc[d2.trust_level] || 0) + 1;
      return acc;
    }, {}) : {},
    pending_posts: pendingPosts.status === "fulfilled" ? pendingPosts.value : 0,
    recent_activity: recentActivity.status === "fulfilled" ? recentActivity.value : [],
    last_outgoing: await getLastFederationSent(env.DB),
    last_incoming: await getLastFederationReceived(env.DB)
  };
}
__name(getFederationRealtimeStatus, "getFederationRealtimeStatus");
async function getPendingFederationPosts(db) {
  const result = await db.prepare(`
        SELECT COUNT(*) as count 
        FROM posts 
        WHERE federation_pending = 1
    `).first();
  return result?.count || 0;
}
__name(getPendingFederationPosts, "getPendingFederationPosts");
async function getRecentFederationActivity(db, limit = 5) {
  const result = await db.prepare(`
        SELECT 
            id, title, 
            json_extract(federation_metadata, '$.source_domain') as source_domain,
            json_extract(federation_metadata, '$.received_at') as received_at,
            post_type,
            moderation_status
        FROM posts 
        WHERE post_type IN ('federated', 'comment') 
            AND federation_metadata IS NOT NULL
        ORDER BY created_at DESC 
        LIMIT ?
    `).bind(limit).all();
  return (result.results || []).map((row) => ({
    type: row.post_type,
    title: row.title,
    domain: row.source_domain,
    timestamp: row.received_at,
    status: row.moderation_status
  }));
}
__name(getRecentFederationActivity, "getRecentFederationActivity");
async function getLastFederationSent(db) {
  const result = await db.prepare(`
        SELECT federation_sent_at, title
        FROM posts 
        WHERE federation_sent_at IS NOT NULL 
        ORDER BY federation_sent_at DESC 
        LIMIT 1
    `).first();
  return result ? { timestamp: result.federation_sent_at, title: result.title } : null;
}
__name(getLastFederationSent, "getLastFederationSent");
async function getLastFederationReceived(db) {
  const result = await db.prepare(`
        SELECT 
            json_extract(federation_metadata, '$.received_at') as received_at,
            title
        FROM posts 
        WHERE post_type = 'federated' 
            AND federation_metadata IS NOT NULL
        ORDER BY created_at DESC 
        LIMIT 1
    `).first();
  return result ? { timestamp: result.received_at, title: result.title } : null;
}
__name(getLastFederationReceived, "getLastFederationReceived");

// src/routes/admin.js
init_password();
init_base2();
init_models();
init_logger();
init_base();
var adminRoutes = {
  "/admin": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
        const config2 = await configService2.getConfig(env.DB);
        let stats = {
          totalPosts: 0,
          totalUsers: 0,
          postsToday: 0,
          publishedPosts: 0
        };
        let posts = [];
        let requestStats = [];
        try {
          const postsCount = await env.DB.prepare(`
            SELECT COUNT(*) as count FROM posts 
            WHERE (is_email = 0 OR is_email IS NULL)
          `).first();
          stats.totalPosts = postsCount?.count || 0;
          const usersCount = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
          stats.totalUsers = usersCount?.count || 0;
          const today = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
          const todayCount = await env.DB.prepare(`
            SELECT COUNT(*) as count FROM posts 
            WHERE DATE(created_at) = ? AND (is_email = 0 OR is_email IS NULL)
          `).bind(today).first();
          stats.postsToday = todayCount?.count || 0;
          const publishedCount = await env.DB.prepare(`
            SELECT COUNT(*) as count FROM posts 
            WHERE published = 1 AND (is_email = 0 OR is_email IS NULL)
          `).first();
          stats.publishedPosts = publishedCount?.count || 0;
          const recentPostsQuery = await env.DB.prepare(`
            SELECT p.id, p.title, p.slug, p.created_at, p.published, p.author_id, u.username as author_username
            FROM posts p
            LEFT JOIN users u ON p.author_id = u.id
            WHERE (p.is_email = 0 OR p.is_email IS NULL)
            ORDER BY p.created_at DESC 
            LIMIT 10
          `).all();
          posts = recentPostsQuery.results || [];
        } catch (dbError) {
          console.error("Database query error in admin dashboard:", dbError);
        }
        const { renderAdminDashboard: renderAdminDashboard2 } = await Promise.resolve().then(() => (init_dashboard(), dashboard_exports));
        return new Response(renderAdminDashboard2(stats, posts, requestStats, user, config2), {
          headers: { "Content-Type": "text/html" }
        });
      } catch (error) {
        console.error("Admin dashboard error:", error);
        const fallbackStats = { totalPosts: 0, totalUsers: 0, postsToday: 0, publishedPosts: 0 };
        const { renderAdminDashboard: renderAdminDashboard2 } = await Promise.resolve().then(() => (init_dashboard(), dashboard_exports));
        try {
          return new Response(renderAdminDashboard2(fallbackStats, [], [], user, config), {
            headers: { "Content-Type": "text/html" }
          });
        } catch (templateError) {
          return new Response(`
            <h1>Admin Dashboard</h1>
            <p>Dashboard temporarily unavailable. <a href="/admin/add">Add Post</a> | <a href="/admin/users">Manage Users</a></p>
          `, {
            headers: { "Content-Type": "text/html" }
          });
        }
      }
    }, "GET")
  },
  "/admin/edit/:id": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const postModel = new PostModel(env.DB);
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
        const config2 = await configService2.getConfig(env.DB);
        const postId = request.params.id;
        const post = await postModel.getById(postId);
        if (!post) {
          return new Response("Post not found", { status: 404 });
        }
        return new Response(renderEditPostForm(post, user, config2), {
          headers: { "Content-Type": "text/html" }
        });
      } catch (error) {
        console.error("Error loading post for edit:", error);
        return new Response("Internal server error", { status: 500 });
      }
    }, "GET"),
    // Combined POST handler for /admin/edit/:id
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const postId = request.params.id;
        const existingPost = await postModel.getById(postId);
        if (!existingPost) {
          return new Response("Post not found", { status: 404 });
        }
        const formData = await request.formData();
        const title = formData.get("title");
        const content = formData.get("content");
        const slug = formData.get("slug") || "";
        const excerpt = formData.get("excerpt") || "";
        const published = formData.has("published");
        if (!title || !content) {
          return new Response("Title and content are required", { status: 400 });
        }
        const updatedSlug = slug && slug !== existingPost.slug ? slug : existingPost.slug;
        const updatedPost = await postModel.update(postId, {
          title,
          content,
          slug: updatedSlug,
          excerpt,
          published
        });
        logger.info("Post updated successfully", {
          postId,
          title,
          slug: updatedPost.slug,
          published: updatedPost.published
        });
        return Response.redirect(`${new URL(request.url).origin}/`);
      } catch (error) {
        logger.error("Error updating post", { postId: request.params.id, error: error.message });
        if (error instanceof DatabaseError && error.code === "NOT_FOUND") {
          return new Response("Post not found", { status: 404 });
        }
        return new Response(`Failed to update post: ${error.message}`, { status: 500 });
      }
    }, "POST")
  },
  "/admin/settings": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const { SettingsModel: SettingsModel2 } = await Promise.resolve().then(() => (init_models(), models_exports));
        const settingsModel = new SettingsModel2(env.DB);
        const settings = await settingsModel.getAll();
        const { renderSettings: renderSettings2 } = await Promise.resolve().then(() => (init_settings(), settings_exports));
        return new Response(renderSettings2(settings, user), {
          headers: { "Content-Type": "text/html" }
        });
      } catch (error) {
        console.error("Settings error:", error);
        return new Response("Internal server error", { status: 500 });
      }
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const formData = await request.formData();
        const { SettingsModel: SettingsModel2 } = await Promise.resolve().then(() => (init_models(), models_exports));
        const settingsModel = new SettingsModel2(env.DB);
        await settingsModel.set("site_title", formData.get("site_title") || "", "string");
        await settingsModel.set("site_description", formData.get("site_description") || "", "string");
        await settingsModel.set("posts_per_page", formData.get("posts_per_page") || "10", "number");
        await settingsModel.set("date_format", formData.get("date_format") || "M/D/YYYY", "string");
        await settingsModel.set("timezone", formData.get("timezone") || "UTC", "string");
        await settingsModel.set("enable_registration", formData.has("enable_registration"), "boolean");
        await settingsModel.set("require_login_to_read", formData.has("require_login_to_read"), "boolean");
        await settingsModel.set("maintenance_mode", formData.has("maintenance_mode"), "boolean");
        const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
        configService2.clearCache();
        return Response.redirect(`${new URL(request.url).origin}/admin`);
      } catch (error) {
        console.error("Settings update error:", error);
        return new Response("Failed to update settings", { status: 500 });
      }
    }, "POST")
  },
  "/admin/add": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
      const config2 = await configService2.getConfig(env.DB);
      return new Response(renderAddPostForm(user, config2), {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const formData = await request.formData();
        const title = formData.get("title");
        const content = formData.get("content");
        const slug = formData.get("slug") || "";
        const excerpt = formData.get("excerpt") || "";
        const published = formData.has("published");
        logger.info("Adding post", {
          title,
          contentLength: content?.length,
          published
          // Log the published status
        });
        if (!title || !content) {
          return new Response("Title and content are required", { status: 400 });
        }
        const newPost = await postModel.create({
          title,
          content,
          slug: slug || postModel.generateSlug(title),
          excerpt,
          author_id: user.id,
          published
          // This will be true/false
        });
        logger.info("Post created successfully", {
          postId: newPost.id,
          title,
          published: newPost.published
        });
        return Response.redirect(`${new URL(request.url).origin}/`);
      } catch (error) {
        logger.error("Error adding post", { error: error.message });
        if (error instanceof DatabaseError) {
          return new Response(`Database error: ${error.message}`, { status: 500 });
        }
        return new Response("Failed to add post", { status: 500 });
      }
    }, "POST")
  },
  "/admin/delete/:id": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const postId = request.params.id;
        await postModel.delete(postId);
        logger.info("Post deleted successfully", { postId });
        return Response.redirect(`${new URL(request.url).origin}/`);
      } catch (error) {
        logger.error("Error deleting post", { postId: request.params.id, error: error.message });
        if (error instanceof DatabaseError && error.code === "NOT_FOUND") {
          return new Response("Post not found", { status: 404 });
        }
        return new Response("Failed to delete post", { status: 500 });
      }
    }, "POST")
  },
  "/admin/comments/:postId": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const postId = request.params.postId;
      const fedSvc = new FederationService(env);
      const comments = await fedSvc.getThreadedComments(postId);
      const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
      const config2 = await configService2.getConfig(env.DB);
      const { renderCommentList: renderCommentList2 } = await Promise.resolve().then(() => (init_comments(), comments_exports));
      return new Response(renderCommentList2(comments, postId, user, config2), {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET")
  },
  "/admin/add-comment/:postId": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const postId = request.params.postId;
      const { renderAddCommentForm: renderAddCommentForm2 } = await Promise.resolve().then(() => (init_comments(), comments_exports));
      return new Response(renderAddCommentForm2(postId, user), {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const postId = request.params.postId;
      const clonedRequest = request.clone();
      const formData = await clonedRequest.formData();
      const content = formData.get("content");
      if (!content) {
        return new Response("Content is required", { status: 400 });
      }
      const fedSvc = new FederationService(env);
      const post = await env.DB.prepare("SELECT id, federation_metadata FROM posts WHERE id = ?").bind(postId).first();
      if (!post) {
        return new Response("Post not found", { status: 404 });
      }
      const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
      const sourceUrl = meta.source_url || `${env.SITE_URL}/post/${postId}`;
      const comment = {
        id: Date.now(),
        content,
        author: user.username,
        published_at: (/* @__PURE__ */ new Date()).toISOString(),
        parent_url: sourceUrl
      };
      const insertResult = await env.DB.prepare(`
        INSERT INTO posts (title, content, slug, author_id, created_at, published, post_type, parent_id, thread_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        `Comment on ${sourceUrl}`,
        content,
        `comment-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        user.id,
        (/* @__PURE__ */ new Date()).toISOString(),
        1,
        "comment",
        postId,
        postId
      ).run();
      const domains = await fedSvc.getConnectedDomains();
      const targetDomains = domains.map((d2) => d2.domain);
      await fedSvc.sendFederatedComment(comment, targetDomains);
      return Response.redirect(`${new URL(request.url).origin}/admin/comments/${postId}`);
    }, "POST")
  },
  "/admin/comments/reply/:id": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const commentId = request.params.id;
      const comment = await env.DB.prepare(`
        SELECT p.*, u.username as author_username
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.id = ? AND p.post_type = 'comment'
      `).bind(commentId).first();
      if (!comment) return new Response("Comment not found", { status: 404 });
      const { renderReplyForm: renderReplyForm2 } = await Promise.resolve().then(() => (init_comments(), comments_exports));
      return new Response(renderReplyForm2(comment, user), {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const commentId = request.params.id;
      const clonedRequest = request.clone();
      const formData = await clonedRequest.formData();
      const content = formData.get("content");
      if (!content) {
        return new Response("Content is required", { status: 400 });
      }
      const parentComment = await env.DB.prepare(`
        SELECT p.*, u.username as author_username
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.id = ? AND p.post_type = 'comment'
      `).bind(commentId).first();
      if (!parentComment) {
        return new Response("Parent comment not found", { status: 404 });
      }
      const fedSvc = new FederationService(env);
      const post = await env.DB.prepare("SELECT id, federation_metadata FROM posts WHERE id = ?").bind(parentComment.parent_id || parentComment.thread_id).first();
      if (!post) {
        return new Response("Post not found", { status: 404 });
      }
      const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
      const sourceUrl = meta.source_url || `${env.SITE_URL}/post/${parentComment.parent_id || parentComment.thread_id}`;
      const reply = {
        id: Date.now(),
        content,
        author: user.username,
        published_at: (/* @__PURE__ */ new Date()).toISOString(),
        parent_url: sourceUrl,
        in_reply_to: commentId
      };
      const insertResult = await env.DB.prepare(`
        INSERT INTO posts (title, content, slug, author_id, created_at, published, post_type, parent_id, thread_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        `Reply to comment on ${sourceUrl}`,
        content,
        `reply-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        user.id,
        (/* @__PURE__ */ new Date()).toISOString(),
        1,
        "comment",
        commentId,
        parentComment.thread_id || commentId
      ).run();
      const domains = await fedSvc.getConnectedDomains();
      const targetDomains = domains.map((d2) => d2.domain);
      await fedSvc.sendFederatedComment(reply, targetDomains);
      return Response.redirect(`${new URL(request.url).origin}/admin/comments/${parentComment.parent_id || parentComment.thread_id}`);
    }, "POST")
  },
  "/admin/comments/delete/:id": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const commentId = request.params.id;
      const comment = await env.DB.prepare(`
        SELECT p.*, u.username as author_username, p.parent_id AS parent_post_id
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.id = ? AND p.post_type = 'comment'
      `).bind(commentId).first();
      if (!comment) return new Response("Comment not found", { status: 404 });
      await env.DB.prepare("DELETE FROM posts WHERE id = ?").bind(commentId).run();
      const fedSvc = new FederationService(env);
      const domains = await fedSvc.getConnectedDomains();
      const targetDomains = domains.map((d2) => d2.domain);
      await fedSvc.sendDeleteComment(commentId, targetDomains);
      return Response.redirect(`${new URL(request.url).origin}/admin/comments/${comment.parent_post_id || comment.thread_id}`);
    }, "GET")
  },
  "/admin/users": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const userModel = new UserModel(env.DB);
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
        const config2 = await configService2.getConfig(env.DB);
        const users = await userModel.list({ limit: 50 });
        const totalUsers = await userModel.count();
        const { renderUserManagement: renderUserManagement2 } = await Promise.resolve().then(() => (init_userManagement(), userManagement_exports));
        return new Response(renderUserManagement2(users, user, config2), {
          headers: { "Content-Type": "text/html" }
        });
      } catch (error) {
        console.error("User management error:", error);
        return new Response("Internal server error", { status: 500 });
      }
    }, "GET")
  },
  "/admin/users/add": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
      const config2 = await configService2.getConfig(env.DB);
      return new Response(renderAddUserForm(user, config2), {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const formData = await request.formData();
        const username = formData.get("username");
        const password = formData.get("password");
        const role = formData.get("role") || "user";
        if (!username || !password) {
          return new Response("Username and password are required", { status: 400 });
        }
        const newUser = await userModel.create({ username, password, role });
        logger.info("User created successfully", { userId: newUser.id, username, role });
        return Response.redirect(`${new URL(request.url).origin}/admin/users`);
      } catch (error) {
        logger.error("Error creating user", { error: error.message });
        if (error instanceof DatabaseError && error.code === "DUPLICATE_USER") {
          return new Response("Username already exists", { status: 400 });
        }
        return new Response("Failed to create user", { status: 500 });
      }
    }, "POST")
  },
  "/admin/users/delete/:id": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const userId = parseInt(request.params.id);
        if (userId === user.id) {
          return new Response("Cannot delete yourself", { status: 400 });
        }
        await userModel.delete(userId);
        logger.info("User deleted successfully", { userId });
        return Response.redirect(`${new URL(request.url).origin}/admin/users`);
      } catch (error) {
        logger.error("Error deleting user", { userId: request.params.id, error: error.message });
        return new Response("Failed to delete user", { status: 500 });
      }
    }, "POST")
  },
  // Proxy Dashboard
  "/admin/proxy": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      return await handleProxyRoutes(request, env, user);
    }, "GET")
  },
  // Add this to your adminRoutes in routes/admin.js
  "/admin/proxy/discover-domain": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      return await handleProxyTests.discoverDomain(request, env);
    }, "POST")
  },
  // Proxy API Test Endpoints
  "/admin/proxy/test-blog-api": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      return await handleProxyTests.testBlogApi(request, env);
    }, "GET")
  },
  "/admin/proxy/test-email-api": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      return await handleProxyTests.testEmailApi(request, env);
    }, "GET")
  },
  "/admin/proxy/test-federation": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      return await handleProxyTests.testFederation(request, env);
    }, "GET")
  },
  "/admin/proxy/send-test-email": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      return await handleProxyTests.sendTestEmail(request, env);
    }, "POST")
  },
  "/admin/process-outbox": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      try {
        const { OutboxService: OutboxService2 } = await Promise.resolve().then(() => (init_outbox(), outbox_exports));
        const outbox = new OutboxService2(env);
        const result = await outbox.processQueue();
        if (result.error) {
          return Response.json({
            success: false,
            error: result.error,
            message: `Failed to process queue: ${result.error}`
          });
        }
        return Response.json({
          success: true,
          processed: result.processed || 0,
          queued: result.queued || 0,
          message: `\u2705 Processed ${result.processed || 0} operations. ${result.queued || 0} remaining in queue.`
        });
      } catch (error) {
        console.error("Outbox processing error:", error);
        return Response.json({
          success: false,
          error: error.message,
          message: `Failed to process queue: ${error.message}`
        });
      }
    }, "POST")
  },
  // Endpoint for receiving federated posts
  "/federation/receive": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const fedSvc = new FederationService(env);
      const data = await request.json();
      const result = await fedSvc.processIncomingFederation(data);
      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" }
      });
    }, "POST")
  },
  "/admin/federation/sync": {
    POST: /* @__PURE__ */ __name(async (req, env) => {
      const user = await checkAuth(req, env);
      if (!user) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }
      const fedSvc = new FederationService(env);
      const result = await fedSvc.syncNetwork();
      return Response.json({
        success: true,
        message: `Imported ${result.imported} new posts from ${result.domains} domains.`,
        imported: result.imported,
        domains: result.domains,
        newPosts: result.newPosts
        // optional: raw posts for client-side rendering
      });
    }, "POST")
  },
  "/federation/outbox": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const url = new URL(request.url);
      const limit = parseInt(url.searchParams.get("limit") || "50");
      const since = url.searchParams.get("since");
      let query = `
        SELECT id, title, content, created_at, author_id, federation_metadata
        FROM posts
        WHERE post_type = 'federated'
          AND published = 1
      `;
      const params = [];
      if (since) {
        query += ` AND created_at > ?`;
        params.push(since);
      }
      query += ` ORDER BY created_at DESC LIMIT ?`;
      params.push(limit);
      const { results: posts } = await env.DB.prepare(query).bind(...params).all();
      const items = posts.map((post) => {
        const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
        return {
          id: `${url.origin}/posts/${post.id}`,
          type: "Create",
          actor: meta.actor || `${url.origin}/actors/system`,
          object: {
            id: `${url.origin}/posts/${post.id}`,
            type: "Note",
            content: post.content,
            published: post.created_at,
            attributedTo: meta.actor || `${url.origin}/actors/system`,
            to: ["https://www.w3.org/ns/activitystreams#Public"]
          }
        };
      });
      const response = {
        "@context": "https://www.w3.org/ns/activitystreams",
        id: url.href,
        type: "OrderedCollectionPage",
        partOf: `${url.origin}/federation/outbox`,
        orderedItems: items,
        next: null
        // Add pagination later
      };
      return new Response(JSON.stringify(response), {
        headers: { "Content-Type": "application/json" }
      });
    }, "GET")
  },
  "/admin/federate-post/(?<id>[^/]+)": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const postId = request.params.id;
        const federationService = new FederationService(env);
        const post = await env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first();
        if (!post) {
          return Response.json({ success: false, error: "Post not found" });
        }
        const domains = await federationService.getConnectedDomains();
        const targetDomains = domains.map((d2) => d2.domain);
        if (targetDomains.length === 0) {
          return Response.json({ success: false, error: "No federated domains found" });
        }
        const results = await federationService.sendFederatedPost(post, targetDomains);
        return Response.json({
          success: true,
          message: `Post "${post.title}" federated to ${targetDomains.length} domains`,
          results
        });
      } catch (error) {
        console.error("Federation error:", error);
        return Response.json({ success: false, error: error.message });
      }
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const postId = request.params.id;
        const federationService = new FederationService(env);
        const post = await env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first();
        if (!post) {
          return Response.json({ success: false, error: "Post not found" });
        }
        const domains = await federationService.getConnectedDomains();
        const targetDomains = domains.map((d2) => d2.domain);
        if (targetDomains.length === 0) {
          return Response.json({ success: false, error: "No federated domains found" });
        }
        const results = await federationService.sendFederatedPost(post, targetDomains);
        return Response.json({
          success: true,
          message: `Post federated to ${targetDomains.length} domains`,
          results
        });
      } catch (error) {
        console.error("Federation error:", error);
        return Response.json({ success: false, error: error.message });
      }
    }, "POST")
  },
  "/admin/inject-emails": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user || user.role !== "admin") {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const content = `
        <h1>Inject Emails</h1>
        <p>This will inject mock email data into the posts table for testing purposes.</p>
        <form action="/admin/inject-emails" method="POST">
          <button type="submit">Inject Mock Emails</button>
        </form>
        <div class="admin-actions">
          <a href="/admin" class="button secondary">Back to Dashboard</a>
          <a href="/inbox" class="button">View Inbox</a>
        </div>
      `;
      return new Response(renderTemplate("Inject Emails", content, user), {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      if (!user || user.role !== "admin") {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      try {
        const mockEmails = [
          {
            subject: "Your account is live - join millions of businesses on Google",
            body: "thatch, welcome to Google\n\nNow you can start growing your business.\n\nComplete your profile  \n<https://business.google.com/create?hl=en&gmbsrc=US-en-et-em-z-gmb-z-l~wlcemnewv%7Ccreate&mcsubid=ww-ww-xs-mc-simedm-1-simometest!o3&trk=https%3A%2F%2Fc.gle%2FANiao5o-_gstjXfaH2vfT_kVzzSgMwbu_1X48UquUw0U6Zg1mL4h9fJvctaO5ZJBjaNHYTlIkvKGEO_YHYziseGVtWfCGQ5fZyLL60gkNNhfvIy9IkLOkgX0mej2jq0l6fkuRfcsmF7ZAlQ>\n\nCongratulations \u2013 your account is live and ready for action. You now have access to a range of tools that can help your business reach more people.\n\n...",
            from: "Google Community Team <googlecommunityteam-noreply@google.com>",
            to: "deadlight.boo@gmail.com",
            date: "Sat, 02 Aug 2025 07:21:59 -0700",
            message_id: "a1d91498095de4b1b3de613c0fe9cd1471d1f0d1-20166281-111702100@google.com"
          },
          {
            subject: "Test Email for Deadlight Comm",
            body: "Hello,\n\nThis is a test email to check if the inbox rendering works correctly in Deadlight Comm.\n\nBest regards,\nTest User",
            from: "Test User <test@example.com>",
            to: "deadlight.boo@gmail.com",
            date: "Sun, 03 Aug 2025 10:00:00 -0700",
            message_id: "test-1234567890@example.com"
          }
        ];
        let insertedCount = 0;
        for (const email of mockEmails) {
          try {
            const metadata = JSON.stringify({
              from: email.from,
              to: email.to,
              message_id: email.message_id,
              date: email.date
            });
            const shortMsgId = email.message_id.length > 20 ? email.message_id.substring(0, 20) : email.message_id;
            const checkQuery = "SELECT id FROM posts WHERE is_email = 1 AND email_metadata LIKE ? LIMIT 1";
            const existing = await env.DB.prepare(checkQuery).bind(`%${shortMsgId}%`).first();
            if (!existing) {
              const insertQuery = `
                INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              `;
              await env.DB.prepare(insertQuery).bind(
                email.subject,
                email.body,
                `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                // Unique slug
                user.id,
                // Use logged-in user's ID
                email.date || (/* @__PURE__ */ new Date()).toISOString(),
                (/* @__PURE__ */ new Date()).toISOString(),
                0,
                // Not published (private)
                1,
                // is_email flag
                metadata
              ).run();
              insertedCount++;
              logger.info(`Injected email: ${email.subject}`, { userId: user.id });
            } else {
              logger.info(`Skipped existing email: ${email.subject}`, { userId: user.id });
            }
          } catch (err) {
            logger.error(`Error injecting email ${email.subject}:`, { error: err.message, userId: user.id });
          }
        }
        const content = `
          <h2>Injection Complete</h2>
          <p>Inserted ${insertedCount} email(s) into the database.</p>
          <div class="admin-actions">
            <a href="/inbox" class="button">View Inbox</a>
            <a href="/admin" class="button secondary">Back to Dashboard</a>
          </div>
        `;
        return new Response(renderTemplate("Injection Complete", content, user), {
          headers: { "Content-Type": "text/html" }
        });
      } catch (error) {
        logger.error("Error injecting emails", { error: error.message, userId: user.id });
        return new Response(renderTemplate("Error", `<p>Failed to inject emails: ${error.message}</p>`, user), {
          headers: { "Content-Type": "text/html" },
          status: 500
        });
      }
    }, "POST")
  },
  "/admin/fetch-emails": {
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      if (!user || user.role !== "admin") {
        const apiKey = request.headers.get("X-API-Key");
        const expectedKey = env.API_KEY || "YOUR_API_KEY";
        if (apiKey !== expectedKey) {
          logger.warn("Unauthorized fetch-emails attempt", { ip: request.headers.get("CF-Connecting-IP") || "unknown" });
          return new Response(JSON.stringify({ error: "Unauthorized" }), {
            headers: { "Content-Type": "application/json" },
            status: 403
          });
        }
      }
      try {
        const payload = await request.json();
        let insertedCount = 0;
        if (Array.isArray(payload.emails)) {
          for (const email of payload.emails) {
            try {
              const metadata = JSON.stringify({
                from: email.from || "Unknown Sender",
                to: email.to || "Unknown Recipient",
                message_id: email.message_id || `msg-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                date: email.date || (/* @__PURE__ */ new Date()).toISOString()
              });
              const checkQuery = "SELECT id FROM posts WHERE is_email = 1 AND title = ? LIMIT 1";
              const existing = await env.DB.prepare(checkQuery).bind(email.subject || "Untitled Email").first();
              if (!existing) {
                const insertQuery = `
                  INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `;
                await env.DB.prepare(insertQuery).bind(
                  email.subject || "Untitled Email",
                  email.body || "No content",
                  `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                  // Unique slug
                  user?.id || 2,
                  // Use logged-in user's ID or default admin ID
                  email.date || (/* @__PURE__ */ new Date()).toISOString(),
                  (/* @__PURE__ */ new Date()).toISOString(),
                  0,
                  // Not published (private)
                  1,
                  // is_email flag
                  metadata
                ).run();
                insertedCount++;
                logger.info(`Fetched and inserted email: ${email.subject || "Untitled Email"}`, { userId: user?.id || "API" });
              } else {
                logger.info(`Skipped existing email: ${email.subject || "Untitled Email"}`, { userId: user?.id || "API" });
              }
            } catch (err) {
              logger.error(`Error inserting email ${email.subject || "Untitled Email"}:`, { error: err.message, userId: user?.id || "API" });
            }
          }
        }
        return new Response(JSON.stringify({ success: true, inserted: insertedCount }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        logger.error("Error fetching emails via API", { error: error.message, userId: user?.id || "API" });
        return new Response(JSON.stringify({ error: "Failed to fetch emails", details: error.message }), {
          headers: { "Content-Type": "application/json" },
          status: 500
        });
      }
    }, "POST")
  },
  "/admin/notifications": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const notifications = await env.DB.prepare(`
        SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
      `).bind(user.id).all();
    }, "GET")
  },
  "/admin/federation": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
      const config2 = await configService2.getConfig(env.DB);
      const fed = new FederationService(env);
      const [domains, posts] = await Promise.all([
        fed.getConnectedDomains(),
        fed.getFederatedPosts()
      ]);
      return new Response(
        federationDashboard(posts, domains, user, config2),
        { headers: { "Content-Type": "text/html" } }
      );
    }, "GET")
  },
  "/admin/moderation": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        const origin = new URL(request.url).origin;
        return Response.redirect(`${origin}/login`, 302);
      }
      const { results: pendingPosts } = await env.DB.prepare(`
        SELECT id, title, content, author_id, created_at, moderation_notes
        FROM posts
        WHERE post_type = 'federated'
          AND moderation_status = 'pending'
        ORDER BY created_at DESC
        LIMIT 100
      `).all();
      const rows = pendingPosts.map((p) => {
        const date = new Date(p.created_at).toLocaleString();
        const snippet = p.content.length > 100 ? p.content.slice(0, 100) + "\u2026" : p.content;
        return `
          <tr>
            <td>${p.id}</td>
            <td>${p.title}</td>
            <td>${date}</td>
            <td>${snippet}</td>
            <td>
              <form action="/admin/moderation/${p.id}/approve" method="POST" style="display:inline">
                <button type="submit">Approve</button>
              </form>
              <form action="/admin/moderation/${p.id}/reject" method="POST" style="display:inline">
                <input type="text" name="reason" placeholder="Reason" />
                <button type="submit">Reject</button>
              </form>
            </td>
          </tr>`;
      }).join("");
      const html = `
        <h1>Federation Moderation Queue</h1>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Received</th>
              <th>Content</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
        <p><a href="/admin">\u2190 Back to Dashboard</a></p>
      `;
      return new Response(renderTemplate("Moderation Queue", html, user), {
        headers: { "Content-Type": "text/html" }
      });
    }, "GET")
  },
  "/admin/pending-replies": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      const apiKey = request.headers.get("X-API-Key");
      const expectedKey = env.X_API_KEY || "YOUR_API_KEY";
      console.log("Debugging API Key - Received:", apiKey ? apiKey.substring(0, 5) + "..." : "none");
      console.log("Debugging API Key - Expected:", expectedKey ? expectedKey.substring(0, 5) + "..." : "none");
      const isAuthenticated = user && user.role === "admin" || apiKey === expectedKey;
      if (!isAuthenticated) {
        logger.warn("Unauthorized pending-replies attempt", {
          ip: request.headers.get("CF-Connecting-IP") || "unknown",
          keyProvided: !!apiKey,
          userPresent: !!user,
          userRole: user ? user.role : "none"
        });
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          headers: { "Content-Type": "application/json" },
          status: 403
        });
      }
      try {
        const query = `SELECT * FROM posts WHERE is_reply_draft = 1 AND email_metadata LIKE '%sent":false%'`;
        const repliesResult = await env.DB.prepare(query).all();
        const pendingReplies = repliesResult.results.map((reply) => {
          const metadata = reply.email_metadata ? JSON.parse(reply.email_metadata) : {};
          return {
            id: reply.id,
            to: metadata.to || "Unknown",
            from: metadata.from || "deadlight.boo@gmail.com",
            subject: reply.title,
            body: reply.content,
            original_id: metadata.original_id || null,
            queued_at: metadata.date_queued || reply.created_at
          };
        });
        return new Response(JSON.stringify({ success: true, replies: pendingReplies }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        logger.error("Error fetching pending replies", { error: error.message, userId: user?.id || "API" });
        return new Response(JSON.stringify({ error: "Failed to fetch pending replies", details: error.message }), {
          headers: { "Content-Type": "application/json" },
          status: 500
        });
      }
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const logger = new Logger({ context: "admin" });
      const user = await checkAuth(request, env);
      const apiKey = request.headers.get("X-API-Key");
      const expectedKey = env.X_API_KEY || "YOUR_API_KEY";
      const isAuthenticated = user && user.role === "admin" || apiKey === expectedKey;
      if (!isAuthenticated) {
        logger.warn("Unauthorized mark-sent attempt", {
          ip: request.headers.get("CF-Connecting-IP") || "unknown",
          keyProvided: !!apiKey,
          userPresent: !!user,
          userRole: user ? user.role : "none"
        });
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          headers: { "Content-Type": "application/json" },
          status: 403
        });
      }
      try {
        const payload = await request.json();
        const replyId = payload.id;
        if (!replyId) {
          return new Response(JSON.stringify({ error: "Reply ID required" }), {
            headers: { "Content-Type": "application/json" },
            status: 400
          });
        }
        const query = "SELECT * FROM posts WHERE id = ? AND is_reply_draft = 1";
        const replyResult = await env.DB.prepare(query).bind(replyId).first();
        if (!replyResult) {
          return new Response(JSON.stringify({ error: "Reply not found" }), {
            headers: { "Content-Type": "application/json" },
            status: 404
          });
        }
        const metadata = replyResult.email_metadata ? JSON.parse(replyResult.email_metadata) : {};
        metadata.sent = true;
        metadata.date_sent = (/* @__PURE__ */ new Date()).toISOString();
        const updateQuery = "UPDATE posts SET email_metadata = ?, updated_at = ? WHERE id = ?";
        await env.DB.prepare(updateQuery).bind(
          JSON.stringify(metadata),
          (/* @__PURE__ */ new Date()).toISOString(),
          replyId
        ).run();
        logger.info(`Marked reply ${replyId} as sent`, { userId: user?.id || "API" });
        return new Response(JSON.stringify({ success: true, id: replyId }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (error) {
        logger.error("Error marking reply as sent", { error: error.message, userId: user?.id || "API" });
        return new Response(JSON.stringify({ error: "Failed to mark reply as sent", details: error.message }), {
          headers: { "Content-Type": "application/json" },
          status: 500
        });
      }
    }, "POST")
  },
  "/admin/proxy/status-stream": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      return await handleProxyTests.statusStream(request, env);
    }, "GET")
  },
  // Also add a JSON status endpoint for fallback
  "/admin/proxy/status": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: "Unauthorized" }, { status: 401 });
      }
      try {
        const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || "http://localhost:8080" });
        const outboxService = new EnhancedOutboxService(env);
        const [proxyStatus, queueStatus] = await Promise.allSettled([
          proxyService.healthCheck(),
          outboxService.getStatus()
        ]);
        return Response.json({
          success: true,
          data: {
            proxy_connected: proxyStatus.status === "fulfilled" && proxyStatus.value.proxy_connected,
            blogApi: proxyStatus.status === "fulfilled" ? proxyStatus.value.blog_api : null,
            emailApi: proxyStatus.status === "fulfilled" ? proxyStatus.value.email_api : null,
            queueCount: queueStatus.status === "fulfilled" ? queueStatus.value.queued_operations?.total || 0 : 0,
            circuitState: proxyService.getCircuitState(),
            timestamp: (/* @__PURE__ */ new Date()).toISOString()
          }
        });
      } catch (error) {
        return Response.json({
          success: false,
          error: error.message,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    }, "GET")
  }
};

// src/routes/blog.js
init_checked_fetch();

// src/templates/blog/list.js
init_checked_fetch();
init_base2();

// ../lib.deadlight/core/src/components/posts/index.js
init_checked_fetch();

// ../lib.deadlight/core/src/components/posts/list.js
init_checked_fetch();

// ../lib.deadlight/core/src/markdown/index.js
init_checked_fetch();
init_processor();

// ../lib.deadlight/core/src/utils/templates.js
init_checked_fetch();
function renderAuthorLink(username) {
  return `<a href="/user/${username}" class="author-link">${username}</a>`;
}
__name(renderAuthorLink, "renderAuthorLink");

// ../lib.deadlight/core/src/components/posts/list.js
var PostList = class {
  static {
    __name(this, "PostList");
  }
  constructor(options = {}) {
    this.markdown = options.markdown || new MarkdownProcessor();
    this.showActions = options.showActions !== false;
    this.showAuthor = options.showAuthor !== false;
    this.showDate = options.showDate !== false;
    this.excerptLength = options.excerptLength || 300;
  }
  render(posts = [], options = {}) {
    const { user = null, baseUrl = "" } = options;
    if (posts.length === 0) {
      return "<p>No posts yet.</p>";
    }
    return posts.map((post) => this.renderPost(post, user, baseUrl)).join("\n");
  }
  renderPost(post, user, baseUrl = "") {
    const excerpt = this.markdown.extractExcerpt(post.content, this.excerptLength);
    const hasMore = this.markdown.hasMore(post.content, this.excerptLength);
    return `
      <article class="post-preview">
        <h2><a href="${baseUrl}/post/${post.id}">${post.title}</a></h2>
        ${this.renderMeta(post)}
        <div class="post-excerpt">
          ${this.markdown.render(excerpt)}
        </div>
        <div class="post-footer">
          ${hasMore ? `<a href="${baseUrl}/post/${post.id}" class="read-more">Read more \u2192</a>` : ""}
          ${user && this.showActions ? this.renderActions(post, baseUrl) : ""}
        </div>
      </article>
    `;
  }
  renderMeta(post) {
    const parts = [];
    if (this.showAuthor && post.author_username) {
      parts.push(`By ${renderAuthorLink(post.author_username)}`);
    }
    if (this.showDate && post.created_at) {
      parts.push(new Date(post.created_at).toLocaleDateString());
    }
    return parts.length > 0 ? `<div class="post-meta">${parts.join(" | ")}</div>` : "";
  }
  renderActions(post, baseUrl = "") {
    return `
      <div class="post-actions">
        <a href="${baseUrl}/admin/edit/${post.id}" class="button edit-button">Edit</a>
        <form class="delete-link" action="${baseUrl}/admin/delete/${post.id}" method="POST" style="display: inline;">
          <button type="submit" class="button delete-button">Delete</button>
        </form>
      </div>
    `;
  }
};

// ../lib.deadlight/core/src/components/posts/pagination.js
init_checked_fetch();
var Pagination = class {
  static {
    __name(this, "Pagination");
  }
  constructor(options = {}) {
    this.maxPagesToShow = options.maxPagesToShow || 5;
    this.baseUrl = options.baseUrl || "/";
  }
  render(pagination2) {
    if (!pagination2 || pagination2.totalPages <= 1) {
      return "";
    }
    const { currentPage, totalPages, hasPrevious, hasNext, previousPage, nextPage } = pagination2;
    const pageNumbers = this.getPageNumbers(currentPage, totalPages);
    return `
      <nav class="pagination" aria-label="Pagination Navigation">
        ${this.renderNavButtons(hasPrevious, hasNext, previousPage, nextPage, totalPages)}
        ${this.renderPageNumbers(pageNumbers, currentPage, totalPages)}
        <div class="pagination-info">Page ${currentPage} of ${totalPages}</div>
      </nav>
    `;
  }
  getPageNumbers(currentPage, totalPages) {
    const pageNumbers = [];
    let startPage = Math.max(1, currentPage - Math.floor(this.maxPagesToShow / 2));
    let endPage = Math.min(totalPages, startPage + this.maxPagesToShow - 1);
    if (endPage - startPage < this.maxPagesToShow - 1) {
      startPage = Math.max(1, endPage - this.maxPagesToShow + 1);
    }
    for (let i = startPage; i <= endPage; i++) {
      pageNumbers.push(i);
    }
    return { pageNumbers, startPage, endPage };
  }
  renderNavButtons(hasPrevious, hasNext, previousPage, nextPage, totalPages) {
    return `
      ${hasPrevious ? `
        <a href="${this.baseUrl}?page=1" class="pagination-link pagination-first" aria-label="First page">\u226A</a>
        <a href="${this.baseUrl}?page=${previousPage}" class="pagination-link pagination-prev" aria-label="Previous page">\u2039</a>
      ` : `
        <span class="pagination-link pagination-disabled">\u226A</span>
        <span class="pagination-link pagination-disabled">\u2039</span>
      `}
      
      ${hasNext ? `
        <a href="${this.baseUrl}?page=${nextPage}" class="pagination-link pagination-next" aria-label="Next page">\u203A</a>
        <a href="${this.baseUrl}?page=${totalPages}" class="pagination-link pagination-last" aria-label="Last page">\u226B</a>
      ` : `
        <span class="pagination-link pagination-disabled">\u203A</span>
        <span class="pagination-link pagination-disabled">\u226B</span>
      `}
    `;
  }
  renderPageNumbers({ pageNumbers, startPage, endPage }, currentPage, totalPages) {
    return `
      ${startPage > 1 ? '<span class="pagination-ellipsis">...</span>' : ""}
      
      ${pageNumbers.map(
      (num) => num === currentPage ? `<span class="pagination-link pagination-current" aria-current="page">${num}</span>` : `<a href="${this.baseUrl}?page=${num}" class="pagination-link">${num}</a>`
    ).join("")}
      
      ${endPage < totalPages ? '<span class="pagination-ellipsis">...</span>' : ""}
    `;
  }
};

// src/templates/blog/list.js
var postList = new PostList({
  showActions: true,
  showAuthor: true,
  showDate: true
});
var pagination = new Pagination({
  baseUrl: "/"
});
function renderPostList(posts = [], user = null, paginationData = null, config2 = null) {
  const postsHtml = postList.render(posts, { user });
  const paginationHtml = pagination.render(paginationData);
  return renderTemplate(
    "Blog Posts",
    `<div class="container">
      ${postsHtml}
      ${paginationHtml}
    </div>`,
    user,
    config2
  );
}
__name(renderPostList, "renderPostList");

// src/templates/blog/single.js
init_checked_fetch();
init_base2();
init_processor();
function renderSinglePost(post, user, navigation, config2, comments = []) {
  if (!post) throw new Error("Post is undefined");
  if (post.post_type === "comment") {
    const parentUrl = post.federation_metadata ? JSON.parse(post.federation_metadata).parent_url : null;
    return renderTemplate("Comment", `
      <h1 class="post-title">This is a Comment</h1>
      <p>This content is a comment on <a href="${parentUrl}">${parentUrl}</a>.</p>
      <p>Content: ${post.content}</p>
      <p class="post-meta">By ${renderAuthorLink(post.author_username)} | ${new Date(post.created_at).toLocaleDateString()}</p>
      ${user ? `
        <div class="comment-actions">
          <a href="/admin/comments/edit/${post.id}" class="button edit-button">Edit</a>
          <a href="/admin/comments/delete/${post.id}" class="button delete-button">Delete</a>
          <a href="/admin/comments/reply/${post.id}" class="button reply-button">Reply</a>
        </div>
      ` : ""}
      <a href="${parentUrl || "/"}">Back to Post</a>
    `, user, config2);
  }
  const commentHtml = comments.length ? `
    <div class="comment-list">
      <h2>Comments</h2>
      ${comments.map((comment, index) => `
        <div class="comment" style="margin-left: ${comment.level * 20}px;">
          <p class="post-content">${comment.content}</p>
          <p class="post-meta">By ${comment.author} | ${new Date(comment.published_at).toLocaleDateString()}</p>
          ${user ? `
            <div class="comment-actions">
              <a href="/admin/comments/edit/${comment.id}" class="button edit-button">Edit</a>
              <a href="/admin/comments/delete/${comment.id}" class="button delete-button">Delete</a>
              <a href="/admin/comments/reply/${comment.id}" class="button reply-button">Reply</a>
            </div>
          ` : ""}
        </div>
      `).join("")}
    </div>
  ` : '<p class="no-comments">No comments yet.</p>';
  const fullContent = post.content.replace("<--!more-->", "");
  const content = `
    <h1 class="post-title">${post.title}</h1>
    <div class="post-meta">
      <span>By ${renderAuthorLink(post.author_username)}</span>
      <span>| ${new Date(post.created_at).toLocaleDateString()}</span>
    </div>
    <div class="post-content">${renderMarkdown(fullContent)}</div>
    ${navigation ? `
      <div class="post-navigation">
        ${navigation.prev_id ? `<a href="/post/${navigation.prev_id}" class="button">Previous: ${navigation.prev_title}</a>` : ""}
        ${navigation.next_id ? `<a href="/post/${navigation.next_id}" class="button">Next: ${navigation.next_title}</a>` : ""}
      </div>
    ` : ""}
    ${user ? `<a href="/admin/add-comment/${post.id}" class="button">Add Comment</a>` : ""}
    ${user ? `<a href="/admin/edit/${post.id}" class="button">Edit</a>` : ""}
    ${commentHtml}
  `;
  return renderTemplate(post.title, content, user, config2);
}
__name(renderSinglePost, "renderSinglePost");

// src/routes/blog.js
init_password();
init_federation();
var blogRoutes = {
  "/": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      try {
        const user = await checkAuth(request, env);
        const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
        const config2 = await configService2.getConfig(env.DB);
        const postsPerPage = parseInt(config2.postsPerPage) || 10;
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get("page") || "1");
        const offset = (page - 1) * postsPerPage;
        const countResult = await env.DB.prepare(`
          SELECT COUNT(*) as total 
          FROM posts 
          WHERE published = 1 AND post_type != 'comment'
        `).first();
        const totalPosts = countResult.total;
        const totalPages = Math.ceil(totalPosts / postsPerPage);
        const result = await env.DB.prepare(`
          SELECT posts.*, users.username as author_username 
          FROM posts 
          JOIN users ON posts.author_id = users.id 
          WHERE posts.published = 1 AND posts.post_type != 'comment'
          ORDER BY posts.created_at DESC
          LIMIT ? OFFSET ?
        `).bind(postsPerPage, offset).all();
        const paginationData = {
          currentPage: page,
          totalPages,
          totalPosts,
          postsPerPage,
          hasPrevious: page > 1,
          hasNext: page < totalPages,
          previousPage: page - 1,
          nextPage: page + 1
        };
        return new Response(
          renderPostList(result.results, user, paginationData, config2),
          { headers: { "Content-Type": "text/html" } }
        );
      } catch (error) {
        console.error("Blog route error:", error);
        return new Response("Internal server error", { status: 500 });
      }
    }, "GET")
  },
  "/post/:slug": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      try {
        const user = await checkAuth(request, env);
        const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
        const config2 = await configService2.getConfig(env.DB);
        const slug = request.params.slug;
        let post = await env.DB.prepare(`
          SELECT posts.*, users.username as author_username
          FROM posts 
          LEFT JOIN users ON posts.author_id = users.id
          WHERE posts.slug = ? AND posts.published = 1 AND posts.post_type != 'comment'
        `).bind(slug).first();
        if (!post && !isNaN(slug)) {
          post = await env.DB.prepare(`
            SELECT posts.*, users.username as author_username
            FROM posts 
            LEFT JOIN users ON posts.author_id = users.id
            WHERE posts.id = ? AND posts.published = 1 AND posts.post_type != 'comment'
          `).bind(parseInt(slug)).first();
        }
        if (!post) {
          return new Response("Post not found", { status: 404 });
        }
        let navigation = null;
        try {
          const prevPost = await env.DB.prepare(`
            SELECT id, title, slug
            FROM posts 
            WHERE created_at < ? AND published = 1 AND post_type != 'comment' AND (is_email = 0 OR is_email IS NULL)
            ORDER BY created_at DESC 
            LIMIT 1
          `).bind(post.created_at).first();
          const nextPost = await env.DB.prepare(`
            SELECT id, title, slug
            FROM posts 
            WHERE created_at > ? AND published = 1 AND post_type != 'comment' AND (is_email = 0 OR is_email IS NULL)
            ORDER BY created_at ASC 
            LIMIT 1
          `).bind(post.created_at).first();
          if (prevPost || nextPost) {
            navigation = {
              prev_id: prevPost ? prevPost.slug || prevPost.id : null,
              prev_title: prevPost ? prevPost.title : null,
              next_id: nextPost ? nextPost.slug || nextPost.id : null,
              next_title: nextPost ? nextPost.title : null
            };
          }
        } catch (navError) {
          console.error("Navigation query error:", navError);
        }
        const fedSvc = new FederationService(env);
        const comments = await fedSvc.getThreadedComments(post.id);
        return new Response(renderSinglePost(post, user, navigation, config2, comments), {
          headers: { "Content-Type": "text/html" }
        });
      } catch (error) {
        console.error("Post page error:", error);
        return new Response("Internal server error", { status: 500 });
      }
    }, "GET")
  }
};

// src/routes/inbox.js
init_checked_fetch();
init_base2();
init_processor();
init_password();
init_config2();
var inboxRoutes = {
  "/inbox": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const config2 = await configService.getConfig(env.DB);
      const page = parseInt(request.query?.page || "1");
      const limit = config2.postsPerPage || 10;
      const offset = (page - 1) * limit;
      const query = "SELECT * FROM posts WHERE is_email = 1 ORDER BY created_at DESC LIMIT ? OFFSET ?";
      const countQuery = "SELECT COUNT(*) as total FROM posts WHERE is_email = 1";
      const emailsResult = await env.DB.prepare(query).bind(limit, offset).all();
      const countResult = await env.DB.prepare(countQuery).first();
      const totalEmails = countResult.total;
      const totalPages = Math.ceil(totalEmails / limit);
      const processor = new MarkdownProcessor();
      const emails = emailsResult.results.map((email) => {
        const metadata = email.email_metadata ? JSON.parse(email.email_metadata) : {};
        const excerpt = email.content.length > 200 ? email.content.substring(0, 200) + "..." : email.content;
        return {
          ...email,
          from: metadata.from || "Unknown Sender",
          date: metadata.date || email.created_at,
          content: excerpt,
          // Show excerpt in list view
          full_content: processor.render(email.content)
          // Render full content for single view
        };
      });
      const emailList = emails.length > 0 ? emails.map((email) => `
            <article class="email-preview">
              <h2><a href="/email/${email.id}">${escapeHtml(email.title)}</a></h2>
              <div class="email-meta">
                <strong>From:</strong> ${escapeHtml(email.from)} | <strong>Date:</strong> ${new Date(email.date).toLocaleString()}
              </div>
              <div class="email-excerpt">
                ${processor.render(email.content)}
              </div>
              <div class="email-footer">
                <a href="/email/${email.id}" class="read-more">Read Full Email \u2192</a>
                ${user ? `
                  <div class="email-actions">
                    <a href="/inbox/reply/${email.id}" class="button reply-button">Reply</a>
                  </div>
                ` : ""}
              </div>
            </article>
          `).join("\n") : "<p>No emails in inbox.</p>";
      const pagination2 = {
        currentPage: page,
        totalPages,
        hasPrevious: page > 1,
        hasNext: page < totalPages,
        previousPage: page - 1,
        nextPage: page + 1,
        totalEmails
      };
      const paginationHtml = renderPagination(pagination2, "/inbox");
      return new Response(
        renderTemplate(
          "Email Inbox",
          `<div class="container">
            <h1>Email Inbox</h1>
            ${emailList}
            ${paginationHtml}
          </div>`,
          user,
          config2
          // Pass config here
        ),
        { headers: { "Content-Type": "text/html" } }
      );
    }, "GET")
  },
  "/email/:id": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const config2 = await configService.getConfig(env.DB);
      const emailId = request.params.id;
      const query = "SELECT * FROM posts WHERE id = ? AND is_email = 1";
      const emailResult = await env.DB.prepare(query).bind(emailId).first();
      if (!emailResult) {
        return new Response(
          renderTemplate("Email Not Found", "<p>Email not found or access denied.</p>", user, config2),
          { headers: { "Content-Type": "text/html" }, status: 404 }
        );
      }
      const metadata = emailResult.email_metadata ? JSON.parse(emailResult.email_metadata) : {};
      const processor = new MarkdownProcessor();
      const email = {
        ...emailResult,
        from: metadata.from || "Unknown Sender",
        date: metadata.date || emailResult.created_at,
        content: processor.render(emailResult.content)
      };
      const emailDate = new Date(email.date).toLocaleString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      });
      const content = `
        <article class="single-email">
          <header class="email-header">
            <h1>${escapeHtml(email.title)}</h1>
            <div class="email-meta">
              <span><strong>From:</strong> ${escapeHtml(email.from)}</span>
              <span class="separator">\u2022</span>
              <time datetime="${email.date}">${emailDate}</time>
            </div>
          </header>
          <div class="email-content">
            ${email.content}
          </div>
          ${user ? `
            <div class="email-actions">
              <a href="/inbox/reply/${email.id}" class="button reply-button">Reply</a>
              <form class="delete-form" action="/inbox/delete/${email.id}" method="POST" 
                    onsubmit="return confirm('Are you sure you want to delete this email?');">
                <button type="submit" class="button delete-button">Delete</button>
              </form>
            </div>
          ` : ""}
          <nav class="email-navigation">
            <a href="/inbox" class="nav-back">\u2190 Back to Inbox</a>
          </nav>
        </article>
      `;
      return new Response(
        renderTemplate(email.title, `<div class="container">${content}</div>`, user, config2),
        { headers: { "Content-Type": "text/html" } }
      );
    }, "GET")
  },
  "/inbox/reply/:id": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const config2 = await configService.getConfig(env.DB);
      const emailId = request.params.id;
      const query = "SELECT * FROM posts WHERE id = ? AND is_email = 1";
      const emailResult = await env.DB.prepare(query).bind(emailId).first();
      if (!emailResult) {
        return new Response(
          renderTemplate("Email Not Found", "<p>Email not found or access denied.</p>", user, config2),
          { headers: { "Content-Type": "text/html" }, status: 404 }
        );
      }
      const metadata = emailResult.email_metadata ? JSON.parse(emailResult.email_metadata) : {};
      const originalFrom = metadata.from || "Unknown Sender";
      const originalSubject = emailResult.title || "No Subject";
      const replyTo = originalFrom;
      const replySubject = originalSubject.startsWith("Re:") ? originalSubject : `Re: ${originalSubject}`;
      const quotedBody = `On ${new Date(metadata.date || emailResult.created_at).toLocaleString()}, ${originalFrom} wrote:
> ${emailResult.content.split("\n").join("\n> ")}`;
      const content = `
        <div class="reply-form-container">
            <h1>Reply to ${escapeHtml(originalFrom)}</h1>
            <form action="/inbox/reply/${emailId}" method="POST" class="reply-form">
            <div class="form-group">
                <label for="to">To:</label>
                <input type="text" id="to" name="to" value="${escapeHtml(replyTo)}" readonly class="form-input readonly">
            </div>
            <div class="form-group">
                <label for="subject">Subject:</label>
                <input type="text" id="subject" name="subject" value="${escapeHtml(replySubject)}" class="form-input">
            </div>
            <div class="form-group">
                <label for="body">Your Reply:</label>
                <textarea id="body" name="body" rows="10" class="form-textarea" placeholder="Write your reply here...">

${quotedBody}</textarea>
            </div>
            <div class="form-actions">
                <button type="submit" class="button send-button">Send Reply</button>
                <a href="/email/${emailId}" class="button cancel-button secondary">Cancel</a>
            </div>
            </form>
        </div>
        `;
      return new Response(
        renderTemplate("Compose Reply", `<div class="container">${content}</div>`, user, config2),
        { headers: { "Content-Type": "text/html" } }
      );
    }, "GET"),
    POST: /* @__PURE__ */ __name(async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      const config2 = await configService.getConfig(env.DB);
      const emailId = request.params.id;
      const query = "SELECT * FROM posts WHERE id = ? AND is_email = 1";
      const emailResult = await env.DB.prepare(query).bind(emailId).first();
      if (!emailResult) {
        return new Response(
          renderTemplate("Email Not Found", "<p>Email not found or access denied.</p>", user, config2),
          { headers: { "Content-Type": "text/html" }, status: 404 }
        );
      }
      const formData = await request.formData();
      const to = formData.get("to") || "";
      const subject = formData.get("subject") || "Re: No Subject";
      const body = formData.get("body") || "";
      if (!to || !body) {
        return new Response(
          renderTemplate("Invalid Input", '<p>Recipient and reply body are required.</p><a href="/inbox/reply/' + emailId + '" class="button">Try Again</a>', user, config2),
          { headers: { "Content-Type": "text/html" }, status: 400 }
        );
      }
      try {
        const replyMetadata = JSON.stringify({
          to,
          from: "deadlight.boo@gmail.com",
          // Or user's email if available
          original_id: emailId,
          date_queued: (/* @__PURE__ */ new Date()).toISOString(),
          sent: false
        });
        const insertQuery = `
            INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata, is_reply_draft)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `;
        await env.DB.prepare(insertQuery).bind(
          subject,
          body,
          `reply-draft-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          // Unique slug
          user.id,
          (/* @__PURE__ */ new Date()).toISOString(),
          (/* @__PURE__ */ new Date()).toISOString(),
          0,
          // Not published
          0,
          // Not an incoming email
          replyMetadata,
          1
          // Flag as reply draft
        ).run();
        const successMessage = `<p>Reply queued for sending to ${escapeHtml(to)}! It will be sent shortly.</p><a href="/email/${emailId}" class="button">Back to Email</a><a href="/inbox" class="button secondary">Back to Inbox</a>`;
        return new Response(
          renderTemplate("Reply Queued", successMessage, user, config2),
          { headers: { "Content-Type": "text/html" } }
        );
      } catch (error) {
        console.error(`Failed to queue reply: ${error.message}`);
        const errorMessage = `<p>Failed to queue reply: ${escapeHtml(error.message)}</p><a href="/inbox/reply/${emailId}" class="button">Try Again</a>`;
        return new Response(
          renderTemplate("Queue Failed", errorMessage, user, config2),
          { headers: { "Content-Type": "text/html" }, status: 500 }
        );
      }
    }, "POST")
  }
};
function renderPagination(pagination2, basePath = "/inbox") {
  if (!pagination2 || pagination2.totalPages <= 1) {
    return "";
  }
  const { currentPage, totalPages, hasPrevious, hasNext, previousPage, nextPage } = pagination2;
  const pageNumbers = [];
  const maxPagesToShow = 5;
  let startPage = Math.max(1, currentPage - Math.floor(maxPagesToShow / 2));
  let endPage = Math.min(totalPages, startPage + maxPagesToShow - 1);
  if (endPage - startPage < maxPagesToShow - 1) {
    startPage = Math.max(1, endPage - maxPagesToShow + 1);
  }
  for (let i = startPage; i <= endPage; i++) {
    pageNumbers.push(i);
  }
  return `
    <nav class="pagination" aria-label="Pagination Navigation">
      ${hasPrevious ? `
        <a href="${basePath}?page=1" class="pagination-link pagination-first" aria-label="First page">\u226A</a>
        <a href="${basePath}?page=${previousPage}" class="pagination-link pagination-prev" aria-label="Previous page">\u2039</a>
      ` : `
        <span class="pagination-link pagination-disabled">\u226A</span>
        <span class="pagination-link pagination-disabled">\u2039</span>
      `}
      
      ${startPage > 1 ? '<span class="pagination-ellipsis">...</span>' : ""}
      
      ${pageNumbers.map(
    (num) => num === currentPage ? `<span class="pagination-link pagination-current" aria-current="page">${num}</span>` : `<a href="${basePath}?page=${num}" class="pagination-link">${num}</a>`
  ).join("")}
      
      ${endPage < totalPages ? '<span class="pagination-ellipsis">...</span>' : ""}
      
      ${hasNext ? `
        <a href="${basePath}?page=${nextPage}" class="pagination-link pagination-next" aria-label="Next page">\u203A</a>
        <a href="${basePath}?page=${totalPages}" class="pagination-link pagination-last" aria-label="Last page">\u226B</a>
      ` : `
        <span class="pagination-link pagination-disabled">\u203A</span>
        <span class="pagination-link pagination-disabled">\u226B</span>
      `}
      
      <div class="pagination-info">Page ${currentPage} of ${totalPages}</div>
    </nav>
  `;
}
__name(renderPagination, "renderPagination");
function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
__name(escapeHtml, "escapeHtml");

// src/routes/user.js
init_checked_fetch();
init_password();
var userRoutes = {
  "/user/:username": {
    GET: /* @__PURE__ */ __name(async (request, env) => {
      try {
        const username = request.params.username.toLowerCase();
        const currentUser = await checkAuth(request, env);
        const { configService: configService2 } = await Promise.resolve().then(() => (init_config2(), config_exports));
        const config2 = await configService2.getConfig(env.DB);
        const user = await env.DB.prepare(`
          SELECT u.*, 
                 COUNT(p.id) as post_count,
                 MAX(p.created_at) as last_post_date
          FROM users u
          LEFT JOIN posts p ON u.id = p.author_id 
            AND p.published = 1 
            AND (p.is_email = 0 OR p.is_email IS NULL)
          WHERE LOWER(u.subdomain) = ? OR LOWER(u.username) = ?
          GROUP BY u.id
        `).bind(username, username).first();
        if (!user) {
          return new Response("User not found", { status: 404 });
        }
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get("page") || "1");
        const postsPerPage = 10;
        const offset = (page - 1) * postsPerPage;
        const posts = await env.DB.prepare(`
          SELECT id, title, slug, content, excerpt, created_at, updated_at, published
          FROM posts 
          WHERE author_id = ? 
            AND published = 1 
            AND (is_email = 0 OR is_email IS NULL)
          ORDER BY created_at DESC
          LIMIT ? OFFSET ?
        `).bind(user.id, postsPerPage, offset).all();
        const totalResult = await env.DB.prepare(`
          SELECT COUNT(*) as total 
          FROM posts 
          WHERE author_id = ? 
            AND published = 1 
            AND (is_email = 0 OR is_email IS NULL)
        `).bind(user.id).first();
        const totalPosts = totalResult.total;
        const totalPages = Math.ceil(totalPosts / postsPerPage);
        const pagination2 = {
          currentPage: page,
          totalPages,
          totalPosts,
          hasNext: page < totalPages,
          hasPrevious: page > 1,
          nextPage: page + 1,
          previousPage: page - 1
        };
        const { renderUserProfile: renderUserProfile2 } = await Promise.resolve().then(() => (init_profile(), profile_exports));
        return new Response(renderUserProfile2(user, posts.results, currentUser, config2, pagination2), {
          headers: { "Content-Type": "text/html" }
        });
      } catch (error) {
        console.error("User profile error:", error);
        return new Response("Internal server error", { status: 500 });
      }
    }, "GET")
  }
};

// src/middleware/error.js
init_checked_fetch();
var errorMiddleware = /* @__PURE__ */ __name(async (request, env, next) => {
  try {
    const response = await next();
    return response;
  } catch (error) {
    console.error("Application error:", {
      message: error.message,
      stack: error.stack,
      url: request.url,
      method: request.method
    });
    const errorMap = {
      "Unauthorized": { status: 401, message: "Unauthorized access" },
      "Not Found": { status: 404, message: "Resource not found" },
      "Invalid request data": { status: 400, message: "Invalid request data" },
      "default": { status: 500, message: "Internal server error" }
    };
    const errorResponse = errorMap[error.message] || errorMap.default;
    const isDevelopment = env.ENVIRONMENT !== "production";
    const responseBody = isDevelopment ? `Error: ${error.message}

Stack: ${error.stack}` : errorResponse.message;
    return new Response(responseBody, {
      status: errorResponse.status,
      headers: { "Content-Type": "text/plain" }
    });
  }
}, "errorMiddleware");

// src/middleware/logging.js
init_checked_fetch();
function getClientIP(request) {
  return request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || request.headers.get("x-forwarded-for") || "unknown";
}
__name(getClientIP, "getClientIP");
var initLogsTable = /* @__PURE__ */ __name(async (db) => {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      path TEXT NOT NULL,
      method TEXT NOT NULL,
      duration INTEGER NOT NULL,
      status_code INTEGER,
      user_agent TEXT,
      ip TEXT,
      referer TEXT,
      country TEXT,
      error TEXT
    )
  `).run();
}, "initLogsTable");
var logRequest = /* @__PURE__ */ __name(async (request, response, env) => {
  try {
    const duration = Date.now() - request.timing.startTime;
    const analytics = request.analytics || {};
    await env.DB.prepare(`
      INSERT INTO request_logs (
        path,
        method,
        duration,
        status_code,
        user_agent,
        ip,
        referer,
        country,
        error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      analytics.path,
      analytics.method,
      duration,
      response?.status || 500,
      analytics.userAgent,
      analytics.ip,
      analytics.referer,
      analytics.country,
      response?.ok ? null : response?.statusText || "Unknown error"
    ).run();
  } catch (error) {
    console.error("Error logging request:", error);
  }
}, "logRequest");
var loggingMiddleware = /* @__PURE__ */ __name(async (request, env, next) => {
  const startTime = Date.now();
  const url = new URL(request.url);
  try {
    await initLogsTable(env.DB);
    const requestData = {
      path: url.pathname,
      method: request.method,
      userAgent: request.headers.get("user-agent"),
      ip: getClientIP(request),
      referer: request.headers.get("referer") || "",
      country: request.headers.get("cf-ipcountry") || "unknown"
    };
    request.analytics = requestData;
    request.timing = { startTime };
    const response = await next();
    const duration = Date.now() - startTime;
    if (response && typeof response.status === "number") {
      await logRequest(request, response, env);
    } else {
      await logRequest(request, { status: 500, ok: false, statusText: "Invalid response" }, env);
      console.warn("Response undefined or invalid, logged with status 500", { path: requestData.path });
    }
    return response;
  } catch (error) {
    console.error("Logging middleware error:", error);
    const fallbackResponse = await next();
    return fallbackResponse || new Response("Internal Server Error", { status: 500 });
  }
}, "loggingMiddleware");

// ../lib.deadlight/core/src/security/middleware.js
init_checked_fetch();

// ../lib.deadlight/core/src/security/headers.js
init_checked_fetch();
function securityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-XSS-Protection", "1; mode=block");
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
  );
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set(
    "Permissions-Policy",
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
  );
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
__name(securityHeaders, "securityHeaders");

// ../lib.deadlight/core/src/security/middleware.js
async function rateLimitMiddleware(request, env, ctx, next) {
  const url = new URL(request.url);
  let limiter = apiLimiter;
  if (url.pathname.startsWith("/login") || url.pathname.startsWith("/register")) {
    limiter = authLimiter;
  }
  const result = await limiter.isAllowed(request, env);
  if (!result.allowed) {
    return new Response("Too Many Requests", {
      status: 429,
      headers: {
        "Retry-After": Math.ceil((result.resetAt - Date.now()) / 1e3),
        "X-RateLimit-Limit": limiter.maxRequests,
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": result.resetAt.toISOString()
      }
    });
  }
  const response = await next();
  response.headers.set("X-RateLimit-Limit", limiter.maxRequests);
  response.headers.set("X-RateLimit-Remaining", result.remaining);
  response.headers.set("X-RateLimit-Reset", result.resetAt.toISOString());
  return response;
}
__name(rateLimitMiddleware, "rateLimitMiddleware");
async function securityHeadersMiddleware(request, env, ctx, next) {
  const response = await next();
  return securityHeaders(response);
}
__name(securityHeadersMiddleware, "securityHeadersMiddleware");

// src/index.js
init_outbox();
var router = new Router();
router.use(errorMiddleware);
router.use(loggingMiddleware);
[
  { name: "blog", routes: blogRoutes },
  { name: "user", routes: userRoutes },
  { name: "style", routes: styleRoutes },
  { name: "static", routes: staticRoutes },
  { name: "auth", routes: authRoutes },
  { name: "admin", routes: adminRoutes },
  { name: "inbox", routes: inboxRoutes }
].forEach(({ name, routes }) => {
  console.log(`Registering ${name} routes:`, Object.keys(routes));
  Object.entries(routes).forEach(([path, handlers]) => {
    router.register(path, handlers);
  });
});
var queueProcessorStarted = false;
async function startQueueProcessor(env, intervalMs = 3e5) {
  if (!env.ENABLE_QUEUE_PROCESSING) {
    console.log("Queue processing disabled");
    return;
  }
  if (queueProcessorStarted) {
    console.log("Queue processor already started");
    return;
  }
  queueProcessorStarted = true;
  const outbox = new OutboxService(env);
  setInterval(async () => {
    try {
      const result = await outbox.processQueue();
      console.log(`Queue processed: ${result.processed} operations, ${result.queued} remaining`);
    } catch (error) {
      console.error("Queue processing error:", error);
    }
  }, intervalMs);
}
__name(startQueueProcessor, "startQueueProcessor");
var src_default = {
  async fetch(request, env, ctx) {
    ctx.waitUntil(startQueueProcessor(env));
    return rateLimitMiddleware(
      request,
      env,
      ctx,
      () => securityHeadersMiddleware(
        request,
        env,
        ctx,
        () => router.handle(request, env, ctx)
      )
    );
  }
};

// ../../.nvm/versions/node/v24.4.1/lib/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
init_checked_fetch();
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../.nvm/versions/node/v24.4.1/lib/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
init_checked_fetch();
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-Q0vcA9/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// ../../.nvm/versions/node/v24.4.1/lib/node_modules/wrangler/templates/middleware/common.ts
init_checked_fetch();
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-Q0vcA9/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
