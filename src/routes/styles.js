// src/routes/styles.js

function lightenDarkenColor(col, amt) {
  let usePound = false;
  if (col[0] === "#") { col = col.slice(1); usePound = true; }
  const num = parseInt(col, 16);
  let r = (num >> 16) + amt;
  let g = ((num >> 8) & 0x00FF) + amt;
  let b = (num & 0x0000FF) + amt;
  r = Math.min(255, Math.max(0, r));
  g = Math.min(255, Math.max(0, g));
  b = Math.min(255, Math.max(0, b));
  return (usePound ? "#" : "") + ((r << 16) | (g << 8) | b).toString(16).padStart(6, '0');
}

const CACHE_HEADERS = { 'Content-Type': 'text/css', 'Cache-Control': 'public, max-age=3600' };

// =============================
// 1. BASE STYLES (shared)
// =============================
const baseStyles = `
  :root {
    --font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --max-width: 900px;
    --border-radius: 6px;
    --transition: all 0.2s ease;
  }

  *, *::before, *::after { box-sizing: border-box; }
  body { margin: 0; padding: 20px; font-family: var(--font-family); background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; }
  a { color: var(--link-color); text-decoration: none; transition: var(--transition); }
  a:hover { color: var(--link-hover); text-decoration: underline; }

  .container { max-width: var(--max-width); margin: 0 auto; padding: 0 20px; }
  header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 1rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border-color); }
  header h1 { margin: 0; font-size: 1.8rem; }
  header h1 a { color: inherit; text-decoration: none; }

  nav { display: flex; gap: 1rem; align-items: center; }
  nav a { padding: 0.5rem 1rem; border-radius: var(--border-radius); color: var(--link-color); }
  nav a:hover { background: var(--nav-hover-bg); color: var(--nav-hover-color); }

  h1, h2, h3, h4, h5, h6 { margin-top: 0; color: var(--text-primary); }

  /* ===== FIXED BUTTONS — THIS IS THE REAL FIX ===== */
  button, .button, .edit-button, .delete-button, .delete-link button, [type="submit"] {
    padding: 0.45rem 0.9rem !important;
    border-radius: var(--border-radius) !important;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    border: none;
    font-family: inherit;
    transition: var(--transition);
  }

  .edit-button, .button { background: var(--button-secondary-bg); color: var(--button-secondary-text); }
  .edit-button:hover, .button:hover { background: var(--button-secondary-hover); }

  .delete-button, .delete-link button {
    background: var(--button-danger-bg) !important;
    color: var(--button-danger-text) !important;
    border: 1px solid var(--button-danger-text) !important;
  }
  .delete-button:hover, .delete-link button:hover { background: var(--button-danger-hover); }

  /* Forms */
  input, textarea, select {
    width: 100%; padding: 10px; margin: 8px 0; background: var(--input-bg); border: 1px solid var(--input-border);
    border-radius: var(--border-radius); color: var(--text-primary); font-family: inherit;
  }

  /* Posts */
  article, .post-preview { padding-bottom: 2rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border-color); }
  article:last-child, .post-preview:last-child { border-bottom: none; }
  .post-actions { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
`;


// =============================
// 2. ADMIN DASHBOARD STYLES (preserved exactly)
// =============================
const adminStyles = `
  /* =============================
    ADMIN DASHBOARD + ANALYTICS 
    ============================= */

  /* Stats Grid (Admin Dashboard) */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1.5rem;
    margin: 2rem 0;
  }

  .stat-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 1.5rem;
    text-align: center;
  }

  .stat-card h3 {
    margin: 0 0 0.5rem;
    font-size: 0.9rem;
    text-transform: uppercase;
    color: var(--text-secondary);
    letter-spacing: 0.5px;
  }

  .stat-number {
    font-size: 2.4rem;
    font-weight: bold;
    color: var(--text-primary);
    margin: 0.5rem 0;
  }

  .stat-link {
    font-size: 0.9rem;
    color: var(--link-color);
  }

  /* Active Visitors Pulse */
  .active-visitors {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.95rem;
    color: #4ade80;
  }

  .pulse {
    width: 10px;
    height: 10px;
    background: #4ade80;
    border-radius: 50%;
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); }
    70% { box-shadow: 0 0 0 10px rgba(74, 222, 128, 0); }
    100% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0); }
  }

  /* Quick Actions */
  .quick-actions h2 { margin: 2.5rem 0 1rem; font-size: 1.4rem; }
  .action-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin: 1rem 0;
  }

  .action-buttons .button {
    padding: 0.7rem 1.3rem;
    background: var(--button-secondary-bg);
    color: #fff;
    border-radius: var(--border-radius);
    font-size: 0.95rem;
    font-weight: 500;
  }

  /* SIMPLE CHART — FINAL VERSION (used on BOTH pages) */
  .simple-chart {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    height: 180px;
    padding: 20px 10px 30px;
    gap: 6px;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    overflow: hidden;
  }

  .simple-chart .chart-bar {
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    position: relative;
    min-width: 28px;
  }

  .simple-chart .bar {
    width: 100%;
    height: var(--height, 0%);
    min-height: 4px;
    background: #e91e63;
    border-radius: 4px 4px 0 0;
    transition: all 0.4s ease;
    box-shadow: 0 2px 6px rgba(233, 30, 99, 0.3);
  }

  .simple-chart .chart-bar:hover .bar {
    background: #ff4081;
    transform: scaleY(1.05);
    box-shadow: 0 4px 12px rgba(255, 64, 129, 0.4);
  }

  .simple-chart .value {
    position: absolute;
    top: -26px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.8rem;
    font-weight: bold;
    color: var(--text-primary);
    opacity: 0.9;
  }

  .simple-chart .label {
    position: absolute;
    bottom: -26px;
    left: 50%;
    transform: translateX(-50%) rotate(-45deg);
    font-size: 0.75rem;
    color: var(--text-secondary);
    white-space: nowrap;
    origin: center;
  }

  /* Chart Section Wrapper */
  .chart-section {
    margin: 3rem 0;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 2rem;
  }

  .chart-section h2 {
    margin: 0 0 1.5rem;
    font-size: 1.4rem;
    color: var(--text-primary);
  }

  /* Recent Posts Table */
  .recent-posts-section h2 { margin: 3rem 0 1rem; font-size: 1.4rem; }

  .data-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
    font-size: 0.95rem;
  }

  .data-table th {
    text-align: left;
    padding: 0.8rem 0.6rem;
    background: var(--card-bg);
    color: var(--text-secondary);
    font-weight: 500;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border-color);
  }

  .data-table td {
    padding: 0.9rem 0.6rem;
    border-bottom: 1px solid var(--border-color);
  }

  .data-table tr:hover {
    background: rgba(255,255,255,0.03);
  }

  .action-cell {
    white-space: nowrap;
  }

  .action-cell .button {
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    margin-right: 0.4rem;
  }

  .badge {
    background: #4ade80;
    color: #000;
    padding: 0.2rem 0.6rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: bold;
  }

  /* =============================
   ANALYTICS SUMMARY CARDS
   ============================= */
  .analytics-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.5rem;
    margin: 2rem 0;
  }

  .analytics-summary .metric {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 1.8rem 1.2rem;
    text-align: center;
    transition: transform 0.2s ease;
  }

  .analytics-summary .metric:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 20px rgba(0,0,0,0.2);
  }

  .analytics-summary .metric-value {
    font-size: 2.6rem;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0.4rem 0;
    line-height: 1;
  }

  .analytics-summary .metric-label {
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
    font-weight: 500;
  }

  /* Optional: make error rate red when >5% */
  .analytics-summary .metric-value:has(+ .metric-label:contains("Error")) {
    color: #ff6b6b;
  }

  /* =============================
   AUTH PAGES — LOGIN + REGISTER 
   ============================= */
  .auth-container {
    max-width: 440px;
    margin: 4rem auto;
    padding: 2.8rem;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    box-shadow: 0 12px 40px rgba(0,0,0,0.25);
  }

  .auth-container h1 {
    text-align: center;
    margin: 0 0 2rem;
    font-size: 1.8rem;
    color: var(--text-primary);
  }

  /* Form layout */
  .auth-container form {
    display: flex;
    flex-direction: column;
    gap: 1.4rem;
  }

  /* Labels & inputs */
  .auth-container label {
    display: block;
    margin-bottom: 0.4rem;
    font-weight: 500;
    color: var(--text-primary);
    font-size: 0.95rem;
  }

  .auth-container input[type="text"],
  .auth-container input[type="email"],
  .auth-container input[type="password"],
  .auth-container input[type="number"] {
    width: 100%;
    padding: 0.9rem 1rem;
    background: var(--input-bg);
    border: 1px solid var(--input-border);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 1rem;
    font-family: inherit;
    transition: all 0.2s ease;
  }

  .auth-container input:focus {
    outline: none;
    border-color: var(--link-color);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--link-color) 20%, transparent);
  }

  /* Small helper text */
  .auth-container small {
    display: block;
    margin-top: 0.4rem;
    font-size: 0.8rem;
    color: var(--text-secondary);
    opacity: 0.9;
  }

  /* Submit button */
  .auth-container button,
  .auth-container .button {
    margin-top: 0.8rem;
    padding: 0.95rem 1.6rem;
    background: var(--button-secondary-bg);
    color: white;
    font-weight: 600;
    font-size: 1.05rem;
    border: none;
    border-radius: var(--border-radius);
    cursor: pointer;
    transition: var(--transition);
  }

  .auth-container button:hover,
  .auth-container .button:hover {
    background: var(--button-secondary-hover);
    transform: translateY(-2px);
  }

  /* Error messages */
  .auth-container .error-message {
    background: #440000;
    color: #ff6b6b;
    padding: 1rem 1.2rem;
    border-radius: var(--border-radius);
    border: 1px solid #880000;
    margin-bottom: 1.5rem;
    font-size: 0.95rem;
    line-height: 1.4;
  }

  /* Bottom links */
  .auth-links {
    text-align: center;
    margin-top: 1.8rem;
    font-size: 0.95rem;
    color: var(--text-secondary);
  }

  .auth-links a {
    color: var(--link-color);
    font-weight: 500;
  }
  .auth-links a:hover {
    text-decoration: underline;
  }
  /* =============================
    STURDY HEADER — Mobile + Desktop (FINAL FOREVER VERSION)
    ============================= */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1.4rem 0;
    margin-bottom: 2rem;
    border-bottom: 1px solid var(--border-color);
    flex-wrap: wrap;
    gap: 1rem;
  }

  header h1 {
    margin: 0;
    font-size: clamp(1.8rem, 5vw, 2.6rem);
    font-weight: 900;
    letter-spacing: -1.5px;
  }

  header h1 a {
    text-decoration: none;
    background: linear-gradient(90deg, #ff4081, #8ba3c7, #ff4081);
    background-size: 200%;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: gradient 10s ease infinite;
  }

  @keyframes gradient {
    0%, 100% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
  }

  /* Nav — always horizontal, always centered on mobile */
  nav {
    display: flex;
    flex-wrap: wrap;
    gap: clamp(0.8rem, 2vw, 1.5rem);
    font-size: clamp(0.9rem, 2.5vw, 1rem);
    align-items: center;
  }

  nav a {
    padding: 0.45rem 0.75rem;
    border-radius: 6px;
    transition: all 0.2s ease;
    white-space: nowrap;
  }

  nav a:hover {
    background: rgba(255,255,255,0.08);
  }

  /* Theme toggle button stays on the far right */
  #theme-toggle {
    margin-left: auto;
    padding: 0.5rem 0.8rem;
    background: rgba(255,255,255,0.1);
    border-radius: 8px;
    cursor: pointer;
    font-size: 1.3rem;
  }

  /* Mobile: everything just scales down gracefully */
  @media (max-width: 640px) {
    header {
      padding: 1rem 0;
      flex-direction: column;
      text-align: center;
    }
    
    header h1 {
      margin-bottom: 0.5rem;
    }
    
    nav {
      justify-content: center;
      width: 100%;
    }
    
    #theme-toggle {
      margin-left: 0;
      margin-top: 0.5rem;
    }
  }

  /* Tablet & up: back to side-by-side */
  @media (min-width: 641px) {
    header {
      flex-direction: row;
      text-align: left;
    }
    
    nav {
      width: auto;
    }
  }
`;

// =============================
// 3. THEMES
// =============================
const themes = {
  dark: `
    :root[data-theme="dark"] {
      --bg-primary: #000; --bg-secondary: #222;
      --text-primary: #fff; --text-secondary: #888;
      --border-color: #444; --border-hover: #666;
      --link-color: #8ba3c7; --link-hover: #adc3e7;
      --nav-hover-bg: #333; --nav-hover-color: #fff;

      --button-secondary-bg: #444; --button-secondary-text: #fff; --button-secondary-hover: #666;
      --button-danger-bg: #440000; --button-danger-text: #ff6b6b; --button-danger-hover: #660000;

      --input-bg: #121212; --input-border: #333;
      --card-bg: #1a1a1a; --card-border: #333;
      --code-bg: #1a1a1a;
    }
  `,
  light: `
    :root[data-theme="light"] {
      --bg-primary: #fff; --bg-secondary: #f5f5f5;
      --text-primary: #333; --text-secondary: #666;
      --border-color: #ddd; --border-hover: #999;
      --link-color: #0066cc; --link-hover: #0052a3;
      --nav-hover-bg: #f0f0f0; --nav-hover-color: #333;

      --button-secondary-bg: #666; --button-secondary-text: #fff; --button-secondary-hover: #888;
      --button-danger-bg: #f5f5f5; --button-danger-text: #dc3545; --button-danger-hover: #e8e8e8;

      --input-bg: #fff; --input-border: #ccc;
      --card-bg: #f5f5f5; --card-border: #ddd;
      --code-bg: #f4f4f4;
    }
  `
};

// =============================
// 4. DYNAMIC ACCENT
// =============================
function applyAccent(css, accent) {
  if (!accent) return css;
  const hover = lightenDarkenColor(accent, css.includes('dark') ? 40 : -40);
  return css
    .replace(/--link-color:[^;]+;/g, `--link-color: ${accent};`)
    .replace(/--link-hover:[^;]+;/g, `--link-hover: ${hover};`);
}

// =============================
// 5. ROUTES
// =============================
export const styleRoutes = {
  '/styles/theme.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#8ba3c7';
      const css = baseStyles + adminStyles + themes.dark;
      return new Response(applyAccent(css, accent), { headers: CACHE_HEADERS });
    }
  },
  '/styles/dark_min.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#8ba3c7';
      const css = baseStyles + adminStyles + themes.dark;
      return new Response(applyAccent(css, accent), { headers: CACHE_HEADERS });
    }
  },
  '/styles/light_min.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#0066cc';
      const css = baseStyles + adminStyles + themes.light;
      return new Response(applyAccent(css, accent), { headers: CACHE_HEADERS });
    }
  }
};