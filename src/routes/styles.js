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

// Convert hex to HSL
function hexToHSL(hex) {
  let r = 0, g = 0, b = 0;
  if (hex.length === 4) {
    r = parseInt(hex[1] + hex[1], 16);
    g = parseInt(hex[2] + hex[2], 16);
    b = parseInt(hex[3] + hex[3], 16);
  } else if (hex.length === 7) {
    r = parseInt(hex[1] + hex[2], 16);
    g = parseInt(hex[3] + hex[4], 16);
    b = parseInt(hex[5] + hex[6], 16);
  }
  
  r /= 255; g /= 255; b /= 255;
  
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  let h, s, l = (max + min) / 2;
  
  if (max === min) {
    h = s = 0;
  } else {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r: h = ((g - b) / d + (g < b ? 6 : 0)) / 6; break;
      case g: h = ((b - r) / d + 2) / 6; break;
      case b: h = ((r - g) / d + 4) / 6; break;
    }
  }
  
  return { h: h * 360, s: s * 100, l: l * 100 };
}

// Convert HSL back to hex
function hslToHex(h, s, l) {
  s /= 100;
  l /= 100;
  
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;
  let r = 0, g = 0, b = 0;
  
  if (0 <= h && h < 60) { r = c; g = x; b = 0; }
  else if (60 <= h && h < 120) { r = x; g = c; b = 0; }
  else if (120 <= h && h < 180) { r = 0; g = c; b = x; }
  else if (180 <= h && h < 240) { r = 0; g = x; b = c; }
  else if (240 <= h && h < 300) { r = x; g = 0; b = c; }
  else if (300 <= h && h < 360) { r = c; g = 0; b = x; }
  
  r = Math.round((r + m) * 255);
  g = Math.round((g + m) * 255);
  b = Math.round((b + m) * 255);
  
  return "#" + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
}

// Generate a color palette from a single accent color
function generateColorPalette(accent) {
  const hsl = hexToHSL(accent);
  
  // Create complementary colors using color theory
  const colors = {
    primary: accent,
    // Analogous color (30 degrees on color wheel)
    analogous: hslToHex((hsl.h + 30) % 360, hsl.s, hsl.l),
    // Triadic color (120 degrees on color wheel)
    triadic: hslToHex((hsl.h + 120) % 360, hsl.s, hsl.l),
    // Complementary color (180 degrees on color wheel)
    complementary: hslToHex((hsl.h + 180) % 360, hsl.s, hsl.l),
    // Lighter variation
    lighter: hslToHex(hsl.h, hsl.s, Math.min(hsl.l + 20, 90)),
    // Darker variation
    darker: hslToHex(hsl.h, hsl.s, Math.max(hsl.l - 20, 20))
  };
  
  return colors;
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

  /* ===== BUTTON SYSTEM ===== */
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

  /* Primary buttons (submit, post, save) */
  [type="submit"], .button-primary {
    background: var(--button-primary-bg);
    color: var(--button-primary-text);
    border: 1px solid transparent;
  }

  [type="submit"]:hover, .button-primary:hover {
    background: var(--button-primary-hover);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px var(--button-primary-shadow);
  }

  /* Secondary buttons (edit, cancel, etc.) */
  .edit-button, .button {
    background: var(--button-secondary-bg);
    color: var(--button-secondary-text);
    border: 1px solid var(--button-secondary-border);
  }

  .edit-button:hover, .button:hover {
    background: var(--button-secondary-hover);
    border-color: var(--button-secondary-border-hover);
    transform: translateY(-1px);
  }

  /* Danger buttons (delete) */
  .delete-button, .delete-link button {
    background: var(--button-danger-bg) !important;
    color: var(--button-danger-text) !important;
    border: 1px solid var(--button-danger-border) !important;
  }

  .delete-button:hover, .delete-link button:hover {
    background: var(--button-danger-hover) !important;
    border-color: var(--button-danger-border-hover) !important;
    transform: translateY(-1px);
  }

  /* Forms */
  input, textarea, select {
    width: 100%; padding: 10px; margin: 8px 0; background: var(--input-bg); border: 1px solid var(--input-border);
    border-radius: var(--border-radius); color: var(--text-primary); font-family: inherit;
  }

  /* Posts */
  article, .post-preview { padding-bottom: 2rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border-color); }
  article:last-child, .post-preview:last-child { border-bottom: none; }
  .post-actions { display: flex; gap: 0.5rem; margin-top: 0.5rem; }

  /* =============================
   COMMENTS SYSTEM
   ============================= */

  .comments-section {
    margin-top: 3rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border-color);
  }

  .comment {
    padding: 1rem;
    margin-bottom: 1rem;
    background: var(--bg-secondary);
    border-left: 2px solid var(--border-color);
    border-radius: var(--border-radius);
  }

  /* Thread indentation (0–6 levels supported) */
  .comment[data-level="1"] { margin-left: 20px; }
  .comment[data-level="2"] { margin-left: 40px; }
  .comment[data-level="3"] { margin-left: 60px; }
  .comment[data-level="4"] { margin-left: 80px; }
  .comment[data-level="5"] { margin-left: 100px; }
  .comment[data-level="6"] { margin-left: 120px; }

  .comment-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 0.9rem;
    margin-bottom: 0.5rem;
  }

  .comment-author {
    font-weight: 600;
  }

  .comment-author a {
    color: var(--text-primary);
  }

  .comment-date {
    color: var(--text-secondary);
  }

  .comment-content p {
    margin: 0.5rem 0;
    line-height: 1.6;
  }

  .comment-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }

  /* Empty state */
  .no-comments {
    text-align: center;
    font-style: italic;
    color: var(--text-secondary);
    padding: 2rem 0;
  }

  /* Empty state */
  .no-comments {
    text-align: center;
    font-style: italic;
    color: var(--text-secondary);
    padding: 2rem 0;
  }

  /* =============================
   COMMENT FORMS (Admin & Public)
   ============================= */
  
  /* Form groups - shared styling */
  .form-group {
    margin-bottom: 1.5rem;
  }
  
  .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
    color: var(--text-primary);
  }
  
  .form-group textarea {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    font-family: inherit;
    font-size: 1rem;
    resize: vertical;
    background: var(--input-bg);
    color: var(--text-primary);
    min-height: 100px;
  }

  .form-group input {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    font-family: inherit;
    font-size: 1rem;
    background: var(--input-bg);
    color: var(--text-primary);
  }
  
  .char-count {
    display: block;
    margin-top: 0.25rem;
    color: var(--text-secondary);
    font-size: 0.85rem;
  }
  
  .form-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 1rem;
  }
  
  .button.primary {
    background: var(--button-primary-bg);
    color: var(--button-primary-text);
    border: 1px solid transparent;
  }

  .button.primary:hover {
    background: var(--button-primary-hover);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px var(--button-primary-shadow);
  }
  
  .button.secondary {
    background: var(--button-secondary-bg);
    color: var(--button-secondary-text);
    border: 1px solid var(--button-secondary-border);
  }

  .button.secondary:hover {
    background: var(--button-secondary-hover);
    border-color: var(--button-secondary-border-hover);
  }

  .button.small {
    padding: 0.25rem 0.75rem !important;
    font-size: 0.85rem;
  }

  .button.delete {
    background: var(--button-danger-bg) !important;
    color: var(--button-danger-text) !important;
    border: 1px solid var(--button-danger-border) !important;
  }

  .button.delete:hover {
    background: var(--button-danger-hover) !important;
    border-color: var(--button-danger-border-hover) !important;
  }
  
  /* Parent comment preview (reply forms) */
  .parent-comment {
    margin: 1.5rem 0;
    padding: 1rem;
    background: var(--bg-secondary);
    border-left: 3px solid var(--link-color);
    border-radius: var(--border-radius);
  }
  
  .parent-label {
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: var(--text-secondary);
  }
  
  .parent-comment blockquote {
    margin: 0.5rem 0;
    padding: 0;
    border: none;
    font-style: italic;
    color: var(--text-primary);
  }
  
  /* Info messages */
  .info-message {
    color: var(--text-secondary);
    font-size: 0.9rem;
    margin-bottom: 1rem;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border-radius: var(--border-radius);
  }
  
  /* Status messages */
  .status-message {
    margin-top: 1rem;
    padding: 1rem;
    border-radius: var(--border-radius);
    display: none;
  }
  
  .status-message.success {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
    display: block;
  }
  
  .status-message.error {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
    display: block;
  }

  /* Public comment form container */
  .public-comment-form {
    margin: 2rem 0;
    padding: 1.5rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border-color);
  }
  
  .public-comment-form h3 {
    margin-top: 0;
    color: var(--text-primary);
  }

  /* Comment CTA */
  .comment-cta {
    margin-top: 1.5rem;
    text-align: center;
  }

  /* Badges */
  .badge.pending {
    background: #fff3cd;
    color: #856404;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-left: 0.5rem;
  }

  /* =============================
   KARMA/VOTING STYLES
   ============================= */
  
  /* Sort controls */
  .sort-controls {
    margin: 2rem 0;
    padding: 1rem 0;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .sort-controls label {
    color: var(--text-secondary);
    font-size: 0.9rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .sort-controls select {
    padding: 0.5rem 0.8rem;
    background: var(--input-bg);
    border: 1px solid var(--input-border);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 0.9rem;
    cursor: pointer;
    min-width: 120px;
  }

  /* For single post view - minimal voting */
  .post-voting-single {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    margin: 1.5rem 0;
    padding: 0;  /* Remove padding */
    background: transparent;  /* No background */
    border: none;  /* No border */
  }

  .post-voting-single form {
    margin: 0;
    display: inline-block;
  }

  .post-voting-single .vote-button {
    background: transparent;
    border: none;  /* No border for cleaner look */
    color: var(--text-secondary);
    padding: 4px 8px !important;  /* Minimal padding */
    border-radius: 4px;
    cursor: pointer;
    font-size: 1.4rem;  /* Slightly larger for single view */
    line-height: 1;
    transition: all 0.2s ease;
    opacity: 0.6;  /* Subtle when not hovered */
  }

  .post-voting-single .vote-button:hover {
    opacity: 1;
    transform: scale(1.2);  /* Subtle grow effect */
  }

  /* Upvote specific - green on hover */
  .post-voting-single .vote-button.upvote:hover {
    color: #4ade80;
    background: rgba(74, 222, 128, 0.1);
  }

  /* Downvote specific - red on hover */
  .post-voting-single .vote-button.downvote:hover {
    color: #ff6b6b;
    background: rgba(255, 107, 107, 0.1);
  }

  /* Karma score in single view */
  .post-voting-single .karma-score {
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--text-primary);
    min-width: 30px;
    text-align: center;
  }

  /* Remove border from list view karma button too for consistency */
  .karma-button {
    background: transparent;
    border: none;  /* Remove border */
    color: var(--text-secondary);
    padding: 2px 6px !important;
    margin: 0;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1.1rem;
    line-height: 1;
    transition: all 0.2s ease;
    vertical-align: middle;
    opacity: 0.6;
  }

  .karma-button:hover {
    opacity: 1;
    color: #4ade80;
    transform: scale(1.1);
  }

  .vote-button {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    padding: 6px 10px !important;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1.2rem;
    line-height: 1;
    transition: all 0.2s ease;
  }

  .vote-button:hover {
    border-color: var(--link-color);
    color: var(--link-color);
    background: rgba(139, 163, 199, 0.1);
  }

  /* Upvote specific */
  .vote-button[value="like"]:hover,
  .karma-button:hover {
    background: #4ade80;
    border-color: #4ade80;
    color: #000;
  }

  /* Downvote specific */
  .vote-button[value="dislike"]:hover {
    background: #ff6b6b;
    border-color: #ff6b6b;
    color: #fff;
  }

  /* Active/voted state (for future enhancement) */
  .karma-button.voted,
  .vote-button.voted {
    background: var(--link-color);
    color: white;
    border-color: var(--link-color);
  }

`;


// =============================
// 2. ADMIN DASHBOARD STYLES 
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
    border-radius: var(--border-radius);
    font-size: 0.95rem;
    font-weight: 500;
  }

  /* SIMPLE CHART STYLES */
  .simple-chart {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    height: 240px;
    padding: 20px 10px 40px;
    gap: 6px;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    overflow: hidden;
    position: relative;
  }

  .simple-chart .chart-bar {
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    align-items: stretch;  /* NEW: ensures bar fills width */
    position: relative;
    min-width: 28px;
    max-width: 80px;
    height: 100%;  /* NEW: bar container takes full height */
  }

  .simple-chart .bar {
    width: 100%;
    height: var(--height, 5%);  /* Changed from 0% to 5% minimum */
    min-height: 8px;  /* Increased from 4px for better visibility */
    background: var(--link-color);
    border-radius: 4px 4px 0 0;
    transition: all 0.4s ease;
    box-shadow: 0 2px 6px var(--button-primary-shadow);
    flex-shrink: 0;  /* NEW: prevents flex from shrinking the bar */
  }

  .simple-chart .chart-bar:hover .bar {
    background: var(--link-hover);
    transform: scaleY(1.05);
    box-shadow: 0 4px 12px var(--button-primary-shadow);
  }

  .simple-chart .value {
    position: absolute;
    top: -26px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text-primary);
    opacity: 1;
    white-space: nowrap;
    pointer-events: none;  /* NEW: prevents hover interference */
  }

  .simple-chart .label {
    position: absolute;
    bottom: -32px;
    left: 50%;
    transform: translateX(-50%) rotate(-45deg);
    transform-origin: center;
    font-size: 0.75rem;
    color: var(--text-secondary);
    white-space: nowrap;
    pointer-events: none;  /* NEW: prevents hover interference */
  }

  /* Responsive chart sizing */
  @media (max-width: 768px) {
    .simple-chart {
      height: 200px;
      padding: 15px 8px 50px;
    }
    
    .simple-chart .label {
      font-size: 0.7rem;
      bottom: -36px;
    }
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
   AUTH PROMPT PAGE (Vote/Action Prompt)
   ============================= */
  .auth-prompt-container {
    max-width: 600px;
    margin: 4rem auto;
    padding: 3rem;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    box-shadow: 0 12px 40px rgba(0,0,0,0.25);
    text-align: center;
  }

  .auth-prompt-container h1 {
    margin: 0 0 1rem;
    font-size: 2rem;
    color: var(--text-primary);
    font-weight: 700;
  }

  .auth-prompt-container > p {
    margin: 0 0 2.5rem;
    font-size: 1.1rem;
    color: var(--text-secondary);
  }

  /* Auth options layout */
  .auth-options {
    display: flex;
    gap: 2rem;
    align-items: stretch;
    justify-content: center;
    margin: 2rem 0;
  }

  .auth-option {
    flex: 1;
    padding: 2rem 1.5rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    min-width: 200px;
  }

  .auth-option h3 {
    margin: 0 0 1.2rem;
    font-size: 1rem;
    color: var(--text-secondary);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .auth-option .button {
    display: inline-block;
    width: 100%;
    max-width: 180px;
    padding: 0.8rem 1.5rem !important;
    font-size: 1rem;
    font-weight: 600;
    text-align: center;
    text-decoration: none;
    transition: all 0.2s ease;
  }

  .auth-option .button.primary {
    background: var(--link-color);
    color: white;
  }

  .auth-option .button.primary:hover {
    background: var(--link-hover);
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(139, 163, 199, 0.3);
  }

  .auth-option .button:not(.primary) {
    background: var(--button-secondary-bg);
    color: white;
  }

  .auth-option .button:not(.primary):hover {
    background: var(--button-secondary-hover);
    transform: translateY(-2px);
  }

  /* Divider */
  .auth-divider {
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
  }

  .auth-divider span {
    padding: 0.5rem;
    background: var(--card-bg);
    color: var(--text-secondary);
    font-style: italic;
    font-size: 0.9rem;
    z-index: 1;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .auth-divider::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 1px;
    height: 100px;
    background: var(--border-color);
  }

  /* Hint text */
  .auth-hint {
    margin-top: 0.8rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
    opacity: 0.8;
  }

  /* Cancel/back link */
  .auth-cancel {
    margin-top: 2.5rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border-color);
  }

  .link-subtle {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 0.95rem;
    transition: all 0.2s ease;
  }

  .link-subtle:hover {
    color: var(--text-primary);
    text-decoration: underline;
  }

  /* Mobile responsive */
  @media (max-width: 640px) {
    .auth-prompt-container {
      margin: 2rem auto;
      padding: 2rem 1.5rem;
    }

    .auth-options {
      flex-direction: column;
      gap: 1.5rem;
    }

    .auth-option {
      padding: 1.5rem;
    }
    
    .auth-divider {
      width: 100%;
      margin: 1rem 0;
    }

    .auth-divider::before {
      width: 100px;
      height: 1px;
    }

    .auth-divider span {
      padding: 0.5rem 1rem;
    }
  }

  /* =============================
    STURDY HEADER — Mobile + Desktop
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
      --bg-primary: #000;
      --bg-secondary: #222;
      --text-primary: #fff;
      --text-secondary: #888;
      --border-color: #444;
      --border-hover: #666;
      --link-color: #8ba3c7;
      --link-hover: #adc3e7;
      --nav-hover-bg: #333;
      --nav-hover-color: #fff;

      /* Primary buttons - use accent color */
      --button-primary-bg: var(--link-color);
      --button-primary-text: #fff;
      --button-primary-hover: var(--link-hover);
      --button-primary-shadow: rgba(139, 163, 199, 0.3);

      /* Secondary buttons - use analogous color or muted accent */
      --button-secondary-bg: rgba(139, 163, 199, 0.15);
      --button-secondary-text: var(--link-color);
      --button-secondary-border: rgba(139, 163, 199, 0.3);
      --button-secondary-hover: rgba(139, 163, 199, 0.25);
      --button-secondary-border-hover: var(--link-color);

      /* Danger buttons */
      --button-danger-bg: #440000;
      --button-danger-text: #ff6b6b;
      --button-danger-border: #880000;
      --button-danger-hover: #660000;
      --button-danger-border-hover: #ff6b6b;

      --input-bg: #121212;
      --input-border: #333;
      --card-bg: #1a1a1a;
      --card-border: #333;
      --code-bg: #1a1a1a;
    }
  `,
  
  light: `
    :root[data-theme="light"] {
      --bg-primary: #fff;
      --bg-secondary: #f5f5f5;
      --text-primary: #333;
      --text-secondary: #666;
      --border-color: #ddd;
      --border-hover: #999;
      --link-color: #0066cc;
      --link-hover: #0052a3;
      --nav-hover-bg: #f0f0f0;
      --nav-hover-color: #333;

      /* Primary buttons - use accent color */
      --button-primary-bg: var(--link-color);
      --button-primary-text: #fff;
      --button-primary-hover: var(--link-hover);
      --button-primary-shadow: rgba(0, 102, 204, 0.3);

      /* Secondary buttons - lighter treatment in light mode */
      --button-secondary-bg: rgba(0, 102, 204, 0.08);
      --button-secondary-text: var(--link-color);
      --button-secondary-border: rgba(0, 102, 204, 0.2);
      --button-secondary-hover: rgba(0, 102, 204, 0.15);
      --button-secondary-border-hover: var(--link-color);

      /* Danger buttons */
      --button-danger-bg: #fff5f5;
      --button-danger-text: #dc3545;
      --button-danger-border: #dc3545;
      --button-danger-hover: #ffe5e7;
      --button-danger-border-hover: #c82333;

      --input-bg: #fff;
      --input-border: #ccc;
      --card-bg: #f5f5f5;
      --card-border: #ddd;
      --code-bg: #f4f4f4;
    }
  `
};

// =============================
// 4. DYNAMIC ACCENT
// =============================
function applyAccent(css, accent) {
  if (!accent) return css;
  
  const palette = generateColorPalette(accent);
  const isDark = css.includes('data-theme="dark"');
  const hover = lightenDarkenColor(accent, isDark ? 40 : -40);
  
  // Create shadow color with transparency
  const shadowColor = accent.replace('#', '');
  const r = parseInt(shadowColor.substring(0, 2), 16);
  const g = parseInt(shadowColor.substring(2, 4), 16);
  const b = parseInt(shadowColor.substring(4, 6), 16);
  const shadow = `rgba(${r}, ${g}, ${b}, 0.3)`;
  
  return css
    .replace(/--link-color:[^;]+;/g, `--link-color: ${accent};`)
    .replace(/--link-hover:[^;]+;/g, `--link-hover: ${hover};`)
    // Apply to primary buttons
    .replace(/--button-primary-bg:[^;]+;/g, `--button-primary-bg: ${accent};`)
    .replace(/--button-primary-hover:[^;]+;/g, `--button-primary-hover: ${hover};`)
    .replace(/--button-primary-shadow:[^;]+;/g, `--button-primary-shadow: ${shadow};`)
    // Apply to secondary buttons (lighter/desaturated)
    .replace(/--button-secondary-text:[^;]+;/g, `--button-secondary-text: ${accent};`)
    .replace(/--button-secondary-border-hover:[^;]+;/g, `--button-secondary-border-hover: ${accent};`);
}

// =============================
// 5. ROUTES
// =============================
export const styleRoutes = {
  '/styles/theme.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#8ba3c7';
      const palette = generateColorPalette(accent);
      
      // Create the dynamic gradient
      // const gradient = `linear-gradient(135deg, ${palette.primary}, ${palette.analogous}, ${palette.primary}, ${palette.analogous}, ${palette.primary})`;
      // const gradient = `linear-gradient(135deg, ${palette.primary}, ${palette.triadic}, ${palette.complementary}, ${palette.triadic}, ${palette.primary})`;
      // const gradient = `linear-gradient(135deg, ${palette.darker}, ${palette.complementary}, ${palette.primary}, ${palette.complementary}, ${palette.lighter})`;
      const gradient = `linear-gradient(135deg, ${palette.darker}, ${palette.primary}, ${palette.lighter}, ${palette.primary}, ${palette.darker})`;

      // Replace the hardcoded gradient in adminStyles BEFORE concatenating
      const dynamicAdminStyles = adminStyles.replace(
        'background: linear-gradient(90deg, #ff4081, #8ba3c7, #ff4081);',
        `background: ${gradient};`
      );
      
      // Concatenate with the modified adminStyles
      const css = baseStyles + dynamicAdminStyles + themes.dark;
      
      // Apply the other accent colors (links, etc)
      return new Response(applyAccent(css, accent), { headers: CACHE_HEADERS });
    }
  },
  
  '/styles/dark_min.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#8ba3c7';
      const palette = generateColorPalette(accent);
      
      // const gradient = `linear-gradient(135deg, ${palette.primary}, ${palette.analogous}, ${palette.primary}, ${palette.analogous}, ${palette.primary})`;
      // const gradient = `linear-gradient(135deg, ${palette.primary}, ${palette.triadic}, ${palette.complementary}, ${palette.triadic}, ${palette.primary})`;
      // const gradient = `linear-gradient(135deg, ${palette.darker}, ${palette.complementary}, ${palette.primary}, ${palette.complementary}, ${palette.lighter})`;
      const gradient = `linear-gradient(135deg, ${palette.darker}, ${palette.primary}, ${palette.complementary}, ${palette.triadic}, ${palette.darker})`;

      const dynamicAdminStyles = adminStyles.replace(
        'background: linear-gradient(90deg, #ff4081, #8ba3c7, #ff4081);',
        `background: ${gradient};`
      );
      
      const css = baseStyles + dynamicAdminStyles + themes.dark;
      return new Response(applyAccent(css, accent), { headers: CACHE_HEADERS });
    }
  },
  
  '/styles/light_min.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#0066cc';
      const palette = generateColorPalette(accent);
      
      // const gradient = `linear-gradient(135deg, ${palette.primary}, ${palette.analogous}, ${palette.primary}, ${palette.analogous}, ${palette.primary})`;
      // const gradient = `linear-gradient(135deg, ${palette.primary}, ${palette.triadic}, ${palette.complementary}, ${palette.triadic}, ${palette.primary})`;
      // const gradient = `linear-gradient(135deg, ${palette.darker}, ${palette.complementary}, ${palette.primary}, ${palette.complementary}, ${palette.lighter})`;
      const gradient = `linear-gradient(135deg, ${palette.darker}, ${palette.primary}, ${palette.lighter}, ${palette.primary}, ${palette.darker})`;

      const dynamicAdminStyles = adminStyles.replace(
        'background: linear-gradient(90deg, #ff4081, #8ba3c7, #ff4081);',
        `background: ${gradient};`
      );
      
      const css = baseStyles + dynamicAdminStyles + themes.light;
      return new Response(applyAccent(css, accent), { headers: CACHE_HEADERS });
    }
  }
};