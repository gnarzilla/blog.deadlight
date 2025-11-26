// src/routes/styles.js

function lightenDarkenColor(col, amt) {
  let usePound = false;
  if (col[0] === "#") {
    col = col.slice(1);
    usePound = true;
  }
  const num = parseInt(col, 16);
  let r = (num >> 16) + amt;
  let g = ((num >> 8) & 0x00FF) + amt;
  let b = (num & 0x0000FF) + amt;

  r = Math.min(255, Math.max(0, r));
  g = Math.min(255, Math.max(0, g));
  b = Math.min(255, Math.max(0, b));

  return (usePound ? "#" : "") +
    ((r << 16) | (g << 8) | b)
      .toString(16)
      .padStart(6, '0');
}

const CACHE_HEADERS = {
  'Content-Type': 'text/css',
  'Cache-Control': 'public, max-age=3600'
};

// ------------------------------
//  ENTIRE FULL BASE STYLES
// ------------------------------

// Base styles that work for both themes
const baseStyles = `
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
    margin: 0;
    font-size: 0.875rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stat-number {
    font-size: 2.5rem;
    font-weight: bold;
    color: var(--text-primary);
    line-height: 1;
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

  .data-table th, .data-table td {
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

  /* Analytics Dashboard Specific */
  .analytics-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
  }

  .metric {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
    text-align: center;
  }

  .metric-value {
    font-size: 2rem;
    font-weight: bold;
    color: var(--text-primary);
  }

  .metric-label {
    color: var(--text-secondary);
    text-transform: uppercase;
    font-size: 0.9rem;
  }

  .chart-section {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
    margin-bottom: 3rem;
  }

  .simple-chart {
    display: flex;
    align-items: flex-end;
    height: 200px;
    margin: 1rem 0;
  }

  .chart-bar {
    flex: 1;
    text-align: center;
    position: relative;
  }

  .bar {
    background: var(--button-primary-bg);
    width: 100%;
    border-radius: 4px 4px 0 0;
  }

  .value {
    position: absolute;
    top: -20px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.8rem;
  }

  .label {
    margin-top: 5px;
    font-size: 0.8rem;
    color: var(--text-secondary);
  }

  .data-table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
  }

  .data-table th, .data-table td {
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    text-align: left;
  }

  .data-table th {
    background: var(--bg-primary);
  }

  .analytics-back {
    color: var(--link-color);
    text-decoration: none;
  }

  .analytics-back:hover {
    text-decoration: underline;
  }

  .no-data {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
  }

  /* Proxy Dashboard Specific */
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 1rem;
  }

  .card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 0.25rem;
    padding: 1rem;
    margin-bottom: 1rem;
  }

  .button {
    padding: 0.5rem 1rem;
    background: var(--primary, #007bff);
    color: white;
    border: none;
    cursor: pointer;
    border-radius: 0.25rem;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th, td {
    padding: 0.5rem;
    border-bottom: 1px solid var(--border, #dee2e6);
    text-align: left;
  }

  ul {
    list-style-type: disc;
    padding-left: 1.5rem;
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

  /* Muted helper (used for captions, footnotes, etc.) */
  .muted {
    color: var(--text-secondary);
    font-size: 0.85rem;
  }

  /* Back link on analytics */
  .analytics-back {
    display: inline-block;
    margin-top: 2rem;
    text-align: center;
    color: var(--link-color);
  }

  .analytics-back:hover {
    color: var(--link-hover);
  }

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

  .edit-button { background-color: #218838; }
  .edit-button:hover { background-color: #1e7e34; }
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
  /* Add to your styles */
  .analytics-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }

  .metric {
    background: #1a1a1a;
    border: 1px solid #333;
    padding: 20px;
    border-radius: 8px;
    text-align: center;
  }

  .metric-value {
    font-size: 2em;
    font-weight: bold;
    color: #4a9eff;
    margin-bottom: 10px;
  }

  .metric-label {
    color: #888;
    text-transform: uppercase;
    font-size: 0.9em;
  }

  .chart-section {
    margin-bottom: 40px;
  }

  .simple-chart {
    display: flex;
    align-items: flex-end;
    height: 200px;
    gap: 2px;
    padding: 20px;
    background: #1a1a1a;
    border: 1px solid #333;
    border-radius: 8px;
  }

  .chart-bar {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: flex-end;
    position: relative;
  }

  .chart-bar .bar {
    width: 100%;
    background: #4a9eff;
    height: var(--height);
    border-radius: 2px 2px 0 0;
    transition: height 0.3s ease;
  }

  .chart-bar:hover .bar { background: #0056b3; }

  .chart-bar .value {
    position: absolute;
    bottom: calc(var(--height) + 5px);
    font-size: 0.8em;
    color: #495057;
  }

  .chart-bar .label {
    margin-top: 5px;
    font-size: 0.7em;
    color: #666;
  }

  .data-table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
  }

  .data-table th, .data-table td {
    padding: 0.75rem;
    border: 1px solid #dee2e6;
    text-align: left;
  }

  .data-table th { background: #f8f9fa; }

  .analytics-back {
    display: inline-block;
    margin-top: 20px;
    color: #4a9eff;
    text-decoration: none;
  }
  
  /* Add to your styles */
  .post-form-container {
    max-width: 800px;
    margin: 0 auto;
    padding: 2rem;
  }

  .post-form .form-group {
    margin-bottom: 1.5rem;
  }

  .post-form label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: bold;
  }

  .post-form input[type="text"],
  .post-form textarea {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid #333;
    background: #1a1a1a;
    color: #e0e0e0;
    border-radius: 4px;
  }

  .post-form textarea {
    resize: vertical;
    font-family: monospace;
  }

  .form-help {
    display: block;
    margin-top: 0.25rem;
    color: #888;
    font-size: 0.875rem;
  }

  .form-actions {
    display: flex;
    gap: 1rem;
    margin-top: 2rem;
  }

  .form-actions .button.primary {
    flex: 1;
  }

  .user-settings {
    max-width: 600px;
    margin: 0 auto;
    padding: 2rem;
  }

  .settings-form fieldset {
    border: 1px solid #333;
    padding: 1.5rem;
    margin-bottom: 2rem;
    border-radius: 4px;
  }

  .settings-form legend {
    padding: 0 0.5rem;
    font-weight: bold;
  }

  .danger-zone {
    margin-top: 3rem;
    padding: 1.5rem;
    border: 1px solid #444;
    border-radius: 4px;
    background: rgba(255, 0, 0, 0.05);
  }

  .danger-zone h3 {
    color: #ff6b6b;
    margin-top: 0;
  }

  .metric-card,
  .service-card {
    background: var(--bg-primary);
    border-color: var(--bg-secondary);
    color: var(--text-primary);
  }

  .activity-stream {
    background: var(--activity-bg);
    border-color: var(--card-border);
  }

  .domain-item {
    background: var(--metric-bg);
    border: 1px solid var(--metric-border);
    padding: 0.5rem 1rem;
    border-radius: 4px;
    margin-bottom: 0.5rem;
  }

  /* Enhanced Proxy Dashboard Styles */
  .proxy-dashboard.enhanced {
    max-width: 1400px;
  }

  .connection-status {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .status-dot {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 0.5rem;
    animation: pulse 2s infinite;
  }

  .connected .status-dot { background: var(--status-healthy); }
  .disconnected .status-dot { background: var(--status-error); }

  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }

  .service-icon {
    font-size: 1.5rem;
    margin-right: 0.5rem;
  }

  .circuit-closed { color: var(--status-healthy); }
  .circuit-open { color: var(--status-error); }
  .circuit-half-open { color: var(--status-warning); }

  @keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
  }

  /* Activity Stream Enhancements */
  .activity-item {
    padding: 0.5rem;
    border-bottom: 1px solid var(--border-color);
    font-size: 0.875rem;
  }

  .activity-time {
    color: var(--text-secondary);
    margin-right: 0.5rem;
  }

  .activity-type {
    font-weight: bold;
    margin-right: 0.5rem;
  }

  .activity-item.error { color: var(--status-error); }
  .activity-item.success { color: var(--status-healthy); }
  .activity-item.warning { color: var(--status-warning); }

  /* Federation Management */
  .federation-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
    margin-top: 1.5rem;
  }

  .domain-list {
    max-height: 300px;
    overflow-y: auto;
    margin-bottom: 1rem;
  }

  .domain-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    margin-bottom: 0.5rem;
  }

  .domain-trust {
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .domain-trust.verified { 
    background: var(--status-healthy); 
    color: white;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
  }

  .stat {
    text-align: center;
  }

  .stat-value {
    font-size: 1.5rem;
    font-weight: bold;
    color: var(--text-primary);
  }

  .stat-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }

  /* Action Panel */
  .actions-section {
    margin-top: 2rem;
  }

  .action-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
  }

  .action-group {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: var(--border-radius);
    border: 1px solid var(--border-color);
  }

  .action-group h4 {
    margin: 0 0 1rem 0;
    color: var(--text-primary);
  }

  .action-group .button {
    display: block;
    width: 100%;
    margin-bottom: 0.5rem;
  }

  .button.danger {
    background: var(--button-danger-bg);
    color: var(--button-danger-text);
  }

  .button.danger:hover {
    background: var(--button-danger-hover);
  }

  .button.disabled {
    opacity: 0.5;
    cursor: not-allowed;
    pointer-events: none;
  }
  }`;

// ------------------------------
//  FULL DARK THEME TEMPLATE
// ------------------------------

const darkThemeTemplate = `
:root[data-theme="dark"] {
  --bg-primary: #000;
  --bg-secondary: #222222;
  --text-primary: #fff;
  --text-secondary: #888;
  --border-color: #444444;
  --border-hover: #666666;

  /* dynamic: to be replaced */
  --link-color: #8ba3c7;
  --link-hover: #adc3e7;

  --nav-hover-bg: #333;
  --nav-hover-color: #fff;

  --button-primary-bg: #333;
  --button-primary-text: #fff;
  --button-primary-hover: #555;

  --button-secondary-bg: #444;
  --button-secondary-text: #fff;
  --button-secondary-hover: #666;

  --button-danger-bg: #614f4fff; 
  --button-danger-text: #fff;
  --button-danger-hover: #ada6a6;

  --theme-toggle-box-shadow: #ffffffff;
  --theme-toggle-background-color: #000;

  --input-bg: #121212;
  --input-border: #333;

  --code-bg: #1a1a1a;

  --success-bg: #0a4f0a;
  --success-text: #90ee90;
  --success-border: #0f7f0f;

  --error-bg: #4f0a0a;
  --error-text: #ff9090;
  --error-border: #7f0f0f;

  --card-bg: #1a1a1a;
  --card-border: #333;
  --card-text: #e0e0e0;

  --metric-bg: #0a0a0a;
  --metric-border: #333;

  --activity-bg: #0a0a0a;

  --status-healthy: #4ade80;
  --status-error: #f87171;
  --status-warning: #fbbf24;
}
`;


// ------------------------------
//  FULL LIGHT THEME TEMPLATE
// ------------------------------

const lightThemeTemplate = `
:root[data-theme="light"] {
  --bg-primary: #fff;
  --bg-secondary: #f5f5f5;
  --text-primary: #333;
  --text-secondary: #666;
  --border-color: #ddd;
  --border-hover: #999;

  /* dynamic: to be replaced */
  --link-color: #0066cc;
  --link-hover: #0052a3;

  --nav-hover-bg: #f0f0f0;
  --nav-hover-color: #333;

  --button-primary-bg: #333;
  --button-primary-text: #fff;
  --button-primary-hover: #555;

  --button-secondary-bg: #666;
  --button-secondary-text: #fff;
  --button-secondary-hover: #888;

  --button-danger-bg: #000;
  --button-danger-text: #fff;
  --button-danger-hover: #333;

  --theme-toggle-box-shadow: #00000000;

  --input-bg: #fff;
  --input-border: #ccc;

  --code-bg: #f4f4f4;

  --success-bg: #d4edda;
  --success-text: #155724;
  --success-border: #c3e6cb;

  --error-bg: #f8d7da;
  --error-text: #721c24;
  --error-border: #f5c6cb;

  --card-bg: #f5f5f5;
  --card-border: #ddd;
  --card-text: #333;

  --metric-bg: #fff;
  --metric-border: #e0e0e0;

  --activity-bg: #fafafa;

  --status-healthy: #22c55e;
  --status-error: #ef4444;
  --status-warning: #f59e0b;
}
`;


// ------------------------------
//  APPLY ACCENT COLOR dynamically
// ------------------------------

function applyDynamicAccent(themeTemplate, defaultColor) {
  const accent = defaultColor;
  const hover = defaultColor
    ? lightenDarkenColor(defaultColor, themeTemplate.includes('dark') ? 35 : -30)
    : defaultColor;

  return themeTemplate
    .replace(/--link-color: #[0-9a-fA-F]{6};/, `--link-color: ${accent};`)
    .replace(/--link-hover: #[0-9a-fA-F]{6};/, `--link-hover: ${hover};`);
}

// ------------------------------
//  STYLE ROUTES
// ------------------------------

export const styleRoutes = {

  '/styles/dark_min.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#8ba3c7';

      const dynamicDark = applyDynamicAccent(darkThemeTemplate, accent);

      return new Response(baseStyles + dynamicDark, {
        headers: CACHE_HEADERS
      });
    }
  },

  '/styles/light_min.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#0066cc';

      const dynamicLight = applyDynamicAccent(lightThemeTemplate, accent);

      return new Response(baseStyles + dynamicLight, {
        headers: CACHE_HEADERS
      });
    }
  },

  // theme.css = dark by default
  '/styles/theme.css': {
    GET: async (req, env) => {
      const config = await env.services.config.getConfig();
      const accent = config.accent_color || '#8ba3c7';

      const dynamicDark = applyDynamicAccent(darkThemeTemplate, accent);

      return new Response(baseStyles + dynamicDark, {
        headers: CACHE_HEADERS
      });
    }
  }
};

// Dark theme variables
const darkTheme = `
  :root[data-theme="dark"] {
    /* Colors */
    --bg-primary: #000;
    --bg-secondary: #222222;
    --text-primary: #fff;
    --text-secondary: #888;
    --border-color: #444444;
    --border-hover: #666666;
    
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
    
    --button-danger-bg: #614f4fff; 
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

    /* Dashboard */
    --card-bg: #1a1a1a;
    --card-border: #333;
    --card-text: #e0e0e0;
    --metric-bg: #0a0a0a;
    --metric-border: #333;
    --activity-bg: #0a0a0a;
    --status-healthy: #4ade80;
    --status-error: #f87171;
    --status-warning: #fbbf24;
    }
  `;

  // Light theme variables
  const lightTheme = `
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

      --card-bg: #f5f5f5;
      --card-border: #ddd;
      --card-text: #333;
      --metric-bg: #fff;
      --metric-border: #e0e0e0;
      --activity-bg: #fafafa;
      --status-healthy: #22c55e;
      --status-error: #ef4444;
      --status-warning: #f59e0b;
    }
`;
