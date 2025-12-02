// src/templates/base.js
export function renderTemplate(title, bodyContent, user = null, config = null) {
  const siteTitle = config?.title || 'D E A D L I G H T';
  const pageTitle = title === 'home' ? siteTitle : `${title} | ${siteTitle}`;
  
  const cacheBust = Date.now();  // Cache bust for CSS
  
  let authLinks = '';
  
  // Alternative with more features for regular users
  if (user) {
    const isAdmin = user.role === 'admin' || user.isAdmin;
    
    // Common links for all logged-in users
    let commonLinks = `
      <a href="/user/${user.username}">${user.username}</a> |
      
    `;
    // <a href="/inbox">Inbox</a> |
    if (isAdmin) {
      authLinks = commonLinks + `
        <a href="/admin/add">Post</a> |
        <a href="/admin">Dash</a> |
        <a href="/admin/proxy">Proxy</a> |
        <a href="/logout">Logout</a>
      `;
    } else {
      authLinks = commonLinks + `
        <a href="/analytics">Analytics</a> |
        <a href="/user/${user.username}/new-post">Post</a> |
        <a href="/logout">Logout</a>
      `;
    }
  } else {
    authLinks = `
    <a href="/analytics">Analytics</a> |
    <a href="/register">Register</a> |
    <a href="/login">Login</a>
    `;
  }

  const accentColor = config?.accent_color || '#8ba3c7';
  
  return `
    <!DOCTYPE html>
    <html lang="en" data-theme="dark">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="mobile-web-app-capable" content="yes">
      <meta name="apple-mobile-web-app-capable" content="yes">
      <title>${pageTitle}</title>
      <link rel="icon" type="image/x-icon" href="/favicon.ico">
      <link rel="shortcut icon" type="image/x-icon" href="/favicon.ico">
      <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
      <link rel="stylesheet" href="/styles/theme.css?v=${cacheBust}">
      <link rel="stylesheet" href="/styles/dark_min.css?v=${cacheBust}" id="theme-stylesheet">

      <style>
        :root {
          --accent-color: ${accentColor};
        }
      </style>
    </head>
    <body>
      <header>
        <h1><a href="/">${pageTitle}</a></h1>
        <nav>
          ${authLinks}
          <div class="theme-toggle-container">
            <button id="theme-toggle" class="theme-toggle" aria-label="Toggle theme">
              <span class="theme-icon">♤</span>
            </button>
          </div>
        </nav>
      </header>
      <div class="container">
        ${bodyContent}
      </div>
      <script>
        // Theme Toggle Script
        const themeToggle = document.getElementById('theme-toggle');
        const html = document.documentElement;
        const stylesheet = document.getElementById('theme-stylesheet');
        
        // Load saved theme
        let currentTheme = localStorage.getItem('theme') || 'dark';
        html.setAttribute('data-theme', currentTheme);
        stylesheet.href = '/styles/' + currentTheme + '_min.css?v=${cacheBust}';

        // Update theme icon
        const themeIcon = themeToggle.querySelector('.theme-icon');
        themeIcon.textContent = currentTheme === 'dark' ? '♧' : '◇';
        
        // Handle theme toggle
        themeToggle.addEventListener('click', () => {
          currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
          
          // Update localStorage
          localStorage.setItem('theme', currentTheme);
          
          // Update HTML attribute
          html.setAttribute('data-theme', currentTheme);
          
          // Update stylesheet
          stylesheet.href = '/styles/' + currentTheme + '_min.css?v=${cacheBust}';
          
          // Update icon
          themeIcon.textContent = currentTheme === 'dark' ? '♡' : '♤';
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
      </script>
    </body>
    </html>
  `;
}