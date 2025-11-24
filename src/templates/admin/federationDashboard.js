// src/templates/admin/federationDashboard.js
import { renderTemplate } from '../base.js';

export function federationDashboard(federatedPosts, domains, user, config) {
  const trusted = domains || [];
  const federatedPostsSafe = federatedPosts || [];

  const html = `
    <div class="container">
      <h1>Federation Control Panel</h1>
      
      <div class="grid-3">
        <div class="card">
          <h3>${trusted.length}</h3>
          <p>Connected Blogs</p>
        </div>
        <div class="card">
          <h3>${federatedPostsSafe.length}</h3>
          <p>Federated Posts</p>
        </div>
        <div class="card">
          <h3>${trusted.length}</h3>
          <p>Connected Domains</p>
        </div>
      </div>

      <div class="section">
        <h2>Add a Deadlight Blog</h2>
        <form id="add-domain-form">
          <input type="text" placeholder="threat-level-midnight.deadlight.boo" id="domain-input" required />
          <button type="submit">Discover & Trust</button>
          <span id="discover-status"></span>
        </form>

        <div id="trusted-list">
          ${(trusted || []).map(d => `
            <div class="trusted-domain" data-domain="${d.domain}">
              <strong>${d.domain}</strong> 
              <span class="badge ${d.trust_level}">${d.trust_level}</span>
            </div>
          `).join('')}
        </div>
      </div>

      <div class="section">
        <h2>Posts from the Federation</h2>
        <div id="federated-posts">
          ${federatedPostsSafe.length === 0 
            ? '<p>No federated posts yet. Add a blog to start receiving!</p>'
            : federatedPostsSafe.map(p => `
              <article class="federated-post">
                <h3><a href="${p.source_url || '/post/' + p.id}" target="_blank">${p.title}</a></h3>
                <p>
                  <em>by ${p.author || 'Unknown'} from <strong>${p.source_domain}</strong></em>
                  ${p.published_at ? ' · ' + new Date(p.published_at).toLocaleDateString() : ''}
                </p>
                <div class="preview">${p.content.substring(0, 300)}...</div>
              </article>
            `).join('')}
        </div>
      </div>
    </div>

    <script>
      const form = document.getElementById('add-domain-form');
      const status = document.getElementById('discover-status');

      form.onsubmit = async (e) => {
        e.preventDefault();
        const domain = document.getElementById('domain-input').value.trim();
        if (!domain) return;

        status.textContent = 'Discovering...';
        const res = await fetch('/api/federation/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain, auto_discover: true })
        });
        const json = await res.json();

        if (json.success) {
          status.textContent = 'Trusted!';
          setTimeout(() => location.reload(), 1000);
        } else {
          status.textContent = 'Error: ' + json.error;
        }
      };
    </script>

    <style>
      .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
      .card { background: var(--card); padding: 1.5rem; border-radius: 8px; text-align: center; }
      .card h3 { margin: 0; font-size: 2.5rem; }
      .section { margin: 3rem 0; }
      .trusted-domain { padding: 0.75rem; background: var(--card); margin: 0.5rem 0; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; }
      .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
      .badge.verified { background: #0f0; color: #000; }
      .badge.unverified { background: #ff0; color: #000; }
      .federated-post { border-bottom: 1px solid var(--border); padding: 1rem 0; }
      .preview { margin-top: 0.5rem; opacity: 0.9; }
    </style>
  `;

  return renderTemplate('Federation Dashboard', html, user, config);
}