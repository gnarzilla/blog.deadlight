// src/templates/admin/federationDashboard.js
import { renderTemplate } from '../base.js';

export function federationDashboard(federatedPosts, domains, user, config) {
  // Build the static HTML with IDs for dynamic updates
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
      ${federatedPosts.map(post => `
        <article class="federated-post" data-id="${post.id}">
          <h4>
            <a href="${post.source_url}" target="_blank">${post.title}</a>
          </h4>
          <p>by ${post.author} from ${post.source_domain}</p>
          <div class="post-content">${post.content.substring(0,200)}…</div>
        </article>
      `).join('')}
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
        status.textContent = 'Syncing…';

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
                <div class="post-content">\${post.content.substring(0,200)}…</div>
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
    </script>
  `;

  // Wrap in your site’s layout
  return renderTemplate('Federation Network', html, user, config);
}