// src/templates/admin/federationDashboard.js
import { renderTemplate } from '../base.js';

export function federationDashboard(federatedPosts, domains, user, config) {
  const trusted = domains || [];
  const federatedPostsSafe = federatedPosts || [];

  const html = `
    <div class="container">
      
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
          <h3>${trusted.filter(d => d.trust_level === 'verified').length}</h3>
          <p>Verified Domains</p>
        </div>
      </div>

      <div class="section">
        <h2>Add a Deadlight Blog</h2>
        <p class="help-text">Connect to other Deadlight instances to share and receive posts</p>
        
        <form id="add-domain-form">
          <input 
            type="text" 
            placeholder="threat-level-midnight.deadlight.boo" 
            id="domain-input" 
            required 
          />
          <button type="submit" id="discover-btn">Discover & Trust</button>
        </form>
        
        <div id="discover-status" class="status-message"></div>

        <div id="trusted-list">
          ${trusted.length === 0 
            ? '<p class="empty-state">No connected blogs yet. Add one above to get started!</p>'
            : trusted.map(d => `
              <div class="trusted-domain" data-domain="${d.domain}">
                <div class="domain-info">
                  <strong>${d.domain}</strong>
                  <span class="badge ${d.trust_level}">${d.trust_level}</span>
                  ${d.last_seen ? `<span class="last-seen">Last seen: ${new Date(d.last_seen).toLocaleDateString()}</span>` : ''}
                </div>
                <div class="domain-actions">
                  <button class="small sync-btn" data-domain="${d.domain}" title="Sync posts from this blog">
                    Sync
                  </button>
                  <button class="small danger remove-btn" data-domain="${d.domain}" title="Remove connection">
                    Remove
                  </button>
                </div>
              </div>
            `).join('')}
        </div>
      </div>

      <div class="section">
        <h2>Posts from the Federation</h2>
        <div id="federated-posts">
          ${federatedPostsSafe.length === 0 
            ? '<p class="empty-state">No federated posts yet. Add a blog above to start receiving content!</p>'
            : federatedPostsSafe.map(p => {
                const meta = p.federation_metadata ? JSON.parse(p.federation_metadata) : {};
                return `
                  <article class="federated-post">
                    <h3>
                      <a href="${meta.source_url || '/post/' + p.slug}" target="_blank">
                        ${p.title}
                      </a>
                    </h3>
                    <p class="post-meta">
                      <em>by ${meta.author || 'Unknown'} from <strong>${meta.source_domain || 'unknown'}</strong></em>
                      ${p.created_at ? ' · ' + new Date(p.created_at).toLocaleDateString() : ''}
                      ${p.moderation_status === 'pending' ? ' · <span class="badge warning">Pending Moderation</span>' : ''}
                    </p>
                    <div class="preview">${p.content.substring(0, 300)}${p.content.length > 300 ? '...' : ''}</div>
                  </article>
                `;
              }).join('')}
        </div>
      </div>
    </div>

    <script>
      const form = document.getElementById('add-domain-form');
      const status = document.getElementById('discover-status');
      const btn = document.getElementById('discover-btn');

      form.onsubmit = async (e) => {
        e.preventDefault();
        const domain = document.getElementById('domain-input').value.trim();
        if (!domain) return;

        // UI feedback
        status.className = 'status-message info';
        status.textContent = '🔍 Discovering instance...';
        btn.disabled = true;

        try {
          const res = await fetch('/api/federation/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, auto_discover: true })
          });
          
          const json = await res.json();

          if (json.success) {
            status.className = 'status-message success';
            status.textContent = '✓ Successfully connected to ' + domain + '!';
            setTimeout(() => location.reload(), 1500);
          } else {
            status.className = 'status-message error';
            
            // Provide helpful error messages
            if (json.setup_required) {
              status.innerHTML = '⚠️ <strong>' + domain + '</strong> has not configured federation yet.<br><small>They need to run: <code>scripts/gen-fed-keys.sh</code></small>';
            } else if (json.federation_enabled === false) {
              status.textContent = '⚠️ ' + domain + ' does not have federation enabled';
            } else {
              status.textContent = '✗ Error: ' + (json.error || 'Unknown error');
            }
          }
        } catch (error) {
          status.className = 'status-message error';
          status.textContent = '✗ Network error: ' + error.message;
        } finally {
          btn.disabled = false;
        }
      };

      // Sync button handlers
      document.querySelectorAll('.sync-btn').forEach(btn => {
        btn.onclick = async () => {
          const domain = btn.dataset.domain;
          btn.textContent = 'Syncing...';
          btn.disabled = true;
          
          try {
            const res = await fetch('/admin/federation/sync', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ domain })
            });
            
            if (res.ok) {
              btn.textContent = '✓ Synced';
              setTimeout(() => location.reload(), 1000);
            } else {
              btn.textContent = 'Error';
              setTimeout(() => { btn.textContent = 'Sync'; btn.disabled = false; }, 2000);
            }
          } catch (error) {
            btn.textContent = 'Error';
            setTimeout(() => { btn.textContent = 'Sync'; btn.disabled = false; }, 2000);
          }
        };
      });

      // Remove button handlers
      document.querySelectorAll('.remove-btn').forEach(btn => {
        btn.onclick = async () => {
          const domain = btn.dataset.domain;
          if (!confirm('Remove connection to ' + domain + '?')) return;
          
          try {
            const res = await fetch('/api/federation/trust', {
              method: 'DELETE',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ domain })
            });
            
            if (res.ok) {
              btn.closest('.trusted-domain').remove();
            }
          } catch (error) {
            alert('Failed to remove: ' + error.message);
          }
        };
      });
    </script>
  `;

  return renderTemplate('Federation Dashboard', html, user, config);
}