// src/templates/admin/dashboard.js - Remove the database calls
import { renderTemplate } from '../base.js';

export function renderAdminDashboard(stats, posts, requestStats = [], user, config = null) { 
  // Prepare data for the simple chart
  const chartData = requestStats && requestStats.length > 0 
    ? requestStats.map(day => ({
        day: new Date(day.day).toLocaleDateString('en-US', { weekday: 'short' }),
        requests: day.requests
      }))
    : [];
  
  const maxRequests = chartData.length > 0 
    ? Math.max(...chartData.map(d => d.requests), 1)
    : 1;

  // Build the dashboard content
  const content = `
    <div class="container">
      <div class="page-header">
        <h1>Dashboard</h1>
        ${stats.activeVisitors > 0 ? `
          <div class="active-visitors">
            <span class="pulse"></span>
            ${stats.activeVisitors} active visitor${stats.activeVisitors !== 1 ? 's' : ''} now
          </div>
        ` : ''}
      </div>
      
      <div class="admin-dashboard">
        <!-- Stats Grid -->
        <div class="stats-grid">
          <div class="stat-card">
            <h3>TOTAL POSTS</h3>
            <div class="stat-number">${stats.totalPosts}</div>
            <a href="/admin/analytics?filter=posts" class="stat-link">View analytics →</a>
          </div>
          <div class="stat-card">
            <h3>TOTAL USERS</h3>
            <div class="stat-number">${stats.totalUsers || 0}</div>
            <a href="/admin/users" class="stat-link">View users →</a>
          </div>
          <div class="stat-card">
            <h3>POSTS TODAY</h3>
            <div class="stat-number">${stats.postsToday || 0}</div>
            
          </div>
          <div class="stat-card">
            <h3>PUBLISHED</h3>
            <div class="stat-number">${stats.publishedPosts || 0}</div>
            <a href="/" class="stat-link">View posts →</a>
          </div>
        </div>

        <!-- Browser Stats (if available) -->
        ${stats.browserStats && stats.browserStats.length > 0 ? `
          <div class="browser-stats">
            <h3>Browser Usage</h3>
            <div class="browser-list">
              ${stats.browserStats.map(browser => `
                <div class="browser-item">
                  <span>${browser.browser}</span>
                  <span>${browser.count}</span>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Quick Actions -->
        <div class="quick-actions">
          <h2>Quick Actions</h2>
          <div class="action-buttons">
            <a href="/admin/add" class="button">Create New Post</a>
            <a href="/admin/users" class="button">Manage Users</a>
            <a href="/admin/settings" class="button">Settings</a>
            <a href="/admin/proxy" class="button">Proxy Dashboard</a>
            <a href="/admin/federation" class="button">Federation</a>
            <a href="/admin/analytics" class="button">Analytics</a>
            <a href="/" class="button">View Blog</a>
          </div>
        </div>

        <!-- Rest of your template remains the same -->
        ${chartData.length > 0 ? `
          <div class="chart-section">
            <h2>Requests (Last 7 Days)</h2>
            <div class="simple-chart">
              ${chartData.map(data => `
                <div class="chart-bar" style="--height: ${(data.requests / maxRequests) * 100}%">
                  <div class="bar"></div>
                  <div class="label">${data.day}</div>
                  <div class="value">${data.requests}</div>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Recent Posts section continues as before -->
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
                ${posts.map(post => `
                  <tr>
                    <td>
                      <a href="/post/${post.slug || post.id}" class="post-title-link">${post.title}</a>
                    </td>
                    <td>${post.author_username || 'Unknown'}</td>
                    <td>${new Date(post.created_at).toLocaleDateString()}</td>
                    <td>${post.published ? '<span class="badge">Published</span>' : 'Draft'}</td>
                    <td class="action-cell">
                      <a href="/admin/edit/${post.id}" class="button small-button edit-button">Edit</a>
                      <form action="/admin/delete/${post.id}" method="POST" style="display: inline;">
                        <button type="submit" class="button small-button delete-button" 
                                onclick="return confirm('Delete this post?')">Delete</button>
                      </form>
                    </td>
                  </tr>
                `).join('')}
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

  return renderTemplate('Dashboard', content, user, config);
}