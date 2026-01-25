// src/templates/admin/userManagement.js
import { renderTemplate } from '../base.js';
import { renderAuthorLink } from '../../../../lib.deadlight/core/src/utils/templates.js'

export function renderUserManagement(users, currentUser, config = null) {
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
          ${users.map(user => `
            <tr>
              <td>
                <strong>${renderAuthorLink(user.username)}</strong>
                ${user.id === currentUser.id ? '<span class="badge">You</span>' : ''}
              </td>
              <td>${user.post_count || 0}</td>
              <td>${user.last_post ? new Date(user.last_post).toLocaleDateString() : 'Never'}</td>
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
          `).join('')}
        </tbody>
      </table>

      <div class="info-box">
        <p><strong>Note:</strong> Deleting a user will delete all their posts. You cannot delete your own account while logged in.</p>
      </div>
    </div>
  `;

  return renderTemplate('User Management', content, currentUser, config);
}