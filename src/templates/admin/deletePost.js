// src/templates/admin/deletePost.js
import { renderTemplate } from '../base.js';

export function renderDeleteConfirmation(post, user = null, config = null, csrfToken = '') { 
  const content = `
    <div class="delete-confirmation">
      <h1>Delete Post</h1>
      <p>Are you sure you want to delete "${post.title}"?</p>
      <div class="post-preview">
        <strong>Title:</strong> ${post.title}<br>
        <strong>Created:</strong> ${new Date(post.created_at).toLocaleDateString()}<br>
        <strong>Status:</strong> ${post.published ? 'Published' : 'Draft'}
      </div>
      <form action="/admin/delete/${post.id}" method="POST">
        <input type="hidden" name="csrf_token" value="${csrfToken}">  <!-- -->
        <button type="submit" class="button delete-button">Delete Post</button>
        <a href="/admin" class="button cancel-button">Cancel</a>
      </form>
    </div>
  `;

  return renderTemplate('Delete Post', content, user, config);
}
