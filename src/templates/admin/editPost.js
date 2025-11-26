// src/templates/admin/editPost.js
import { renderTemplate } from '../base.js';

export function renderEditPostForm(post, user, config = null) {
  const content = `
    <div class="admin-form-container">
      <h1>Edit Post</h1>
      <div class="post-meta">
        <p>Created: ${new Date(post.created_at).toLocaleString()}</p>
        <p>Last Updated: ${new Date(post.updated_at).toLocaleString()}</p>
        <p>URL: <a href="/post/${post.slug}" target="_blank">/post/${post.slug}</a></p>
      </div>
      
      <form method="POST" action="/admin/edit/${post.id}" class="post-form">
        <div class="form-group">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" value="${post.title}" required>
        </div>
        
        <div class="form-group">
          <label for="slug">Slug (URL path)</label>
          <input type="text" id="slug" name="slug" value="${post.slug}" 
                 pattern="[a-z0-9-]+" title="Only lowercase letters, numbers, and hyphens allowed">
          <small>Leave blank to auto-generate from title</small>
        </div>
        
        <div class="form-group">
          <label for="content">Content (Markdown supported)</label>
          <textarea id="content" name="content" rows="20" required>${post.content}</textarea>
        </div>
        
        <div class="form-group checkbox-group">
          <label class="checkbox-label">
            <input type="checkbox" name="published" value="true" ${post.published ? 'checked' : ''}>
            <span>${post.published ? 'Published' : 'Draft'}</span>
          </label>
          <label class="checkbox-label">
            <input type="checkbox" name="visibility" value="public" ${post.visibility ? 'checked' : ''}>
            <span>${post.visibility ? 'Public' : 'Private'}</span>
          </label>
        </div>
        
        <div class="form-actions">
          <button type="submit" class="button primary">Update Post</button>
          <a href="/admin" class="button">Cancel</a>
          <a href="/post/${post.slug}" class="button" target="_blank">View Post</a>
        </div>
      </form>
    </div>
  `;

  return renderTemplate('Edit Post', content, user, config);
}