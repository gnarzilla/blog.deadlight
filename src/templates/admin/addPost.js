// src/templates/admin/addPost.js
import { renderTemplate } from '../base.js';

export function renderUserPostForm(user, config, error = null, post = null) {
  const isEdit = !!post;
  const title = isEdit ? 'Edit Post' : 'Create New Post';
  
  const content = `
    <div class="post-form-container">
      <h1>${title}</h1>
      
      ${error ? `<div class="error-message">${error}</div>` : ''}
      
      <form method="POST" class="post-form">
        <div class="form-group">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" 
                 value="${post?.title || ''}" required>
        </div>
        
        <div class="form-group">
          <label for="content">Content</label>
          <textarea id="content" name="content" rows="20" required 
                    placeholder="Write your post here... (Markdown supported)">${post?.content || ''}</textarea>
          <small class="form-help">
            You can use **bold**, *italic*, # headings, and more with Markdown
          </small>
        </div>
        
        <div class="form-group">
          <label>
            <input type="checkbox" name="publish" value="true" 
                   ${post?.published ? 'checked' : ''}>
            Publish immediately (uncheck to save as draft)
          </label>
        </div>
        
        <div class="form-actions">
          <button type="submit" class="button primary">${isEdit ? 'Update' : 'Create'} Post</button>
          <a href="/user/${user.username}" class="button secondary">Cancel</a>
        </div>
      </form>
    </div>
  `;
  
  return renderTemplate(title, content, user, config);
}

export function renderAddPostForm(user, config = null) {
  const content = `
    <div class="admin-form-container">
      <h1>Add New Post</h1>
      <form method="POST" action="/admin/add" class="post-form">
        <div class="form-group">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" required autofocus>
        </div>
        
        <div class="form-group">
          <label for="slug">Slug (URL path)</label>
          <input type="text" id="slug" name="slug" 
                 pattern="[a-z0-9-]+" title="Only lowercase letters, numbers, and hyphens allowed">
          <small>Leave blank to auto-generate from title</small>
        </div>
        
        <div class="form-group">
          <label for="content">Content (Markdown supported)</label>
          <textarea id="content" name="content" rows="20" required 
                    placeholder="Write your post content here...

Use **bold** and *italic* text, add [links](https://example.com), and more!

## Headings
### Subheadings

- List items
- Another item

\`\`\`javascript
// Code blocks work too!
console.log('Hello world!');
\`\`\`

Add <!--more--> to create a custom excerpt break point."></textarea>
        </div>
        
        <div class="form-group checkbox-group">
          <label class="checkbox-label">
            <input type="checkbox" name="published" value="true" checked>
            <span>Publish immediately</span>
          </label>
          <label class="checkbox-label">
            <input type="checkbox" name="visibility" value="private">
            <span>Publish to Profile Only</span>
          </label>
        </div>
        
        <div class="form-actions">
          <button type="submit" class="button primary">Create Post</button>
          <a href="/admin" class="button">Cancel</a>
        </div>
      </form>
    </div>
  `;

  return renderTemplate('Add New Post', content, user, config);
}