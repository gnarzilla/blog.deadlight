import { renderTemplate } from '../base.js';

export function renderUserAddPostForm(user, config = null) {
  const content = `
    <div class="user-form-container">
      <h1>Write a New Post</h1>
      <form method="POST" action="/write" class="post-form">
        <div class="form-group">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" required autofocus>
        </div>
        
        <div class="form-group">
          <label for="content">Content (Markdown supported)</label>
          <textarea id="content" name="content" rows="20" required 
                    placeholder="Write your post content here...

Use **bold** and *italic* text, add [links](https://wikipedia.org), and more!

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
        
        <div class="form-group">
          <label>Visibility</label>
          <div class="radio-group">
            <label class="radio-label">
              <input type="radio" name="visibility" value="public" checked>
              <span>Public (appears on blog.deadlight.boo)</span>
            </label>
            <label class="radio-label">
              <input type="radio" name="visibility" value="private">
              <span>Private (only on your subdomain)</span>
            </label>
          </div>
        </div>
        
        <div class="form-group checkbox-group">
          <label class="checkbox-label">
            <input type="checkbox" name="published" value="true" checked>
            <span>Publish immediately</span>
          </label>
        </div>
        
        <div class="form-actions">
          <button type="submit" class="button primary">Publish Post</button>
          <a href="/dashboard" class="button">Cancel</a>
        </div>
      </form>
    </div>
  `;

  return renderTemplate('Write New Post', content, user, config);
}