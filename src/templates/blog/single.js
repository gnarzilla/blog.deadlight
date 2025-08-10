// src/templates/blog/single.js
import { renderTemplate } from '../base.js';
import { renderMarkdown } from '../../../../lib.deadlight/core/src/markdown/processor.js';
import { renderAuthorLink } from '../../utils/templates.js';

export function renderSinglePost(post, user = null, navigation = null, config = null) {
  const postDate = new Date(post.created_at).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
  
  // Remove the <!--more--> marker from full post display
  const fullContent = post.content.replace('<!--more-->', '');
  
  const content = `
    <article class="single-post">
      <header class="post-header">
        <h1>${post.title}</h1>
        <div class="post-meta">
          <span>By ${renderAuthorLink(post.author_username)}</span>
          <span class="separator">•</span>
          <time datetime="${post.created_at}">${postDate}</time>
          ${post.updated_at && post.updated_at !== post.created_at ? `
            <span class="separator">•</span>
            <span class="updated">Updated ${new Date(post.updated_at).toLocaleDateString()}</span>
          ` : ''}
        </div>
      </header>
      
      <div class="post-content">
        ${renderMarkdown(fullContent)}
      </div>
      
      ${user ? `
        <div class="post-actions">
          <a href="/admin/edit/${post.id}" class="button edit-button">Edit Post</a>
          <form class="delete-form" action="/admin/delete/${post.id}" method="POST" 
                onsubmit="return confirm('Are you sure you want to delete this post?');">
            <button type="submit" class="button delete-button">Delete Post</button>
          </form>
        </div>
      ` : ''}
      
      ${navigation ? `
        <nav class="post-navigation">
          ${navigation.prev_id ? `
            <a href="/post/${navigation.prev_id}" class="nav-prev">
              <span class="nav-label">← Previous</span>
              <span class="nav-title">${navigation.prev_title}</span>
            </a>
          ` : '<div></div>'}
          
          ${navigation.next_id ? `
            <a href="/post/${navigation.next_id}" class="nav-next">
              <span class="nav-label">Next →</span>
              <span class="nav-title">${navigation.next_title}</span>
            </a>
          ` : '<div></div>'}
        </nav>
      ` : ''}
    </article>
  `;
  
  // Pass config to renderTemplate for dynamic site title
  return renderTemplate(post.title, content, user, config);
}
