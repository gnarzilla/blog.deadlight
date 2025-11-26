// src/templates/blog/post.js
import { renderTemplate } from '../base.js';
import { renderAuthorLink } from '../../../../lib.deadlight/core/src/utils/templates.js'

export function renderPost(post, author) {
  return `
    <article class="post">
      <header class="post-header">
        <h1 class="post-title">${post.title}</h1>
        <div class="post-meta">
          <span class="post-author">By ${renderAuthorLink(post.author_username)}</span>
          <span class="post-date">${new Date(post.created_at).toLocaleDateString()}</span>
        </div>
      </header>
      <div class="post-content">
        ${post.content}
      </div>
      ${renderPostActions(post)}
    </article>
  `;
}

export function renderPostActions(post, user) {  
  if (!user || user.role !== 'admin') return '';
  return `
    <div class="post-actions">
      <a href="/admin/edit/${post.id}" class="edit-button button">Edit</a>
      <a href="/admin/delete/${post.id}" class="delete-button button">Delete</a>
    </div>
  `;
}

export function renderFullPost(post, author) {
  return renderTemplate(
    post.title,
    renderPost(post, author)
  );
}