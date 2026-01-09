// src/templates/admin/comments.js 

import { renderTemplate } from '../base.js';

export function renderCommentList(comments, postId, user, config) {
  const commentHtml = comments.map((comment, index) => `
    <div class="comment" style="margin-left: ${comment.level * 20}px;">
      <p>${escapeHtml(comment.content)}</p>
      <p class="post-meta">By ${escapeHtml(comment.author)} | ${new Date(comment.published_at).toLocaleDateString()}</p>
      ${user ? `
        <div class="comment-actions">
          <a href="/comments/reply/${comment.id}" class="button reply-button">Reply</a>
          ${user.role === 'admin' || user.id === comment.author_id ? `
            <a href="/comments/delete/${comment.id}" class="button delete-button">Delete</a>
          ` : ''}
        </div>
      ` : ''}
    </div>
  `).join('');
  
  return renderTemplate('Comments for Post ' + postId, `
    <h1>Comments</h1>
    ${commentHtml || '<p class="no-comments">No comments yet.</p>'}
    ${user ? `<a href="/comments/add/${postId}" class="button">Add Comment</a>` : `
      <p class="info-message">
        <a href="/login">Log in</a> to leave a comment
      </p>
    `}
    <div class="actions">
      <a href="/comments/${postId}" class="button secondary">Back to Comments</a>
    </div>
  `, user, config);
}

export function renderAddCommentForm(postId, user, config, csrfToken) {
  return renderTemplate('Add Comment', `
    <h1>Add Comment</h1>
    <form action="/comments/add/${postId}" method="POST">
      <input type="hidden" name="csrf_token" value="${csrfToken || ''}">
      <div class="form-group">
        <label for="content">Your Comment</label>
        <textarea 
          id="content"
          name="content" 
          required 
          placeholder="Write your comment..."
          rows="5"
          minlength="3"
          maxlength="5000"></textarea>
        <small class="char-count">Max 5000 characters</small>
      </div>
      <div class="form-actions">
        <button type="submit" class="button primary">Submit Comment</button>
        <a href="/comments/${postId}" class="button secondary">Cancel</a>
      </div>
    </form>
    
  `, user, config);
}

export function renderReplyForm(comment, user, config, csrfToken) {
  const meta = comment.federation_metadata ? JSON.parse(comment.federation_metadata) : {};
  const parentUrl = meta.parent_url || `/post/${comment.parent_id || comment.thread_id}`;
  
  return renderTemplate('Reply to Comment', `
    <h1>Reply to Comment</h1>
    <div class="parent-comment">
      <p class="parent-label">Replying to:</p>
      <blockquote>
        ${escapeHtml(comment.content.substring(0, 200))}${comment.content.length > 200 ? '...' : ''}
      </blockquote>
      <p class="post-meta">By ${escapeHtml(comment.author_username || 'Unknown')}</p>
    </div>
    
    <form action="/comments/reply/${comment.id}" method="POST">
      <input type="hidden" name="csrf_token" value="${csrfToken || ''}">
      <div class="form-group">
        <label for="content">Your Reply</label>
        <textarea 
          id="content"
          name="content" 
          required 
          placeholder="Write your reply..."
          rows="5"
          minlength="3"
          maxlength="5000"></textarea>
        <small class="char-count">Max 5000 characters</small>
      </div>
      <div class="form-actions">
        <button type="submit" class="button primary">Submit Reply</button>
        <a href="/comments/${comment.parent_id || comment.thread_id}" class="button secondary">Cancel</a>
      </div>
    </form>
    
  `, user, config);
}

// Utility function to escape HTML (prevent XSS)
function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}
