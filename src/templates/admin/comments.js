// src/templates/admin/comments.js - Updated with public paths

import { renderTemplate } from '../base.js';

export function renderCommentList(comments, postId, user, config) {
  const commentHtml = comments.map((comment, index) => `
    <div class="comment" style="margin-left: ${comment.level * 20}px;">
      <p>${comment.content}</p>
      <p class="post-meta">By ${comment.author} | ${new Date(comment.published_at).toLocaleDateString()}</p>
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
      <a href="/post/${postId}" class="button secondary">Back to Post</a>
    </div>
  `, user, config);
}

export function renderAddCommentForm(postId, user, config) {
  return renderTemplate('Add Comment', `
    <h1>Add Comment</h1>
    <form action="/comments/add/${postId}" method="POST">
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
    
    <style>
      .form-group {
        margin-bottom: 1.5rem;
      }
      
      .form-group label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
      }
      
      .form-group textarea {
        width: 100%;
        padding: 0.75rem;
        border: 1px solid var(--border-color, #ddd);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1rem;
        resize: vertical;
      }
      
      .char-count {
        display: block;
        margin-top: 0.25rem;
        color: var(--text-muted, #666);
        font-size: 0.85rem;
      }
      
      .form-actions {
        display: flex;
        gap: 0.5rem;
      }
      
      .button.primary {
        background: var(--accent-color, #0066cc);
        color: white;
      }
      
      .button.secondary {
        background: var(--bg-secondary, #f5f5f5);
        color: var(--text-primary, #333);
      }
    </style>
  `, user, config);
}

export function renderReplyForm(comment, user, config) {
  const meta = comment.federation_metadata ? JSON.parse(comment.federation_metadata) : {};
  const parentUrl = meta.parent_url || `/post/${comment.parent_id || comment.thread_id}`;
  
  return renderTemplate('Reply to Comment', `
    <h1>Reply to Comment</h1>
    <div class="parent-comment">
      <p class="parent-label">Replying to:</p>
      <blockquote>
        ${comment.content.substring(0, 200)}${comment.content.length > 200 ? '...' : ''}
      </blockquote>
      <p class="post-meta">By ${comment.author_username || 'Unknown'}</p>
    </div>
    
    <form action="/comments/reply/${comment.id}" method="POST">
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
    
    <style>
      .parent-comment {
        margin: 1.5rem 0;
        padding: 1rem;
        background: var(--bg-secondary, #f5f5f5);
        border-left: 3px solid var(--accent-color, #0066cc);
        border-radius: 4px;
      }
      
      .parent-label {
        font-weight: 600;
        margin-bottom: 0.5rem;
        color: var(--text-muted, #666);
      }
      
      blockquote {
        margin: 0.5rem 0;
        padding: 0;
        border: none;
        font-style: italic;
      }
      
      .form-group {
        margin-bottom: 1.5rem;
      }
      
      .form-group label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
      }
      
      .form-group textarea {
        width: 100%;
        padding: 0.75rem;
        border: 1px solid var(--border-color, #ddd);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1rem;
        resize: vertical;
      }
      
      .char-count {
        display: block;
        margin-top: 0.25rem;
        color: var(--text-muted, #666);
        font-size: 0.85rem;
      }
      
      .form-actions {
        display: flex;
        gap: 0.5rem;
      }
      
      .button.primary {
        background: var(--accent-color, #0066cc);
        color: white;
      }
      
      .button.secondary {
        background: var(--bg-secondary, #f5f5f5);
        color: var(--text-primary, #333);
      }
    </style>
  `, user, config);
}

// Keep the public commenting functions from your original file
export function renderPublicCommentForm(postId, postTitle, config) {
  const requireApproval = config?.comments?.requireApproval !== false;
  const allowAnonymous = config?.comments?.allowAnonymous !== false;
  
  return `
    <div class="public-comment-form">
      <h3>Leave a Comment</h3>
      ${requireApproval ? '<p class="info-message">Your comment will be reviewed before publishing.</p>' : ''}
      
      <form action="/comments/add/${postId}" method="POST" id="comment-form">
        ${allowAnonymous ? `
          <div class="form-group">
            <label for="author_name">Name ${!config?.comments?.anonymousOptional ? '*' : '(optional)'}</label>
            <input 
              type="text" 
              id="author_name" 
              name="author_name" 
              ${!config?.comments?.anonymousOptional ? 'required' : ''}
              placeholder="Your name">
          </div>
          
          <div class="form-group">
            <label for="author_email">Email ${config?.comments?.requireEmail ? '*' : '(optional, not public)'}</label>
            <input 
              type="email" 
              id="author_email" 
              name="author_email" 
              ${config?.comments?.requireEmail ? 'required' : ''}
              placeholder="your@email.com">
          </div>
          
          <div class="form-group">
            <label for="author_url">Website (optional)</label>
            <input 
              type="url" 
              id="author_url" 
              name="author_url" 
              placeholder="https://yoursite.com">
          </div>
        ` : ''}
        
        <div class="form-group">
          <label for="content">Comment *</label>
          <textarea 
            id="content" 
            name="content" 
            required 
            rows="5"
            placeholder="Write your comment here..."
            minlength="3"
            maxlength="${config?.comments?.maxLength || 5000}"></textarea>
          <small class="char-count"><span id="char-count">0</span>/${config?.comments?.maxLength || 5000} characters</small>
        </div>
        
        <div class="form-actions">
          <button type="submit" class="button primary">Post Comment</button>
        </div>
      </form>
      
      <div id="comment-status" class="status-message" style="display: none;"></div>
    </div>
    
    <style>
      .public-comment-form {
        margin: 2rem 0;
        padding: 1.5rem;
        background: var(--bg-secondary, #f5f5f5);
        border-radius: 8px;
      }
      
      .public-comment-form h3 {
        margin-top: 0;
      }
      
      .info-message {
        color: var(--text-muted, #666);
        font-size: 0.9rem;
        margin-bottom: 1rem;
      }
      
      .form-group {
        margin-bottom: 1rem;
      }
      
      .form-group label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
      }
      
      .form-group input,
      .form-group textarea {
        width: 100%;
        padding: 0.75rem;
        border: 1px solid var(--border-color, #ddd);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1rem;
      }
      
      .form-group textarea {
        resize: vertical;
        min-height: 100px;
      }
      
      .char-count {
        display: block;
        margin-top: 0.25rem;
        color: var(--text-muted, #666);
        font-size: 0.85rem;
      }
      
      .form-actions {
        margin-top: 1rem;
      }
      
      .status-message {
        margin-top: 1rem;
        padding: 1rem;
        border-radius: 4px;
      }
      
      .status-message.success {
        background: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
      }
      
      .status-message.error {
        background: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
      }
    </style>
    
    <script>
      (function() {
        const form = document.getElementById('comment-form');
        const textarea = document.getElementById('content');
        const charCount = document.getElementById('char-count');
        const statusDiv = document.getElementById('comment-status');
        
        // Character counter
        if (textarea && charCount) {
          textarea.addEventListener('input', function() {
            charCount.textContent = this.value.length;
          });
        }
        
        // Form submission (standard POST, not AJAX)
        // The route will handle redirect after success
      })();
    </script>
  `;
}

export function renderPublicCommentsSection(comments, postId, postTitle, user, config) {
  const approvedComments = user ? comments : comments.filter(c => c.status === 'approved');
  
  const commentHtml = approvedComments.map((comment) => `
    <div class="comment" style="margin-left: ${comment.level * 20}px;" data-comment-id="${comment.id}">
      <div class="comment-header">
        ${comment.author_url ? 
          `<strong class="comment-author"><a href="${comment.author_url}" target="_blank" rel="nofollow">${escapeHtml(comment.author)}</a></strong>` :
          `<strong class="comment-author">${escapeHtml(comment.author)}</strong>`
        }
        <span class="comment-date">${new Date(comment.published_at).toLocaleDateString()}</span>
        ${user && comment.status === 'pending' ? '<span class="badge pending">Pending</span>' : ''}
      </div>
      <div class="comment-content">
        <p>${escapeHtml(comment.content)}</p>
      </div>
      ${user ? `
        <div class="comment-actions">
          <a href="/comments/reply/${comment.id}" class="button small">Reply</a>
          ${user.role === 'admin' || user.id === comment.author_id ? `
            <a href="/comments/delete/${comment.id}" class="button small delete">Delete</a>
          ` : ''}
        </div>
      ` : ''}
    </div>
  `).join('');
  
  return `
    <div class="comments-section">
      <h2>Comments (${approvedComments.length})</h2>
      
      ${commentHtml || '<p class="no-comments">No comments yet. Be the first to comment!</p>'}
      
      ${config?.comments?.enabled !== false ? (
        user ? 
          `<div class="comment-cta"><a href="/comments/add/${postId}" class="button primary">Add Comment</a></div>` :
          `<div class="comment-cta"><a href="/login" class="button primary">Log in to comment</a></div>`
      ) : ''}
    </div>
    
    <style>
      .comments-section {
        margin-top: 3rem;
        padding-top: 2rem;
        border-top: 2px solid var(--border-color, #ddd);
      }
      
      .comment {
        padding: 1rem;
        margin-bottom: 1rem;
        background: var(--bg-secondary, #fafafa);
        border-left: 3px solid var(--accent-color, #0066cc);
        border-radius: 4px;
      }
      
      .comment-header {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 0.5rem;
      }
      
      .comment-author {
        color: var(--text-primary, #333);
      }
      
      .comment-author a {
        color: var(--link-color, #0066cc);
        text-decoration: none;
      }
      
      .comment-date {
        color: var(--text-muted, #666);
        font-size: 0.9rem;
      }
      
      .badge {
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
      }
      
      .badge.pending {
        background: #fff3cd;
        color: #856404;
      }
      
      .comment-content p {
        margin: 0.5rem 0;
        line-height: 1.6;
      }
      
      .comment-actions {
        margin-top: 0.5rem;
        display: flex;
        gap: 0.5rem;
      }
      
      .button.small {
        padding: 0.25rem 0.75rem;
        font-size: 0.85rem;
      }
      
      .comment-cta {
        margin-top: 1.5rem;
        text-align: center;
      }
      
      .no-comments {
        color: var(--text-muted, #666);
        font-style: italic;
        text-align: center;
        padding: 2rem;
      }
    </style>
  `;
}

// Utility function to escape HTML
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}