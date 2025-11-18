// src/views/comments.js - Updated with public commenting

import { renderTemplate } from '../base.js';

export function renderCommentList(comments, postId, user, config) {
  const commentHtml = comments.map((comment, index) => `
    <div class="comment" style="margin-left: ${comment.level * 20}px;">
      <p>${comment.content}</p>
      <p class="post-meta">By ${comment.author} | ${new Date(comment.published_at).toLocaleDateString()}</p>
      ${user ? `
        <div class="comment-actions">
          <a href="/admin/comments/edit/${comment.id}" class="button edit-button">Edit</a>
          <a href="/admin/comments/delete/${comment.id}" class="button delete-button">Delete</a>
          <a href="/admin/comments/reply/${comment.id}" class="button reply-button">Reply</a>
        </div>
      ` : ''}
    </div>
  `).join('');
  
  return renderTemplate('Comments for Post ' + postId, `
    <h1>Comments</h1>
    ${commentHtml || '<p class="no-comments">No comments yet.</p>'}
    ${user ? `<a href="/admin/add-comment/${postId}" class="button">Add Comment</a>` : ''}
  `, user, config);
}

export function renderAddCommentForm(postId, user) {
  return renderTemplate('Add Comment', `
    <h1>Add Comment</h1>
    <form action="/admin/add-comment/${postId}" method="POST">
      <textarea name="content" required placeholder="Write your comment..."></textarea>
      <button type="submit" class="button">Submit</button>
    </form>
  `, user);
}

export function renderReplyForm(comment, user) {
  const parentUrl = comment.federation_metadata ? JSON.parse(comment.federation_metadata).parent_url : null;
  return renderTemplate('Reply to Comment', `
    <h1>Reply to Comment</h1>
    <p>Replying to: <a href="${parentUrl}">${comment.content.substring(0, 50)}${comment.content.length > 50 ? '...' : ''}</a></p>
    <form action="/admin/comments/reply/${comment.id}" method="POST">
      <textarea name="content" required placeholder="Write your reply..."></textarea>
      <button type="submit" class="button">Submit Reply</button>
    </form>
    <a href="/admin/comments/${comment.parent_id || comment.thread_id}" class="button">Back to Comments</a>
  `, user);
}

// NEW: Public comment form for non-admin users
export function renderPublicCommentForm(postId, postTitle, config) {
  const requireApproval = config?.comments?.requireApproval !== false;
  const allowAnonymous = config?.comments?.allowAnonymous !== false;
  
  return `
    <div class="public-comment-form">
      <h3>Leave a Comment</h3>
      ${requireApproval ? '<p class="info-message">Your comment will be reviewed before publishing.</p>' : ''}
      
      <form action="/api/comments/${postId}" method="POST" id="comment-form">
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
        
        // Form submission
        if (form) {
          form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Posting...';
            
            try {
              const formData = new FormData(form);
              const data = Object.fromEntries(formData.entries());
              
              const response = await fetch(form.action, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
              });
              
              const result = await response.json();
              
              if (response.ok) {
                statusDiv.className = 'status-message success';
                statusDiv.textContent = result.message || 'Comment posted successfully!';
                statusDiv.style.display = 'block';
                form.reset();
                if (charCount) charCount.textContent = '0';
                
                // Reload page after 2 seconds to show new comment
                setTimeout(() => window.location.reload(), 2000);
              } else {
                throw new Error(result.error || 'Failed to post comment');
              }
            } catch (error) {
              statusDiv.className = 'status-message error';
              statusDiv.textContent = error.message;
              statusDiv.style.display = 'block';
            } finally {
              submitBtn.disabled = false;
              submitBtn.textContent = originalText;
            }
          });
        }
      })();
    </script>
  `;
}

// NEW: Render comments with public form on blog posts
export function renderPublicCommentsSection(comments, postId, postTitle, user, config) {
  const approvedComments = user ? comments : comments.filter(c => c.status === 'approved');
  
  const commentHtml = approvedComments.map((comment) => `
    <div class="comment" style="margin-left: ${comment.level * 20}px;" data-comment-id="${comment.id}">
      <div class="comment-header">
        ${comment.author_url ? 
          `<strong class="comment-author"><a href="${comment.author_url}" target="_blank" rel="nofollow">${comment.author}</a></strong>` :
          `<strong class="comment-author">${comment.author}</strong>`
        }
        <span class="comment-date">${new Date(comment.published_at).toLocaleDateString()}</span>
        ${user && comment.status === 'pending' ? '<span class="badge pending">Pending</span>' : ''}
      </div>
      <div class="comment-content">
        <p>${escapeHtml(comment.content)}</p>
      </div>
      ${user ? `
        <div class="comment-actions admin-actions">
          ${comment.status === 'pending' ? `
            <button class="button small approve-btn" data-id="${comment.id}">Approve</button>
            <button class="button small reject-btn" data-id="${comment.id}">Reject</button>
          ` : ''}
          <a href="/admin/comments/edit/${comment.id}" class="button small">Edit</a>
          <a href="/admin/comments/delete/${comment.id}" class="button small delete">Delete</a>
        </div>
      ` : ''}
    </div>
  `).join('');
  
  return `
    <div class="comments-section">
      <h2>Comments (${approvedComments.length})</h2>
      
      ${commentHtml || '<p class="no-comments">No comments yet. Be the first to comment!</p>'}
      
      ${config?.comments?.enabled !== false ? renderPublicCommentForm(postId, postTitle, config) : ''}
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
      
      .admin-actions {
        margin-top: 0.5rem;
        display: flex;
        gap: 0.5rem;
      }
      
      .button.small {
        padding: 0.25rem 0.75rem;
        font-size: 0.85rem;
      }
      
      .no-comments {
        color: var(--text-muted, #666);
        font-style: italic;
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
