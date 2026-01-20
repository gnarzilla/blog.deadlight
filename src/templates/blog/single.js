import { renderTemplate } from '../base.js';
import { renderMarkdown } from '../../../../lib.deadlight/core/src/markdown/processor.js';
import { renderAuthorLink } from '../../../../lib.deadlight/core/src/utils/templates.js'

export function renderSinglePost(post, user, navigation, config, comments = [], csrfToken = null) {
  if (!post) throw new Error('Post is undefined');

  if (post.post_type === 'comment') {
    const parentUrl = post.federation_metadata ? JSON.parse(post.federation_metadata).parent_url : null;
    return renderTemplate('Comment', `
      <h1 class="post-title">This is a Comment</h1>
      <p>This content is a comment on <a href="${parentUrl}">${parentUrl}</a>.</p>
      <p>Content: ${post.content}</p>
      <p class="post-meta">By ${renderAuthorLink(post.author_username)} | ${new Date(post.created_at).toLocaleDateString()}</p>
      ${user ? `
        <div class="comment-actions">
          <a href="/comments/edit/${post.id}" class="button edit-button">Edit</a>
          <a href="/comments/delete/${post.id}" class="button delete-button">Delete</a>
          <a href="/comments/reply/${post.id}" class="button reply-button">Reply</a>
        </div>
      ` : ''}
      <a href="${parentUrl || '/'}">Back to Post</a>
    `, user, config);
  }

  const commentHtml = comments.length ? `
    <div class="comment-list">
      <h2>Comments</h2>
      ${comments.map((comment, index) => `
        <div class="comment" style="margin-left: ${comment.level * 20}px;">
          <p class="post-content">${comment.content}</p>
          <p class="post-meta">By ${comment.author} | ${new Date(comment.published_at).toLocaleDateString()}</p>
          ${user ? `
            <div class="comment-actions">
              <a href="/comments/edit/${comment.id}" class="button edit-button">Edit</a>
              <a href="/comments/delete/${comment.id}" class="button delete-button">Delete</a>
              <a href="/comments/reply/${comment.id}" class="button reply-button">Reply</a>
            </div>
          ` : ''}
        </div>
      `).join('')}
    </div>
  ` : '<p class="no-comments">No comments yet.</p>';

  const fullContent = post.content.replace('<--!more-->', '');
  const karma = post.karma || 0;

  const content = `
    <h1 class="post-title">${post.title}</h1>
    <div class="post-meta">
      <span>By ${renderAuthorLink(post.author_username)}</span>
      <span>| ${new Date(post.created_at).toLocaleDateString()}</span>
    </div>
    
    <!-- Voting section with CSRF tokens -->
    <div class="post-voting-single">
      ${user && csrfToken ? `
        <form method="POST" action="/api/posts/${post.id}/upvote">
          <input type="hidden" name="csrf_token" value="${csrfToken}">
          <button type="submit" class="vote-button upvote" title="Upvote">▲</button>
        </form>
      ` : ''}
      <span class="karma-score" title="Score: ${karma}">${karma}</span>
      ${user && csrfToken ? `
        <form method="POST" action="/api/posts/${post.id}/downvote">
          <input type="hidden" name="csrf_token" value="${csrfToken}">
          <button type="submit" class="vote-button downvote" title="Downvote">▼</button>
        </form>
      ` : ''}
    </div>
    
    <div class="post-content">${renderMarkdown(fullContent)}</div>
    
    ${navigation ? `
      <div class="post-navigation">
        ${navigation.prev_id ? `<a href="/post/${navigation.prev_id}" class="button">Previous: ${navigation.prev_title}</a>` : ''}
        ${navigation.next_id ? `<a href="/post/${navigation.next_id}" class="button">Next: ${navigation.next_title}</a>` : ''}
      </div>
    ` : ''}
    
    ${user ? `<a href="/comments/add/${post.id}" class="button">Add Comment</a>` : ''}
    ${user ? `<a href="/admin/edit/${post.id}" class="edit-button button button-sm">Edit</a>` : ''}
    
    ${user && csrfToken ? `
      <form method="POST" action="/admin/federate-post/${post.id}" style="display: inline;">
        <input type="hidden" name="csrf_token" value="${csrfToken}">
        <button type="submit" class="button">Federate Post</button>
      </form>
    ` : ''}
    
    ${commentHtml}
  `;
  
  return renderTemplate(post.title, content, user, config);
}