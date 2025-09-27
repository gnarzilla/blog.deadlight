import { renderTemplate } from '../base.js';
import { renderMarkdown } from '../../../../lib.deadlight/core/src/markdown/processor.js';
import { renderAuthorLink } from '../../../../lib.deadlight/core/src/utils/templates.js'

export function renderSinglePost(post, user, navigation, config, comments = []) {
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
          <a href="/admin/comments/edit/${post.id}" class="button edit-button">Edit</a>
          <a href="/admin/comments/delete/${post.id}" class="button delete-button">Delete</a>
          <a href="/admin/comments/reply/${post.id}" class="button reply-button">Reply</a>
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
              <a href="/admin/comments/edit/${comment.id}" class="button edit-button">Edit</a>
              <a href="/admin/comments/delete/${comment.id}" class="button delete-button">Delete</a>
              <a href="/admin/comments/reply/${comment.id}" class="button reply-button">Reply</a>
            </div>
          ` : ''}
        </div>
      `).join('')}
    </div>
  ` : '<p class="no-comments">No comments yet.</p>';

const fullContent = post.content.replace('<--!more-->', '');

const content = `
    <h1 class="post-title">${post.title}</h1>
    <div class="post-meta">
      <span>By ${renderAuthorLink(post.author_username)}</span>
      <span>| ${new Date(post.created_at).toLocaleDateString()}</span>
    </div>
    <div class="post-content">${renderMarkdown(fullContent)}</div>
    ${navigation ? `
      <div class="post-navigation">
        ${navigation.prev_id ? `<a href="/post/${navigation.prev_id}" class="button">Previous: ${navigation.prev_title}</a>` : ''}
        ${navigation.next_id ? `<a href="/post/${navigation.next_id}" class="button">Next: ${navigation.next_title}</a>` : ''}
      </div>
    ` : ''}
    ${user ? `<a href="/admin/add-comment/${post.id}" class="button">Add Comment</a>` : ''}
    ${user ? `<a href="/admin/edit/${post.id}" class="button">Edit</a>` : ''}
    ${user ? `
      <form method="POST" action="/admin/federate-post/${post.id}" style="display: inline;">
        <button type="submit" class="button">Federate Post</button>
      </form>
    ` : ''}
    ${commentHtml}
  `;
  return renderTemplate(post.title, content, user, config);
}
