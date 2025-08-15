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