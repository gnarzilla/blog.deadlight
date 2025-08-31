// src/templates/blog/list.js 
import { renderTemplate } from '../base.js';
import { PostList, Pagination } from '../../../../lib.deadlight/core/src/components/posts/index.js';

const postList = new PostList({
  showActions: true,
  showAuthor: true,
  showDate: true
});

const pagination = new Pagination({
  baseUrl: '/'
});

export function renderPostList(posts = [], user = null, paginationData = null, config = null) {
  const postsHtml = postList.render(posts, { user });
  const paginationHtml = pagination.render(paginationData);

  return renderTemplate(
    'Blog Posts',
    `<div class="container">
      ${postsHtml}
      ${paginationHtml}
    </div>`,
    user,
    config
  );
}