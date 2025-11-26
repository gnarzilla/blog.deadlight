// src/templates/blog/list.js 
import { renderTemplate } from '../base.js';
import { PostList, Pagination } from '../../../../lib.deadlight/core/src/components/posts/index.js';

const postList = new PostList({
  showActions: true,
  showAuthor: true,
  showDate: true,
  showKarma: true  // Add karma display
});

const pagination = new Pagination({
  baseUrl: '/'
});

export function renderPostList(posts = [], user = null, paginationData = null, config = null) {
  // Add sort controls HTML
  const currentSort = paginationData?.currentSort || 'newest';
  const sortControls = `
    <div class="sort-controls">
      <label for="sort-select">Sort by:</label>
      <select id="sort-select" onchange="window.location.href='?sort=' + this.value">
        <option value="newest" ${currentSort === 'newest' ? 'selected' : ''}>Newest</option>
        <option value="oldest" ${currentSort === 'oldest' ? 'selected' : ''}>Oldest</option>
        <option value="karma" ${currentSort === 'karma' ? 'selected' : ''}>Most Popular</option>
        <option value="discussed" ${currentSort === 'discussed' ? 'selected' : ''}>Most Discussed</option>
      </select>
    </div>
  `;

  // Use existing render method with proper options
  const postsHtml = postList.render(posts, { user, baseUrl: '' });
  
  // Update pagination to preserve sort parameter
  const paginationHtml = pagination.render({
    ...paginationData,
    extraParams: `sort=${currentSort}`
  });

  return renderTemplate(
    'Blog Posts',
    `<div class="container">
      ${sortControls}
      ${postsHtml}
      ${paginationHtml}
    </div>`,
    user,
    config
  );
}