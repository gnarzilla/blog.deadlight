// src/templates/blog/list.js 
import { renderTemplate } from '../base.js';
import { renderMarkdown } from '../../../../lib.deadlight/core/src/markdown/processor.js';
import { PostList, Pagination } from '../../../../lib.deadlight/core/src/components/posts/index.js';
import { defaultProcessor } from '../../../../lib.deadlight/core/src/markdown/processor.js';

const postList = new PostList({
  showActions: true,
  showAuthor: true,
  showDate: true
});

const pagination = new Pagination({
  baseUrl: '/'
});

function createExcerpt(content, maxLength = 300) {
  // Check for manual excerpt marker
  const moreIndex = content.indexOf('<!--more-->');
  if (moreIndex !== -1) {
    // Process the excerpt portion through markdown, then return
    const excerptContent = content.substring(0, moreIndex).trim();
    return defaultProcessor.render(excerptContent);
  }
  
  // For automatic excerpts, we need to be more careful
  // First, let's extract the excerpt text, then process it
  const plainText = content
    .replace(/#{1,6}\s/g, '') // Remove headers
    .replace(/\*\*(.+?)\*\*/g, '$1') // Remove bold
    .replace(/\*(.+?)\*/g, '$1') // Remove italic
    .replace(/$$([^$$]+)\]$[^)]+$/g, '$1') // Remove links (fixed regex)
    .replace(/```[\s\S]*?```/g, '') // Remove code blocks
    .replace(/`(.+?)`/g, '$1') // Remove inline code
    .replace(/\n{2,}/g, ' ') // Replace multiple newlines with space
    .replace(/\n/g, ' ') // Replace single newlines with space
    .trim();
  
  let excerptText;
  if (plainText.length <= maxLength) {
    excerptText = plainText;
  } else {
    // Cut at last complete word
    const excerpt = plainText.substring(0, maxLength);
    const lastSpace = excerpt.lastIndexOf(' ');
    excerptText = excerpt.substring(0, lastSpace) + '...';
  }
  
  // Now process the excerpt through markdown (this handles things like lists, emphasis, etc.)
  return defaultProcessor.render(excerptText);
}

// Ccreate a proper markdown excerpt function
function createMarkdownExcerpt(content, maxLength = 300) {
  // Check for manual excerpt marker
  const moreIndex = content.indexOf('<!--more-->');
  if (moreIndex !== -1) {
    const excerptContent = content.substring(0, moreIndex).trim();
    return defaultProcessor.render(excerptContent);
  }
  
  // For automatic excerpts, we need to render first, then truncate
  const fullHtml = defaultProcessor.render(content);
  
  // Convert HTML back to text for length checking
  const textContent = fullHtml
    .replace(/<[^>]*>/g, '') // Strip HTML tags
    .replace(/&[^;]+;/g, ' ') // Replace HTML entities with space
    .trim();
  
  if (textContent.length <= maxLength) {
    return fullHtml;
  }
  
  // If too long, we need to truncate the markdown before processing
  // This is trickier, so let's find a good breaking point in the original content
  let truncateAt = maxLength;
  
  // Try to find a paragraph break near our target length
  const paragraphs = content.split('\n\n');
  let currentLength = 0;
  let excerptParagraphs = [];
  
  for (const paragraph of paragraphs) {
    if (currentLength + paragraph.length > maxLength && excerptParagraphs.length > 0) {
      break;
    }
    excerptParagraphs.push(paragraph);
    currentLength += paragraph.length;
  }
  
  const excerptContent = excerptParagraphs.join('\n\n') + '...';
  return defaultProcessor.render(excerptContent);
}

export function renderPostList(posts = [], user = null, paginationData = null, config = null) {
  // Process posts to add rendered excerpts
  const postsWithExcerpts = posts.map(post => ({
    ...post,
    excerpt: createMarkdownExcerpt(post.content || '', 300)
  }));
  
  const postsHtml = postList.render(postsWithExcerpts, { user });
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

function renderPagination(pagination) {
  if (!pagination || pagination.totalPages <= 1) {
    return '';
  }

  const { currentPage, totalPages, hasPrevious, hasNext, previousPage, nextPage } = pagination;
  
  // Generate page numbers
  const pageNumbers = [];
  const maxPagesToShow = 5;
  let startPage = Math.max(1, currentPage - Math.floor(maxPagesToShow / 2));
  let endPage = Math.min(totalPages, startPage + maxPagesToShow - 1);
  
  if (endPage - startPage < maxPagesToShow - 1) {
    startPage = Math.max(1, endPage - maxPagesToShow + 1);
  }
  
  for (let i = startPage; i <= endPage; i++) {
    pageNumbers.push(i);
  }

  return `
    <nav class="pagination" aria-label="Pagination Navigation">
      ${hasPrevious ? `
        <a href="/?page=1" class="pagination-link pagination-first" aria-label="First page">≪</a>
        <a href="/?page=${previousPage}" class="pagination-link pagination-prev" aria-label="Previous page">‹</a>
      ` : `
        <span class="pagination-link pagination-disabled">≪</span>
        <span class="pagination-link pagination-disabled">‹</span>
      `}
      
      ${startPage > 1 ? '<span class="pagination-ellipsis">...</span>' : ''}
      
      ${pageNumbers.map(num => 
        num === currentPage 
          ? `<span class="pagination-link pagination-current" aria-current="page">${num}</span>`
          : `<a href="/?page=${num}" class="pagination-link">${num}</a>`
      ).join('')}
      
      ${endPage < totalPages ? '<span class="pagination-ellipsis">...</span>' : ''}
      
      ${hasNext ? `
        <a href="/?page=${nextPage}" class="pagination-link pagination-next" aria-label="Next page">›</a>
        <a href="/?page=${totalPages}" class="pagination-link pagination-last" aria-label="Last page">≫</a>
      ` : `
        <span class="pagination-link pagination-disabled">›</span>
        <span class="pagination-link pagination-disabled">≫</span>
      `}
      
      <div class="pagination-info">Page ${currentPage} of ${totalPages}</div>
    </nav>
  `;
}
