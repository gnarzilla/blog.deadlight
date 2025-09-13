// src/templates/user/profile.js
import { renderTemplate } from '../base.js';
import { renderMarkdown } from '../../../../lib.deadlight/core/src/markdown/processor.js';

export function renderUserProfile(user, posts, currentUser, config, pagination) {
  // Create excerpt from content if no excerpt exists
  function createExcerpt(content, maxLength = 200) {
    const plainText = content.replace(/[#*`$$$$]/g, '').trim();
    return plainText.length > maxLength 
      ? plainText.substring(0, maxLength) + '...'
      : plainText;
  }

  const pageTitle = user.profile_title || `${user.username}'s Posts`;
  
  const content = `
    <div class="user-profile">
      <header class="profile-header">
        <div class="profile-info">
          <h1>${pageTitle}</h1>
          <p class="username">@${user.username}</p>
          ${user.profile_description ? `
            <div class="profile-description">
              ${renderMarkdown(user.profile_description)}
            </div>
          ` : ''}
          <div class="profile-stats">
            <span>${user.post_count} post${user.post_count !== 1 ? 's' : ''}</span>
            ${user.last_post_date ? `
              <span>•</span>
              <span>Last post ${new Date(user.last_post_date).toLocaleDateString()}</span>
            ` : ''}
          </div>
        </div>
        
        ${currentUser && currentUser.id === user.id ? `
          <div class="profile-actions">

            <a href="/user/${user.username}/new-post" class="button">Write Post</a>
            <a href="/user/${user.username}/settings" class="button secondary">Edit Profile</a>
          </div>
        ` : ''}
      </header>
      <div class="posts-section">
        <h2>Posts</h2>
        ${posts && posts.length > 0 ? `
          <div class="post-list">
            ${posts.map(post => `
              <article class="post-preview">
                <header class="post-header">
                  <h3><a href="/post/${post.slug || post.id}">${post.title}</a></h3>
                  <time class="post-date" datetime="${post.created_at}">
                    ${new Date(post.created_at).toLocaleDateString()}
                  </time>
                </header>
                <div class="post-excerpt">
                  ${post.excerpt ? renderMarkdown(post.excerpt) : `
                    <p>${createExcerpt(post.content)}</p>
                  `}
                </div>
                <footer class="post-footer">
                  <a href="/post/${post.slug || post.id}" class="read-more">Read more →</a>
                </footer>
              </article>
            `).join('')}
          </div>
          
          ${pagination.totalPages > 1 ? `
            <nav class="pagination">
              ${pagination.hasPrevious ? `
                <a href="/user/${user.username}?page=${pagination.previousPage}" class="button secondary">← Previous</a>
              ` : ''}
              
              <span class="page-info">
                Page ${pagination.currentPage} of ${pagination.totalPages}
              </span>
              
              ${pagination.hasNext ? `
                <a href="/user/${user.username}?page=${pagination.nextPage}" class="button secondary">Next →</a>
              ` : ''}
            </nav>
          ` : ''}
        ` : `
          <div class="empty-state">
            <p>${user.username} hasn't posted anything yet.</p>
              ${currentUser && currentUser.id === user.id ? `
                <a href="/user/${user.username}/new-post" class="button">Write your first post</a>
              ` : ''}
          </div>
        `}
      </div>
    </div>
  `;

  return renderTemplate(pageTitle, content, currentUser, config);
}
