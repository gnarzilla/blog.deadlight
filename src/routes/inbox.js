
// src/routes/inbox.js
import { renderTemplate } from '../templates/base.js';
import { MarkdownProcessor } from '../../../lib.deadlight/core/src/markdown/processor.js';
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { ConfigService } from '../services/config.js'; // Add this import

export const inboxRoutes = {
  '/inbox': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      // Get dynamic config
      const config = await env.services.config.getConfig();
      
      const page = parseInt(request.query?.page || '1');
      const limit = config.postsPerPage || 10; // Use dynamic posts per page
      
      // Fetch emails (posts with is_email = 1)
      const offset = (page - 1) * limit;
      const query = 'SELECT * FROM posts WHERE is_email = 1 ORDER BY created_at DESC LIMIT ? OFFSET ?';
      const countQuery = 'SELECT COUNT(*) as total FROM posts WHERE is_email = 1';
      const emailsResult = await env.DB.prepare(query).bind(limit, offset).all();
      const countResult = await env.DB.prepare(countQuery).first();
      const totalEmails = countResult.total;
      const totalPages = Math.ceil(totalEmails / limit);
      
      // Format emails for rendering with Markdown
      const processor = new MarkdownProcessor();
      const emails = emailsResult.results.map(email => {
        const metadata = email.email_metadata ? JSON.parse(email.email_metadata) : {};
        const excerpt = email.content.length > 200 ? email.content.substring(0, 200) + '...' : email.content;
        return {
          ...email,
          from: metadata.from || 'Unknown Sender',
          date: metadata.date || email.created_at,
          content: excerpt, // Show excerpt in list view
          full_content: processor.render(email.content) // Render full content for single view
        };
      });
      
      const emailList = emails.length > 0 
        ? emails.map(email => `
            <article class="email-preview">
              <h2><a href="/email/${email.id}">${escapeHtml(email.title)}</a></h2>
              <div class="email-meta">
                <strong>From:</strong> ${escapeHtml(email.from)} | <strong>Date:</strong> ${new Date(email.date).toLocaleString()}
              </div>
              <div class="email-excerpt">
                ${processor.render(email.content)}
              </div>
              <div class="email-footer">
                <a href="/email/${email.id}" class="read-more">Read Full Email →</a>
                ${user ? `
                  <div class="email-actions">
                    <a href="/inbox/reply/${email.id}" class="button reply-button">Reply</a>
                  </div>
                ` : ''}
              </div>
            </article>
          `).join('\n')
        : '<p>No emails in inbox.</p>';
      
      const pagination = {
        currentPage: page,
        totalPages,
        hasPrevious: page > 1,
        hasNext: page < totalPages,
        previousPage: page - 1,
        nextPage: page + 1,
        totalEmails
      };
      
      const paginationHtml = renderPagination(pagination, '/inbox');
      
      return new Response(
        renderTemplate(
          'Email Inbox',
          `<div class="container">
            <h1>Email Inbox</h1>
            ${emailList}
            ${paginationHtml}
          </div>`,
          user,
          config // Pass config here
        ),
        { headers: { 'Content-Type': 'text/html' } }
      );
    }
  },
  '/email/:id': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      // Get dynamic config
      const config = await env.services.config.getConfig();
      
      const emailId = request.params.id;
      const query = 'SELECT * FROM posts WHERE id = ? AND is_email = 1';
      const emailResult = await env.DB.prepare(query).bind(emailId).first();
      
      if (!emailResult) {
        return new Response(
          renderTemplate('Email Not Found', '<p>Email not found or access denied.</p>', user, config),
          { headers: { 'Content-Type': 'text/html' }, status: 404 }
        );
      }
      
      const metadata = emailResult.email_metadata ? JSON.parse(emailResult.email_metadata) : {};
      const processor = new MarkdownProcessor();
      const email = {
        ...emailResult,
        from: metadata.from || 'Unknown Sender',
        date: metadata.date || emailResult.created_at,
        content: processor.render(emailResult.content)
      };
      
      const emailDate = new Date(email.date).toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
      
      const content = `
        <article class="single-email">
          <header class="email-header">
            <h1>${escapeHtml(email.title)}</h1>
            <div class="email-meta">
              <span><strong>From:</strong> ${escapeHtml(email.from)}</span>
              <span class="separator">•</span>
              <time datetime="${email.date}">${emailDate}</time>
            </div>
          </header>
          <div class="email-content">
            ${email.content}
          </div>
          ${user ? `
            <div class="email-actions">
              <a href="/inbox/reply/${email.id}" class="button reply-button">Reply</a>
              <form class="delete-form" action="/inbox/delete/${email.id}" method="POST" 
                    onsubmit="return confirm('Are you sure you want to delete this email?');">
                <button type="submit" class="button delete-button">Delete</button>
              </form>
            </div>
          ` : ''}
          <nav class="email-navigation">
            <a href="/inbox" class="nav-back">← Back to Inbox</a>
          </nav>
        </article>
      `;
      
      return new Response(
        renderTemplate(email.title, `<div class="container">${content}</div>`, user, config),
        { headers: { 'Content-Type': 'text/html' } }
      );
    }
  },
  '/inbox/reply/:id': {
    GET: async (request, env) => {
        const user = await checkAuth(request, env);
        if (!user) {
          return Response.redirect(`${new URL(request.url).origin}/login`);
        }
        
        // Get dynamic config
        const config = await env.services.config.getConfig();
        
        const emailId = request.params.id;
        const query = 'SELECT * FROM posts WHERE id = ? AND is_email = 1';
        const emailResult = await env.DB.prepare(query).bind(emailId).first();
        
        if (!emailResult) {
          return new Response(
            renderTemplate('Email Not Found', '<p>Email not found or access denied.</p>', user, config),
            { headers: { 'Content-Type': 'text/html' }, status: 404 }
          );
        }
        
        const metadata = emailResult.email_metadata ? JSON.parse(emailResult.email_metadata) : {};
        const originalFrom = metadata.from || 'Unknown Sender';
        const originalSubject = emailResult.title || 'No Subject';
        const replyTo = originalFrom;
        const replySubject = originalSubject.startsWith('Re:') ? originalSubject : `Re: ${originalSubject}`;
        const quotedBody = `On ${new Date(metadata.date || emailResult.created_at).toLocaleString()}, ${originalFrom} wrote:\n> ${emailResult.content.split('\n').join('\n> ')}`;
        
        const content = `
        <div class="reply-form-container">
            <h1>Reply to ${escapeHtml(originalFrom)}</h1>
            <form action="/inbox/reply/${emailId}" method="POST" class="reply-form">
            <div class="form-group">
                <label for="to">To:</label>
                <input type="text" id="to" name="to" value="${escapeHtml(replyTo)}" readonly class="form-input readonly">
            </div>
            <div class="form-group">
                <label for="subject">Subject:</label>
                <input type="text" id="subject" name="subject" value="${escapeHtml(replySubject)}" class="form-input">
            </div>
            <div class="form-group">
                <label for="body">Your Reply:</label>
                <textarea id="body" name="body" rows="10" class="form-textarea" placeholder="Write your reply here...">\n\n${quotedBody}</textarea>
            </div>
            <div class="form-actions">
                <button type="submit" class="button send-button">Send Reply</button>
                <a href="/email/${emailId}" class="button cancel-button secondary">Cancel</a>
            </div>
            </form>
        </div>
        `;
        
        return new Response(
          renderTemplate('Compose Reply', `<div class="container">${content}</div>`, user, config),
          { headers: { 'Content-Type': 'text/html' } }
        );
    },
    POST: async (request, env) => {
        const user = await checkAuth(request, env);
        if (!user) {
          return Response.redirect(`${new URL(request.url).origin}/login`);
        }
        
        // Get dynamic config
        const config = await env.services.config.getConfig();
        
        const emailId = request.params.id;
        const query = 'SELECT * FROM posts WHERE id = ? AND is_email = 1';
        const emailResult = await env.DB.prepare(query).bind(emailId).first();
        
        if (!emailResult) {
          return new Response(
            renderTemplate('Email Not Found', '<p>Email not found or access denied.</p>', user, config),
            { headers: { 'Content-Type': 'text/html' }, status: 404 }
          );
        }
        
        const formData = await request.formData();
        const to = formData.get('to') || '';
        const subject = formData.get('subject') || 'Re: No Subject';
        const body = formData.get('body') || '';
        
        if (!to || !body) {
          return new Response(
            renderTemplate('Invalid Input', '<p>Recipient and reply body are required.</p><a href="/inbox/reply/' + emailId + '" class="button">Try Again</a>', user, config),
            { headers: { 'Content-Type': 'text/html' }, status: 400 }
          );
        }
        
        try {
          // Store the reply as a draft in the posts table with is_reply_draft = 1
          const replyMetadata = JSON.stringify({
            to: to,
            from: 'deadlight.boo@gmail.com', // Or user's email if available
            original_id: emailId,
            date_queued: new Date().toISOString(),
            sent: false
          });
          const insertQuery = `
            INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata, is_reply_draft)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `;
          await env.DB.prepare(insertQuery).bind(
            subject,
            body,
            `reply-draft-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`, // Unique slug
            user.id,
            new Date().toISOString(),
            new Date().toISOString(),
            0, // Not published
            0, // Not an incoming email
            replyMetadata,
            1  // Flag as reply draft
          ).run();
          
          const successMessage = `<p>Reply queued for sending to ${escapeHtml(to)}! It will be sent shortly.</p><a href="/email/${emailId}" class="button">Back to Email</a><a href="/inbox" class="button secondary">Back to Inbox</a>`;
          return new Response(
            renderTemplate('Reply Queued', successMessage, user, config),
            { headers: { 'Content-Type': 'text/html' } }
          );
        } catch (error) {
          console.error(`Failed to queue reply: ${error.message}`);
          const errorMessage = `<p>Failed to queue reply: ${escapeHtml(error.message)}</p><a href="/inbox/reply/${emailId}" class="button">Try Again</a>`;
          return new Response(
            renderTemplate('Queue Failed', errorMessage, user, config),
            { headers: { 'Content-Type': 'text/html' }, status: 500 }
          );
        }
    }
  }
};

function renderPagination(pagination, basePath = '/inbox') {
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
        <a href="${basePath}?page=1" class="pagination-link pagination-first" aria-label="First page">≪</a>
        <a href="${basePath}?page=${previousPage}" class="pagination-link pagination-prev" aria-label="Previous page">‹</a>
      ` : `
        <span class="pagination-link pagination-disabled">≪</span>
        <span class="pagination-link pagination-disabled">‹</span>
      `}
      
      ${startPage > 1 ? '<span class="pagination-ellipsis">...</span>' : ''}
      
      ${pageNumbers.map(num => 
        num === currentPage 
          ? `<span class="pagination-link pagination-current" aria-current="page">${num}</span>`
          : `<a href="${basePath}?page=${num}" class="pagination-link">${num}</a>`
      ).join('')}
      
      ${endPage < totalPages ? '<span class="pagination-ellipsis">...</span>' : ''}
      
      ${hasNext ? `
        <a href="${basePath}?page=${nextPage}" class="pagination-link pagination-next" aria-label="Next page">›</a>
        <a href="${basePath}?page=${totalPages}" class="pagination-link pagination-last" aria-label="Last page">≫</a>
      ` : `
        <span class="pagination-link pagination-disabled">›</span>
        <span class="pagination-link pagination-disabled">≫</span>
      `}
      
      <div class="pagination-info">Page ${currentPage} of ${totalPages}</div>
    </nav>
  `;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
