// src/utils/markdown.js
import { marked } from 'marked';
import { filterXSS } from 'xss';

// Configure marked options
marked.setOptions({
  gfm: true,  // GitHub Flavored Markdown
  breaks: true,  // Convert \n to <br>
  headerIds: false,  // Don't add ids to headers
  mangle: false  // Don't escape HTML
});

// Custom renderer to handle different elements
const renderer = new marked.Renderer();

// Custom code block rendering
renderer.code = (code, language) => {
  return `<pre><code class="language-${language}">${filterXSS(code)}</code></pre>`;
};

// Custom link rendering
renderer.link = (href, title, text) => {
  if (href === null) {
    return text;
  }
  return `<a href="${filterXSS(href)}"${title ? ` title="${filterXSS(title)}"` : ''}>${text}</a>`;
};

export function renderMarkdown(content) {
  try {
    // Set the custom renderer
    marked.use({ renderer });
    
    // Convert markdown to HTML and sanitize
    const html = marked(content);
    return filterXSS(html, {
      whiteList: {
        h1: [], h2: [], h3: [], h4: [], h5: [], h6: [],
        p: [], br: [], hr: [],
        a: ['href', 'title', 'target'],
        strong: [], em: [], del: [],
        ul: [], ol: [], li: [],
        code: ['class'], pre: [],
        blockquote: [],
        table: [], thead: [], tbody: [], tr: [], th: [], td: []
      }
    });
  } catch (error) {
    console.error('Markdown rendering error:', error);
    return content; // Return original content if rendering fails
  }
}
