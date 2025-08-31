// utils/excerpt.js
// Build an excerpt from Markdown while preserving paragraph breaks.
export function makeExcerpt(md, opts = {}) {
  const { maxChars = 600, maxWords = 120, maxParas = 2, ellipsis = '…' } = opts;
  if (!md) return '';

  // Honor explicit "more" tag (supports <!--more--> and <--!more-->)
  const moreRE = /<!--\s*more\s*-->|<\-\-!more\-\->/i;
  const cut = md.search(moreRE);
  const slice = cut >= 0 ? md.slice(0, cut) : md;

  // Strip markup, keep structure
  const normalized = slice
    .replace(/\r\n?/g, '\n')
    .replace(/```([\s\S]*?)```/g, (_, code) => `\n${code.trim()}\n`)
    .replace(/!\[([^\]]*)]\([^)]+(?:\s"[^"]*")?\)/g, '$1')   // images → alt
    .replace(/\[([^\]]+)]\((?:[^)]+)\)/g, '$1')              // links → text
    .replace(/^\s{0,3}(?:>+|\#{1,6})\s?/gm, '')              // quotes/headings
    .replace(/^\s{0,3}(?:[-*+]\s|\d+\.\s)/gm, '• ')          // lists
    .replace(/(\*\*|__|\*|_|~~|`)/g, '')                     // bold/italic/etc
    .replace(/^\s*([-*_]\s?){3,}\s*$/gm, '')                 // hr
    .replace(/\n{3,}/g, '\n\n')                              // keep blank lines
    .trim();

  const paras = normalized.split(/\n{2,}/);
  let out = [], words = 0, chars = 0;
  for (const p of paras) {
    const w = p.trim().split(/\s+/).filter(Boolean).length;
    if (out.length >= maxParas || words + w > maxWords || chars + p.length > maxChars) break;
    out.push(p); words += w; chars += p.length;
  }

  let excerpt = out.join('\n\n');
  if (excerpt.length > maxChars) excerpt = excerpt.slice(0, maxChars).replace(/\s+\S*$/, '');

  // Return HTML that actually renders the blank line(s)
  return excerpt.split(/\n{2,}/).map(p => `<p>${escapeHtml(p)}</p>`).join('') +
         ((cut >= 0 || out.length < paras.length) ? `<span class="ellipsis">…</span>` : '');
}

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
          .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
