// src/utils/templates.js
export function renderAuthorLink(username) {
  return `<a href="/user/${username}" class="author-link">${username}</a>`;
}