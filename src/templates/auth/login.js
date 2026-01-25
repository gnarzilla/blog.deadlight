// src/templates/auth/login.js
import { renderAuthTemplate } from './base.js';

export function renderLoginForm(data = {}) {
  const { error, validationErrors, username = '', csrfToken = '', allowRegistration = true } = data;
  
  // Build error display
  let errorHtml = '';
  if (error) {
    errorHtml = `<div class="error-message">${error}</div>`;
  } else if (validationErrors) {
    const errorMessages = Object.values(validationErrors).join('<br>');
    errorHtml = `<div class="error-message">${errorMessages}</div>`;
  }
  
  const content = `
    <div class="auth-container">
      ${errorHtml}
      <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="${csrfToken}">
        <input 
          type="text" 
          name="username" 
          placeholder="Username" 
          value="${username}"
          required
          minlength="3"
          maxlength="20"
          pattern="[a-zA-Z0-9_-]+"
          title="Username can only contain letters, numbers, underscores, and hyphens"
        >
        <input 
          type="password" 
          name="password" 
          placeholder="Password" 
          required
          minlength="8"
        >
        <button type="submit">Login</button>
      </form>

      ${allowRegistration ? `
        <div class="auth-footer">
          <p>Don't have an account? <a href="/register">Register</a></p>
        </div>
      ` : ''}
  `;
  
  return renderAuthTemplate('Login', content);
}