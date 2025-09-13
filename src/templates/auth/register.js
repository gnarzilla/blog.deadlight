// src/templates/auth/register.js
import { renderAuthTemplate } from './base.js';

export function renderRegistrationForm(config, error = null) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Register - ${config.title}</title>
      <link rel="stylesheet" href="/styles/theme.css">
    </head>
    <body>
      <div class="auth-container">
        <h1>Create Account</h1>
        
        ${error ? `<div class="error-message">${error}</div>` : ''}
        
        <form method="POST" action="/register">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required 
                   pattern="[a-zA-Z0-9_-]+" 
                   title="Letters, numbers, underscore, and hyphen only">
          </div>
          
          <div class="form-group">
            <label for="email">Email (optional)</label>
            <input type="email" id="email" name="email">
          </div>
          
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required 
                   minlength="8">
          </div>
          
          <div class="form-group">
            <label for="confirmPassword">Confirm Password</label>
            <input type="password" id="confirmPassword" name="confirmPassword" required>
          </div>
          
          <button type="submit" class="button">Register</button>
        </form>
        
        <p class="auth-links">
          Already have an account? <a href="/login">Login</a>
        </p>
      </div>
    </body>
    </html>
  `;
  return renderAuthTemplate('Register', content);
}
