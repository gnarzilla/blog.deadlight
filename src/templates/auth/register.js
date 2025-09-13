// src/templates/auth/register.js
import { renderAuthTemplate } from './base.js';

export function renderRegistrationForm(config, error = null) {
  // Generate simple math captcha
  const num1 = Math.floor(Math.random() * 10) + 1;
  const num2 = Math.floor(Math.random() * 10) + 1;
  const captchaAnswer = num1 + num2;
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
                   pattern="^[a-zA-Z0-9_-]{3,20}$" 
                   title="3-20 characters, letters, numbers, underscore, and hyphen only"
                   maxlength="20">
            <small>Only letters, numbers, underscore, and hyphen allowed</small>
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
          
          <div class="form-group">
            <label for="captcha">Security Question: What is ${num1} + ${num2}?</label>
            <input type="number" id="captcha" name="captcha" required>
            <input type="hidden" name="captcha_hash" value="${btoa(captchaAnswer.toString())}">
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
