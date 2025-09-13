// src/templates/user/settings.js
import { renderTemplate } from '../base.js';

export function renderUserSettings(user, additionalSettings, config, error = null) {
  const content = `
    <div class="user-settings">
      <h1>Profile Settings</h1>
      
      ${error ? `<div class="error-message">${error}</div>` : ''}
      
      <form method="POST" class="settings-form">
        <fieldset>
          <legend>Profile Information</legend>
          
          <div class="form-group">
            <label for="profile_title">Profile Title</label>
            <input type="text" id="profile_title" name="profile_title" 
                   value="${user.profile_title || ''}"
                   placeholder="${user.username}'s Posts">
            <small>This appears at the top of your profile page</small>
          </div>
          
          <div class="form-group">
            <label for="profile_description">Profile Description (Markdown)</label>
            <textarea id="profile_description" name="profile_description" 
                      rows="5"
                      placeholder="Tell visitors about yourself...">${user.profile_description || ''}</textarea>
            <small>You can use Markdown formatting</small>
          </div>
          
          <div class="form-group">
            <label for="email">Email (optional)</label>
            <input type="email" id="email" name="email" 
                   value="${user.email || ''}">
            <small>Not publicly visible</small>
          </div>
        </fieldset>
        
        <fieldset>
          <legend>Change Password</legend>
          <p class="form-help">Leave blank to keep current password</p>
          
          <div class="form-group">
            <label for="new_password">New Password</label>
            <input type="password" id="new_password" name="new_password" 
                   minlength="8">
          </div>
          
          <div class="form-group">
            <label for="confirm_password">Confirm New Password</label>
            <input type="password" id="confirm_password" name="confirm_password">
          </div>
        </fieldset>
        
        <div class="form-actions">
          <button type="submit" class="button primary">Save Changes</button>
          <a href="/user/${user.username}" class="button secondary">Cancel</a>
        </div>
      </form>
      
      <div class="danger-zone">
        <h3>Account Info</h3>
        <p>Member since: ${new Date(user.created_at).toLocaleDateString()}</p>
        <p>Username: <strong>${user.username}</strong></p>
        <p>Role: <strong>${user.role || 'user'}</strong></p>
      </div>
    </div>
  `;
  
  return renderTemplate('Profile Settings', content, user, config);
}
