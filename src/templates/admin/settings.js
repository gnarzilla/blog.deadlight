// src/templates/admin/settings.js - Updated with proper checkbox styling
import { renderTemplate } from '../base.js';

export function renderSettings(settings, user, config = null) {
  const content = `
    <div class="settings-page">
      <h1>Site Settings</h1>
      
      <form method="POST" action="/admin/settings" class="settings-form">
        <div class="settings-grid">
          <div class="setting-group">
            <h3>General Settings</h3>
            
            <div class="setting-item">
              <label for="site_title">Site Title</label>
              <input type="text" id="site_title" name="site_title" 
                     value="${settings.site_title || ''}" required>
              <small>The name of your site, shown in header and page titles</small>
            </div>
            
            <div class="setting-item">
              <label for="site_description">Site Description</label>
              <textarea id="site_description" name="site_description" rows="3">${settings.site_description || ''}</textarea>
              <small>Brief description for SEO and social sharing</small>
            </div>
          </div>

          <div class="setting-group">
            <h3>Display Settings</h3>
            
            <div class="setting-item">
              <label for="posts_per_page">Posts Per Page</label>
              <input type="number" id="posts_per_page" name="posts_per_page" 
                     value="${settings.posts_per_page || 10}" min="1" max="50">
              <small>How many posts to show on the home page</small>
            </div>
            
            <div class="setting-item">
              <label for="date_format">Date Format</label>
              <select id="date_format" name="date_format">
                <option value="M/D/YYYY" ${settings.date_format === 'M/D/YYYY' ? 'selected' : ''}>M/D/YYYY (12/25/2024)</option>
                <option value="D/M/YYYY" ${settings.date_format === 'D/M/YYYY' ? 'selected' : ''}>D/M/YYYY (25/12/2024)</option>
                <option value="YYYY-MM-DD" ${settings.date_format === 'YYYY-MM-DD' ? 'selected' : ''}>YYYY-MM-DD (2024-12-25)</option>
                <option value="MMM D, YYYY" ${settings.date_format === 'MMM D, YYYY' ? 'selected' : ''}>MMM D, YYYY (Dec 25, 2024)</option>
              </select>
            </div>
            
            <div class="setting-item">
              <label for="timezone">Timezone</label>
              <input type="text" id="timezone" name="timezone" 
                     value="${settings.timezone || 'UTC'}" placeholder="UTC">
              <small>Timezone for post timestamps</small>
            </div>
          </div>

          <div class="setting-group">
            <h3>Access Control</h3>
            
          <div class="checkbox-group">
            <label class="checkbox-label">
              <input type="checkbox" name="enable_registration" ${settings.enable_registration ? 'checked' : ''}>
              <span>Enable User Registration</span>
            </label>
            <small>Allow visitors to create new accounts (currently placeholder)</small>
          </div>
            
            <div class="checkbox-group">
              <label class="checkbox-label">
                <input type="checkbox" name="require_login_to_read" 
                       ${settings.require_login_to_read ? 'checked' : ''}>
                <span>Require Login to Read Posts</span>
              </label>
            </div>
            
            <div class="checkbox-group">
              <label class="checkbox-label">
                <input type="checkbox" name="maintenance_mode" 
                       ${settings.maintenance_mode ? 'checked' : ''}>
                <span>Maintenance Mode</span>
              </label>
            </div>
          </div>
        </div>

        <div class="form-actions">
          <button type="submit" class="button primary">Save Settings</button>
          <a href="/admin" class="button secondary">Cancel</a>
        </div>
      </form>
    </div>
  `;

  return renderTemplate('Settings', content, user, config);
}