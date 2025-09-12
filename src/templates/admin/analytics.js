// src/templates/admin/analytics.js
import { renderTemplate } from '../base.js';

export function renderAnalyticsTemplate({ summary, topPaths, hourlyTraffic, countryStats, user, config=null }) {
  const maxRequests = Math.max(...hourlyTraffic.map(h => h.requests), 1);

  const content = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Analytics Dashboard</title>
      <link rel="stylesheet" href="/styles/theme.css">
    </head>
    <body>
      <div class="admin-dashboard">
        <div class="page-header">
          <h1>Analytics Dashboard</h1>
        </div>

        <!-- Summary Section -->
        <div class="analytics-summary">
          <div class="metric">
            <div class="metric-value">${summary?.total_requests || 0}</div>
            <div class="metric-label">Total Requests</div>
          </div>
          <div class="metric">
            <div class="metric-value">${summary?.unique_visitors || 0}</div>
            <div class="metric-label">Unique Visitors</div>
          </div>
          <div class="metric">
            <div class="metric-value">${Math.round(summary?.avg_duration || 0)}ms</div>
            <div class="metric-label">Avg Response Time</div>
          </div>
          <div class="metric">
            <div class="metric-value">
              ${summary?.total_requests
                ? Math.round((summary.error_count / summary.total_requests) * 100)
                : 0}%
            </div>
            <div class="metric-label">Error Rate</div>
          </div>
        </div>

        <!-- Traffic Chart -->
        <div class="chart-section">
          <h2>Traffic by Hour (Last 24h)</h2>
          <div class="simple-chart">
            ${hourlyTraffic.map(hour => `
              <div class="chart-bar" style="--height:${(hour.requests / maxRequests) * 100}%">
                <div class="bar"></div>
                <div class="value">${hour.requests}</div>
                <div class="label">${hour.hour}:00</div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Top Pages -->
        <div class="chart-section">
          <h2>Top Pages</h2>
          <table class="data-table">
            <thead>
              <tr>
                <th>Path</th>
                <th>Hits</th>
                <th>Visitors</th>
                <th>Avg Time</th>
              </tr>
            </thead>
            <tbody>
              ${topPaths.map(path => `
                <tr>
                  <td>${path.path}</td>
                  <td>${path.hit_count}</td>
                  <td>${path.unique_visitors}</td>
                  <td>${Math.round(path.avg_duration)}ms</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <!-- Top Countries -->
        <div class="chart-section">
          <h2>Top Countries</h2>
          <table class="data-table">
            <thead>
              <tr>
                <th>Country</th>
                <th>Requests</th>
                <th>Visitors</th>
              </tr>
            </thead>
            <tbody>
              ${countryStats.map(country => `
                <tr>
                  <td>${country.country}</td>
                  <td>${country.requests}</td>
                  <td>${country.unique_visitors}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <!-- Back link -->
        <a href="/admin" class="analytics-back">Back to Admin Dashboard</a>
      </div>
    </body>
    </html>
  `;
  return renderTemplate('Analytics', content, user, config);
}
