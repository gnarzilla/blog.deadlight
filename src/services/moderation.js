export async function loadModerationKeywords(DB) {
  const raw = await DB.prepare(`
    SELECT value FROM settings WHERE key = 'moderation_keywords'
  `).first();

  if (!raw?.value) return [];

  return raw.value
    .split(',')
    .map(k => k.trim().toLowerCase())
    .filter(k => k.length > 0);
}

export function checkModeration(content, keywords) {
  const lower = content.toLowerCase();
  const matched = keywords.filter(word => lower.includes(word));

  if (matched.length === 0) {
    return { status: 'approved', notes: null };
  }

  return {
    status: 'pending',
    notes: `Flagged for keywords: ${matched.join(', ')}`
  };
}
