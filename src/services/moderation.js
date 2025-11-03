// src/services/moderation.js
export class ModerationService {
  constructor(configService) {
    this.config = configService;
  }

  async check(content) {
    const kw = await this.config.getModerationKeywords();
    const lower = content.toLowerCase();
    const matched = kw.filter(w => lower.includes(w));
    return matched.length
      ? { status: 'pending', notes: `Flagged: ${matched.join(', ')}` }
      : { status: 'approved', notes: null };
  }

  async setKeywords(list) {
    await this.config.updateSetting('moderation_keywords', list.join(','));
  }
}