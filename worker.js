/**
 * CloudPress CMS — Worker Entry Point
 *
 * Cloudflare Workers requires a default export with fetch (and optionally
 * scheduled) handlers. This file is the true entry point declared in
 * wrangler.toml (`main = "worker.js"`).
 *
 * @package CloudPress
 */

import { route }           from './cp-router.js';
import { handleScheduled } from './cp-cron.js';

export default {
  /**
   * Handle HTTP requests.
   */
  async fetch(request, env, ctx) {
    return route(request, env, ctx);
  },

  /**
   * Handle Cloudflare Cron Triggers.
   */
  async scheduled(event, env, ctx) {
    return handleScheduled(event, env, ctx);
  },
};
