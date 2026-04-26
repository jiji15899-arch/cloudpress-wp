import { ok } from '../_shared.js';
import { getLiveVersions, getLiveRegions } from '../_versions.js';

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  if (url.searchParams.get('type') === 'regions') {
    return ok({ regions: getLiveRegions() });
  }
  const versions = await getLiveVersions();
  return ok(versions);
}
