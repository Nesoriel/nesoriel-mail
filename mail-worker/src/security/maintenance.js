import { Hono } from 'hono';
import { verifyWithJwks } from 'hono/jwt';
import { dbInit } from '../init/init';

const maintenancePath = '/api/maintenance/init';
const maintenanceApp = new Hono();
const privateHeaders = { 'Cache-Control': 'no-store' };

maintenanceApp.use('*', async (c, next) => {
	c.header('Cache-Control', 'no-store');
	await next();
});

maintenanceApp.onError((err, c) => c.text('Maintenance initialization failed', 500));

maintenanceApp.post(maintenancePath, async (c) => {
	const { access_team_domain, access_aud, access_client_id } = c.env;
	if (!/^https:\/\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.cloudflareaccess\.com$/.test(access_team_domain || '') ||
		!access_aud || !access_client_id) {
		return c.text('Maintenance configuration incomplete', 503);
	}

	const assertion = c.req.header('Cf-Access-Jwt-Assertion');
	if (!assertion) {
		return c.text('Forbidden', 403);
	}

	try {
		const payload = await verifyWithJwks(assertion, {
			jwks_uri: `${access_team_domain}/cdn-cgi/access/certs`,
			allowedAlgorithms: ['RS256'],
			verification: { iss: access_team_domain, aud: access_aud },
		}, { redirect: 'error', signal: AbortSignal.timeout(5000) });

		if (payload.type !== 'app' || payload.common_name !== access_client_id ||
			!Number.isSafeInteger(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) {
			return c.text('Forbidden', 403);
		}
	} catch {
		// JWT errors can contain the assertion. Never log them or return them to clients.
		return c.text('Forbidden', 403);
	}

	const secret = c.req.header('X-Init-Secret');
	if (!c.env.jwt_secret || secret !== c.env.jwt_secret) {
		return c.text('Unauthorized', 401);
	}

	return dbInit.init(c, secret);
});

// Return null only for ordinary public traffic. Every workers.dev URL is closed
// before API, attachment, or static-asset routing, including version URLs.
export async function routeMaintenance(req, env, ctx) {
	const url = new URL(req.url);
	const hostname = url.hostname.toLowerCase().replace(/\.+$/, '');
	const workersDev = hostname === 'workers.dev' || hostname.endsWith('.workers.dev');
	const maintenanceNamespace = url.pathname === '/api/maintenance' ||
		url.pathname.startsWith('/api/maintenance/');
	if (!workersDev && !maintenanceNamespace) {
		return null;
	}

	if (!workersDev || env.maintenance_enabled !== 'true' ||
		!/^([a-z0-9][a-z0-9-]*)\.([a-z0-9][a-z0-9-]*)\.workers\.dev$/.test(env.maintenance_host || '') ||
		hostname !== env.maintenance_host || url.protocol !== 'https:' || url.port ||
		url.pathname !== maintenancePath || url.search || req.method !== 'POST') {
		return new Response('Not found', { status: 404, headers: privateHeaders });
	}

	return maintenanceApp.fetch(req, env, ctx);
}
