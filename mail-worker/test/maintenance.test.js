import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { sign } from 'hono/jwt';

const mocks = vi.hoisted(() => ({
	init: vi.fn(async (c) => c.text('success')),
	api: vi.fn(async () => new Response('public api')),
	objects: vi.fn(async () => new Response('public object')),
	email: vi.fn(),
}));

vi.mock('../src/init/init', () => ({ dbInit: { init: mocks.init } }));
vi.mock('../src/hono/webs', () => ({ default: { fetch: mocks.api } }));
vi.mock('../src/email/email', () => ({ email: mocks.email }));
vi.mock('../src/service/kv-obj-service', () => ({ default: { toObjResp: mocks.objects } }));
vi.mock('../src/service/user-service', () => ({ default: {} }));
vi.mock('../src/service/verify-record-service', () => ({ default: {} }));
vi.mock('../src/service/email-service', () => ({ default: {} }));
vi.mock('../src/service/oauth-service', () => ({ default: {} }));
vi.mock('../src/service/analysis-service', () => ({ default: {} }));

import worker from '../src/index';

const host = 'nesoriel-mail.yangyus8.workers.dev';
const issuer = 'maintenance-test.cloudflareaccess.com';
const path = '/api/maintenance/init';
const clientId = 'test-service-token.access';
let privateKey;
let publicKey;
let env;
let jwksFetch;

beforeAll(async () => {
	const keys = await crypto.subtle.generateKey({
		name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
		publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
	}, true, ['sign', 'verify']);
	privateKey = { ...await crypto.subtle.exportKey('jwk', keys.privateKey), kid: 'test-key', alg: 'RS256' };
	publicKey = { ...await crypto.subtle.exportKey('jwk', keys.publicKey), kid: 'test-key', alg: 'RS256' };
});

beforeEach(() => {
	vi.clearAllMocks();
	env = {
		maintenance_enabled: 'true',
		maintenance_host: host,
		access_team_domain: `https://${issuer}`,
		access_aud: 'maintenance-audience',
		access_client_id: clientId,
		jwt_secret: 'test-app-secret',
		db: { prepare: vi.fn(), batch: vi.fn() },
		kv: { get: vi.fn(), put: vi.fn() },
		assets: { fetch: vi.fn(async () => new Response('public assets')) },
	};
	jwksFetch = vi.fn(async () => Response.json({ keys: [publicKey] }));
	vi.stubGlobal('fetch', jwksFetch);
});

afterEach(() => vi.unstubAllGlobals());

async function assertion(claims = {}, key = privateKey) {
	const now = Math.floor(Date.now() / 1000);
	return sign({
		type: 'app', iss: `https://${issuer}`, aud: [env.access_aud],
		common_name: clientId, iat: now - 5, exp: now + 300,
		...claims,
	}, key, key.alg);
}

async function request({ url = `https://${host}${path}`, method = 'POST', token, secret = env.jwt_secret } = {}) {
	const headers = {};
	if (token !== undefined) headers['Cf-Access-Jwt-Assertion'] = token;
	if (secret !== undefined) headers['X-Init-Secret'] = secret;
	return worker.fetch(new Request(url, { method, headers }), env, {});
}

function expectNoApplicationAccess() {
	expect(mocks.init).not.toHaveBeenCalled();
	expect(mocks.api).not.toHaveBeenCalled();
	expect(mocks.objects).not.toHaveBeenCalled();
	expect(env.assets.fetch).not.toHaveBeenCalled();
	expect(env.db.prepare).not.toHaveBeenCalled();
	expect(env.db.batch).not.toHaveBeenCalled();
	expect(env.kv.get).not.toHaveBeenCalled();
	expect(env.kv.put).not.toHaveBeenCalled();
}

describe('maintenance ingress routing', () => {
	it.each([
		['public maintenance endpoint', `https://mail.nesoriel.com${path}`, 'POST'],
		['public namespace', 'https://mail.nesoriel.com/api/maintenance/other', 'POST'],
		['preview hostname', `https://abc123-${host}${path}`, 'POST'],
		['another worker', 'https://another.yangyus8.workers.dev/api/maintenance/init', 'POST'],
		['homepage', `https://${host}/`, 'POST'],
		['API route', `https://${host}/api/login`, 'POST'],
		['legacy init', `https://${host}/api/init/test-app-secret`, 'GET'],
		['static assets', `https://${host}/static/a.png`, 'GET'],
		['attachments', `https://${host}/attachments/a.bin`, 'GET'],
		['asset binding', `https://${host}/index.html`, 'GET'],
		['trailing slash', `https://${host}${path}/`, 'POST'],
		['extra path', `https://${host}${path}/extra`, 'POST'],
		['encoded path', `https://${host}/api/maintenance/%69nit`, 'POST'],
		['query string', `https://${host}${path}?secret=unused`, 'POST'],
		['HTTP scheme', `http://${host}${path}`, 'POST'],
		['nonstandard port', `https://${host}:444${path}`, 'POST'],
		['GET', `https://${host}${path}`, 'GET'],
		['HEAD', `https://${host}${path}`, 'HEAD'],
		['OPTIONS', `https://${host}${path}`, 'OPTIONS'],
		['PUT', `https://${host}${path}`, 'PUT'],
		['trailing-dot static', `https://${host}./static/a.png`, 'GET'],
		['trailing-dot preview', `https://abc123-${host}.${path}`, 'POST'],
	])('blocks %s before any application access', async (_, url, method) => {
		const response = await request({ url, method, token: await assertion() });
		expect(response.status).toBe(404);
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(jwksFetch).not.toHaveBeenCalled();
		expectNoApplicationAccess();
	});

	it.each([undefined, '', 'false', true])('closes ingress when enable latch is %s', async (enabled) => {
		env.maintenance_enabled = enabled;
		expect((await request({ token: await assertion() })).status).toBe(404);
		expectNoApplicationAccess();
	});

	it.each([undefined, '', 'mail.nesoriel.com', `https://${host}`, `other.yangyus8.workers.dev`])(
		'closes ingress with invalid or nonmatching maintenance host %s', async (configuredHost) => {
			env.maintenance_host = configuredHost;
			expect((await request({ token: await assertion() })).status).toBe(404);
			expectNoApplicationAccess();
		});

	it('treats a trailing-dot maintenance hostname as the same protected host', async () => {
		const response = await request({ url: `https://${host}.${path}` });
		expect(response.status).toBe(403);
		expectNoApplicationAccess();
	});

	it.each([
		['https://mail.nesoriel.com/', 'public assets'],
		['https://mail.nesoriel.com/api/login', 'public api'],
		['https://mail.nesoriel.com/api/init/test-app-secret', 'public api'],
		['https://mail.nesoriel.com/static/a.png', 'public object'],
		['https://mail.nesoriel.com/attachments/a.bin', 'public object'],
	])('preserves existing public routing for %s', async (url, body) => {
		const response = await request({ url, method: 'GET' });
		expect(response.status).toBe(200);
		expect(await response.text()).toBe(body);
		expect(jwksFetch).not.toHaveBeenCalled();
		expect(mocks.init).not.toHaveBeenCalled();
	});
});

describe('Access assertion and application secret', () => {
	it.each(['access_team_domain', 'access_aud', 'access_client_id'])('closes ingress without %s', async (field) => {
		const token = await assertion();
		delete env[field];
		expect((await request({ token })).status).toBe(503);
		expect(jwksFetch).not.toHaveBeenCalled();
		expectNoApplicationAccess();
	});

	it.each([
		'https://attacker.example', `http://${issuer}`, `https://${issuer}/`,
		`https://${issuer}/other`, `https://${issuer}:444`,
		`https://${issuer}@attacker.example`,
	])('rejects untrusted JWKS issuer configuration %s', async (teamDomain) => {
		env.access_team_domain = teamDomain;
		expect((await request({ token: await assertion() })).status).toBe(503);
		expect(jwksFetch).not.toHaveBeenCalled();
		expectNoApplicationAccess();
	});

	it('rejects missing assertion', async () => {
		expect((await request()).status).toBe(403);
		expect(jwksFetch).not.toHaveBeenCalled();
		expectNoApplicationAccess();
	});

	it.each([
		['wrong issuer', { iss: 'https://another.cloudflareaccess.com' }],
		['wrong audience', { aud: ['another-app'] }],
		['missing audience', { aud: undefined }],
		['wrong service token', { common_name: 'another-token.access' }],
		['missing service token', { common_name: undefined }],
		['wrong token type', { type: 'org' }],
		['missing token type', { type: undefined }],
		['expired token', { exp: 1 }],
		['missing expiry', { exp: undefined }],
		['string expiry', { exp: '4102444800' }],
		['noninteger expiry', { exp: 4102444800.5 }],
		['future issuance', { iat: 4102444800 }],
		['not yet valid', { nbf: 4102444800 }],
	])('rejects a correctly signed token with %s', async (_, claims) => {
		expect((await request({ token: await assertion(claims) })).status).toBe(403);
		expectNoApplicationAccess();
	});

	it('rejects a tampered RSA signature', async () => {
		const parts = (await assertion()).split('.');
		parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`;
		expect((await request({ token: parts.join('.') })).status).toBe(403);
		expectNoApplicationAccess();
	});

	it('rejects an unknown signing key', async () => {
		expect((await request({ token: await assertion({}, { ...privateKey, kid: 'unknown-key' }) })).status).toBe(403);
		expectNoApplicationAccess();
	});

	it('rejects HS256 even when supplied with a valid HMAC signature and kid', async () => {
		const hmacKey = { kty: 'oct', k: Buffer.from('hmac-test-key').toString('base64url'), alg: 'HS256', kid: 'test-key' };
		expect((await request({ token: await assertion({}, hmacKey) })).status).toBe(403);
		expect(jwksFetch).not.toHaveBeenCalled();
		expectNoApplicationAccess();
	});

	it('rejects malformed JWTs without logging assertions', async () => {
		const log = vi.spyOn(console, 'log');
		const error = vi.spyOn(console, 'error');
		expect((await request({ token: 'malformed.assertion' })).status).toBe(403);
		expect(log).not.toHaveBeenCalled();
		expect(error).not.toHaveBeenCalled();
		log.mockRestore();
		error.mockRestore();
		expectNoApplicationAccess();
	});

	it.each(['network failure', 'non-200 response', 'invalid JWKS'])('fails closed on %s', async (failure) => {
		if (failure === 'network failure') jwksFetch.mockRejectedValue(new Error('network failure'));
		if (failure === 'non-200 response') jwksFetch.mockResolvedValue(new Response('', { status: 503 }));
		if (failure === 'invalid JWKS') jwksFetch.mockResolvedValue(Response.json({ keys: [] }));
		expect((await request({ token: await assertion() })).status).toBe(403);
		expectNoApplicationAccess();
	});

	it.each([undefined, '', 'wrong-secret'])('rejects missing or wrong application secret %s', async (secret) => {
		const token = await assertion();
		// undefined in the helper normally means the default, so remove the header explicitly.
		const headers = { 'Cf-Access-Jwt-Assertion': token };
		if (secret !== undefined) headers['X-Init-Secret'] = secret;
		const response = await worker.fetch(new Request(`https://${host}${path}`, { method: 'POST', headers }), env, {});
		expect(response.status).toBe(401);
		expectNoApplicationAccess();
	});

	it.each([undefined, ''])('rejects an unset Worker application secret %s', async (secret) => {
		env.jwt_secret = secret;
		expect((await request({ token: await assertion(), secret: '' })).status).toBe(401);
		expectNoApplicationAccess();
	});

	it('verifies real RSA/JWKS and passes only the header secret to existing initialization once', async () => {
		const response = await request({ token: await assertion() });
		expect(response.status).toBe(200);
		expect(await response.text()).toBe('success');
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(jwksFetch).toHaveBeenCalledOnce();
		expect(jwksFetch).toHaveBeenCalledWith(`https://${issuer}/cdn-cgi/access/certs`, expect.objectContaining({ redirect: 'error' }));
		expect(mocks.init).toHaveBeenCalledOnce();
		expect(mocks.init.mock.calls[0][1]).toBe(env.jwt_secret);
		expect(mocks.init.mock.calls[0][0].req.param('secret')).toBeUndefined();
		expect(mocks.api).not.toHaveBeenCalled();
		expect(mocks.objects).not.toHaveBeenCalled();
		expect(env.assets.fetch).not.toHaveBeenCalled();
	});

	it('returns a generic uncaught migration failure without logging secrets', async () => {
		const log = vi.spyOn(console, 'log');
		const error = vi.spyOn(console, 'error');
		mocks.init.mockRejectedValueOnce(new Error(`fixture migration failure ${env.jwt_secret}`));
		const response = await request({ token: await assertion() });
		expect(response.status).toBe(500);
		expect(await response.text()).toBe('Maintenance initialization failed');
		expect(log).not.toHaveBeenCalled();
		expect(error).not.toHaveBeenCalled();
		log.mockRestore();
		error.mockRestore();
	});
});
