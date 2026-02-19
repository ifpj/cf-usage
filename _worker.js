/**
 * Cloudflare Workers/Pages 多账号用量监控面板
 * 
 * 同时支持 Worker 部署和 Pages 部署（_worker.js 高级模式）
 * 
 * 功能：
 * - 多账号管理（支持 Email+GlobalAPIKey / AccountID+APIToken 两种认证方式）
 * - 实时查询 Workers 和 Pages 的请求用量
 * - KV 持久化存储账号配置
 * - Web Admin 管理面板（登录认证、账号增删改查、用量可视化）
 * - 自动刷新 & 手动查询
 * - 用量汇总统计
 * 
 * 部署方式：
 * - Worker 部署：wrangler deploy
 * - Pages 部署：将 _worker.js 放在 Pages 项目输出目录根下，或直接上传到 Pages
 *   Pages 绑定：Dashboard -> Pages 项目 -> Settings -> Functions -> KV namespace bindings
 *               变量名 KV，环境变量 ADMIN
 */

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // 管理员密码（环境变量，兼容多种命名）
        const ADMIN_PASS = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
        if (!ADMIN_PASS) {
            return new Response(generateSetupHTML('password'), {
                status: 200,
                headers: { 'Content-Type': 'text/html;charset=utf-8' }
            });
        }

        // 检测 KV 绑定
        const kvReady = env.KV && typeof env.KV.get === 'function';
        if (!kvReady) {
            return new Response(generateSetupHTML('kv'), {
                status: 200,
                headers: { 'Content-Type': 'text/html;charset=utf-8' }
            });
        }

        // CORS headers
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        // ============ 路由 ============

        // 首页显示公开用量概览
        if (path === '/' || path === '' || path === '/public') {
            return new Response(generatePublicHTML(), {
                headers: { 'Content-Type': 'text/html;charset=utf-8' }
            });
        }

        // 登录 API（POST 验证，GET 重定向首页）
        if (path === '/login') {
            if (request.method === 'GET') {
                const cookies = parseCookies(request.headers.get('Cookie'));
                if (cookies.auth && await checkAuth(request, env)) {
                    return Response.redirect(url.origin + '/admin', 302);
                }
                return Response.redirect(url.origin + '/', 302);
            }
            if (request.method === 'POST') {
                try {
                    const body = await request.json();
                    if (body.password === ADMIN_PASS) {
                        const token = await createSession(env);
                        return new Response(JSON.stringify({ success: true }), {
                            headers: {
                                'Content-Type': 'application/json',
                                'Set-Cookie': `auth=${token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict`,
                            }
                        });
                    }
                    return new Response(JSON.stringify({ success: false, error: '密码错误' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' }
                    });
                } catch {
                    return new Response(JSON.stringify({ error: '请求格式错误' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            }
        }

        // 登出
        if (path === '/logout') {
            const cookies = parseCookies(request.headers.get('Cookie'));
            if (cookies.auth) {
                await deleteSession(env, cookies.auth);
            }
            return new Response('已登出', {
                status: 302,
                headers: {
                    'Location': '/',
                    'Set-Cookie': 'auth=; Path=/; Max-Age=0; HttpOnly',
                }
            });
        }

        // ============ 公开 API（无需认证） ============

        // 公开 API：获取用量汇总（脱敏）
        if (path === '/api/public/usage' && request.method === 'GET') {
            const ids = await getAccountIds(env);
            const results = await Promise.allSettled(
                ids.map(id => refreshAccountUsage(env, id).catch(e => ({ id, name: null, usage: { success: false, error: e.message } })))
            );
            const data = results.map(r => r.status === 'fulfilled' ? r.value : { error: r.reason?.message }).filter(Boolean);
            const publicData = data.map(d => ({
                name: d.name ? maskName(d.name) : null,
                usage: d.usage
            }));
            const summary = computeSummary(data);
            return jsonResponse({ accounts: publicData, summary }, corsHeaders);
        }

        // ============ 以下路由需要认证 ============
        const authResult = await checkAuth(request, env);
        if (!authResult) {
            if (path.startsWith('/api/')) {
                return new Response(JSON.stringify({ error: '未授权' }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json', ...corsHeaders }
                });
            }
            return Response.redirect(url.origin + '/login', 302);
        }

        // 管理面板
        if (path === '/admin') {
            return new Response(generateAdminHTML(), {
                headers: { 'Content-Type': 'text/html;charset=utf-8' }
            });
        }

        // ============ API 路由 ============

        // 获取所有账号
        if (path === '/api/accounts' && request.method === 'GET') {
            const accounts = await getAccounts(env);
            const safe = accounts.map(a => ({
                ...a,
                Email: a.Email ? maskEmail(a.Email) : null,
                GlobalAPIKey: a.GlobalAPIKey ? maskStr(a.GlobalAPIKey) : null,
                APIToken: a.APIToken ? maskStr(a.APIToken) : null,
            }));
            return jsonResponse(safe, corsHeaders);
        }

        // 添加账号
        if (path === '/api/accounts' && request.method === 'POST') {
            try {
                const body = await request.json();
                const result = await addAccount(env, body);
                return jsonResponse(result, corsHeaders);
            } catch (e) {
                return jsonResponse({ error: e.message }, corsHeaders, 400);
            }
        }

        // 更新账号
        if (path.match(/^\/api\/accounts\/[\w-]+$/) && request.method === 'PUT') {
            try {
                const id = path.split('/').pop();
                const body = await request.json();
                const result = await updateAccount(env, id, body);
                return jsonResponse(result, corsHeaders);
            } catch (e) {
                return jsonResponse({ error: e.message }, corsHeaders, 400);
            }
        }

        // 删除账号
        if (path.match(/^\/api\/accounts\/[\w-]+$/) && request.method === 'DELETE') {
            const id = path.split('/').pop();
            const result = await deleteAccount(env, id);
            return jsonResponse(result, corsHeaders);
        }

        // 批量查询所有账号用量（必须放在单个账号查询之前）
        if (path === '/api/usage/all' && request.method === 'GET') {
            const ids = await getAccountIds(env);
            const results = await Promise.allSettled(
                ids.map(id => refreshAccountUsage(env, id).catch(e => ({ id, name: null, usage: { success: false, error: e.message } })))
            );
            const data = results.map(r => r.status === 'fulfilled' ? r.value : { error: r.reason?.message }).filter(Boolean);
            const summary = computeSummary(data);
            return jsonResponse({ accounts: data, summary }, corsHeaders);
        }

        // 查询单个账号用量
        if (path.match(/^\/api\/usage\/[\w-]+$/) && request.method === 'GET') {
            const id = path.split('/').pop();
            const account = await getAccount(env, id);
            if (!account) {
                return jsonResponse({ error: '账号不存在' }, corsHeaders, 404);
            }
            const result = await refreshAccountUsage(env, id);
            return jsonResponse({
                ...account,
                Email: account.Email ? maskEmail(account.Email) : null,
                GlobalAPIKey: maskStr(account.GlobalAPIKey),
                APIToken: maskStr(account.APIToken)
            }, corsHeaders);
        }

        // 导出配置
        if (path === '/api/export' && request.method === 'GET') {
            const accounts = await getAccounts(env);
            return new Response(JSON.stringify(accounts, null, 2), {
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Disposition': 'attachment; filename="cf-usage-accounts.json"',
                    ...corsHeaders
                }
            });
        }

        // 导入配置（JSON 格式）
        if (path === '/api/import' && request.method === 'POST') {
            try {
                const imported = await request.json();
                if (!Array.isArray(imported)) throw new Error('格式错误：需要数组');
                const ids = [];
                for (const acc of imported) {
                    if (!acc.id) acc.id = generateId();
                    await saveAccount(env, acc);
                    ids.push(acc.id);
                }
                await saveAccountIds(env, ids);
                return jsonResponse({ success: true, count: imported.length }, corsHeaders);
            } catch (e) {
                return jsonResponse({ error: e.message }, corsHeaders, 400);
            }
        }

        // 批量导入凭证（.env / TEXT / CSV 等多格式）
        if (path === '/api/import-env' && request.method === 'POST') {
            try {
                const body = await request.json();
                const text = body.text || '';
                const mode = body.mode || 'merge';
                const parsed = parseMultiAccountText(text);
                if (!parsed.length) throw new Error('未解析到有效账号，请检查格式');

                let ids = mode === 'overwrite' ? [] : await getAccountIds(env);
                const existingNames = new Set();
                if (mode !== 'overwrite') {
                    for (const id of ids) {
                        const acc = await getAccount(env, id);
                        if (acc) existingNames.add(acc.name);
                    }
                }
                let added = 0, skipped = 0;
                for (const item of parsed) {
                    if (existingNames.has(item.name)) { skipped++; continue; }
                    const account = {
                        id: generateId(),
                        ...item,
                        createdAt: new Date().toISOString(),
                        lastUsage: null,
                        lastQueryTime: null,
                    };
                    await saveAccount(env, account);
                    ids.push(account.id);
                    existingNames.add(item.name);
                    added++;
                }
                await saveAccountIds(env, ids);
                return jsonResponse({ success: true, added, skipped, total: ids.length, parsed: parsed.length }, corsHeaders);
            } catch (e) {
                return jsonResponse({ error: e.message }, corsHeaders, 400);
            }
        }

        return new Response('Not Found', { status: 404 });
    }
};

// ======================== 工具函数 ========================

function parseCookies(cookieStr) {
    const cookies = {};
    if (!cookieStr) return cookies;
    cookieStr.split(';').forEach(c => {
        const [k, v] = c.trim().split('=');
        if (k) cookies[k] = v;
    });
    return cookies;
}

async function hashPassword(pass) {
    const encoder = new TextEncoder();
    const data = encoder.encode(pass + '_cf_usage_dashboard_salt');
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkAuth(request, env) {
    const cookies = parseCookies(request.headers.get('Cookie'));
    if (!cookies.auth) return false;
    const session = await env.KV.get('session:' + cookies.auth);
    return session !== null;
}

async function createSession(env) {
    const token = generateId() + generateId();
    await env.KV.put('session:' + token, '1', { expirationTtl: 86400 });
    return token;
}

async function deleteSession(env, token) {
    await env.KV.delete('session:' + token);
}

function maskStr(str) {
    if (!str) return null;
    if (str.length <= 8) return '****';
    return str.slice(0, 4) + '****' + str.slice(-4);
}

function maskName(name) {
    if (!name) return null;
    if (name.length <= 2) return name[0] + '*';
    if (name.length <= 4) return name[0] + '**' + name[name.length - 1];
    return name.slice(0, 2) + '***' + name.slice(-1);
}

function maskEmail(email) {
    if (!email) return null;
    const [local, domain] = email.split('@');
    if (!domain) return '****';
    const maskedLocal = local.length <= 2 ? local[0] + '***' : local.slice(0, 2) + '***' + local.slice(-1);
    const parts = domain.split('.');
    const maskedDomain = parts.length > 1 
        ? '***.' + parts[parts.length - 1] 
        : '***';
    return maskedLocal + '@' + maskedDomain;
}

function jsonResponse(data, corsHeaders = {}, status = 200) {
    return new Response(JSON.stringify(data, null, 2), {
        status,
        headers: { 'Content-Type': 'application/json;charset=utf-8', ...corsHeaders }
    });
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// ======================== KV 操作（独立存储，避免并发覆盖） ========================

const KV_KEY_LIST = 'account:list';
const KV_KEY_PREFIX = 'account:';

async function getAccountIds(env) {
    try {
        const data = await env.KV.get(KV_KEY_LIST);
        return data ? JSON.parse(data) : [];
    } catch {
        return [];
    }
}

async function saveAccountIds(env, ids) {
    await env.KV.put(KV_KEY_LIST, JSON.stringify(ids));
}

async function getAccount(env, id) {
    try {
        const data = await env.KV.get(KV_KEY_PREFIX + id);
        return data ? JSON.parse(data) : null;
    } catch {
        return null;
    }
}

async function saveAccount(env, account) {
    await env.KV.put(KV_KEY_PREFIX + account.id, JSON.stringify(account));
}

async function deleteAccountKV(env, id) {
    await env.KV.delete(KV_KEY_PREFIX + id);
}

async function getAccounts(env) {
    const ids = await getAccountIds(env);
    if (!ids.length) {
        const legacy = await env.KV.get('accounts.json');
        if (legacy) {
            const accounts = JSON.parse(legacy);
            for (const acc of accounts) {
                await saveAccount(env, acc);
            }
            await saveAccountIds(env, accounts.map(a => a.id));
            await env.KV.delete('accounts.json');
            return accounts;
        }
        return [];
    }
    const results = await Promise.all(ids.map(id => getAccount(env, id)));
    return results.filter(Boolean);
}

async function addAccount(env, body) {
    const ids = await getAccountIds(env);
    const { name, Email, GlobalAPIKey, AccountID, APIToken } = body;

    if (!name) throw new Error('账号名称不能为空');
    for (const id of ids) {
        const acc = await getAccount(env, id);
        if (acc && acc.name === name) throw new Error('账号名称已存在');
    }

    if (!Email && !AccountID) throw new Error('请提供 Email+GlobalAPIKey 或 AccountID+APIToken');
    if (Email && !GlobalAPIKey) throw new Error('使用Email认证时需提供 GlobalAPIKey');
    if (AccountID && !APIToken) throw new Error('使用AccountID认证时需提供 APIToken');

    const account = {
        id: generateId(),
        name,
        Email: Email || null,
        GlobalAPIKey: GlobalAPIKey || null,
        AccountID: AccountID || null,
        APIToken: APIToken || null,
        createdAt: new Date().toISOString(),
        lastUsage: null,
        lastQueryTime: null,
    };

    await saveAccount(env, account);
    ids.push(account.id);
    await saveAccountIds(env, ids);
    return { success: true, id: account.id };
}

async function updateAccount(env, id, body) {
    const account = await getAccount(env, id);
    if (!account) throw new Error('账号不存在');

    const { name, Email, GlobalAPIKey, AccountID, APIToken } = body;
    if (name) account.name = name;
    if (Email !== undefined) account.Email = Email || null;
    if (GlobalAPIKey !== undefined) account.GlobalAPIKey = GlobalAPIKey || null;
    if (AccountID !== undefined) account.AccountID = AccountID || null;
    if (APIToken !== undefined) account.APIToken = APIToken || null;
    account.updatedAt = new Date().toISOString();

    await saveAccount(env, account);
    return { success: true };
}

async function deleteAccount(env, id) {
    const ids = await getAccountIds(env);
    const idx = ids.indexOf(id);
    if (idx === -1) return { success: false, error: '账号不存在' };
    ids.splice(idx, 1);
    await saveAccountIds(env, ids);
    await deleteAccountKV(env, id);
    return { success: true };
}

async function refreshAccountUsage(env, id) {
    const account = await getAccount(env, id);
    if (!account) return null;
    const usage = await getCloudflareUsage(
        account.Email, account.GlobalAPIKey, account.AccountID, account.APIToken
    );
    account.lastUsage = usage;
    account.lastQueryTime = new Date().toISOString();
    await saveAccount(env, account);
    return { id: account.id, name: account.name, usage, lastQueryTime: account.lastQueryTime };
}

// ======================== 多格式凭证解析 ========================

/**
 * 解析多种文本格式的批量账号凭证
 * 
 * 支持格式：
 * 
 * 1. .env 格式（每行一个变量，用空行或 # 注释分隔账号）:
 *    # 账号1
 *    CF_ACCOUNT_NAME=主账号
 *    CF_EMAIL=a@example.com
 *    CF_GLOBAL_API_KEY=xxx
 *    
 *    # 账号2
 *    CF_ACCOUNT_NAME=备用号
 *    CF_ACCOUNT_ID=yyy
 *    CF_API_TOKEN=zzz
 * 
 * 2. 单行紧凑格式（每行一个账号，逗号或竖线分隔）:
 *    名称,email,globalApiKey
 *    名称,accountId,apiToken
 *    名称|email|globalApiKey
 *    名称|accountId|apiToken
 * 
 * 3. CSV 格式（首行为表头）:
 *    name,Email,GlobalAPIKey
 *    主账号,a@example.com,xxx
 *    name,AccountID,APIToken
 *    备用号,yyy,zzz
 */
function parseMultiAccountText(text) {
    if (!text || !text.trim()) return [];
    const lines = text.split('\n').map(l => l.trim());
    const results = [];

    // 检测是否是 CSV（首行包含已知表头字段）
    const csvHeaderPattern = /^name[,|].*(?:email|accountid|globalapi|apitoken)/i;
    if (csvHeaderPattern.test(lines[0])) {
        return parseCSVFormat(lines);
    }

    // 检测是否是 .env 格式（包含 KEY=VALUE 模式）
    const hasEnvPattern = lines.some(l => /^[A-Z_]+=.+/i.test(l) && !l.startsWith('#'));
    if (hasEnvPattern) {
        return parseEnvFormat(lines);
    }

    // 否则按单行紧凑格式解析
    return parseCompactFormat(lines);
}

// .env 格式解析
function parseEnvFormat(lines) {
    const results = [];
    let current = {};
    // 支持的变量名映射（宽松匹配）
    const keyMap = {
        // name
        'CF_ACCOUNT_NAME': 'name', 'ACCOUNT_NAME': 'name', 'NAME': 'name', 'ALIAS': 'name',
        // Email
        'CF_EMAIL': 'Email', 'EMAIL': 'Email', 'CF_AUTH_EMAIL': 'Email',
        // GlobalAPIKey
        'CF_GLOBAL_API_KEY': 'GlobalAPIKey', 'GLOBAL_API_KEY': 'GlobalAPIKey',
        'CF_API_KEY': 'GlobalAPIKey', 'GLOBALAPI_KEY': 'GlobalAPIKey', 'GLOBALAPIKEY': 'GlobalAPIKey',
        'CF_GLOBAL_APIKEY': 'GlobalAPIKey', 'CF_AUTH_KEY': 'GlobalAPIKey',
        // AccountID
        'CF_ACCOUNT_ID': 'AccountID', 'ACCOUNT_ID': 'AccountID', 'ACCOUNTID': 'AccountID',
        // APIToken
        'CF_API_TOKEN': 'APIToken', 'API_TOKEN': 'APIToken', 'APITOKEN': 'APIToken',
        'CF_BEARER_TOKEN': 'APIToken', 'BEARER_TOKEN': 'APIToken',
    };

    const flush = () => {
        if (current.name && (current.Email || current.AccountID)) {
            results.push({
                name: current.name,
                Email: current.Email || null,
                GlobalAPIKey: current.GlobalAPIKey || null,
                AccountID: current.AccountID || null,
                APIToken: current.APIToken || null,
            });
        }
        current = {};
    };

    for (const line of lines) {
        // 空行或纯注释行 = 账号分隔符
        if (!line || /^#+\s*$/.test(line)) { flush(); continue; }
        // 注释行（可能带名称提示，如 "# 主账号"）
        if (line.startsWith('#')) {
            const commentName = line.replace(/^#+\s*/, '').trim();
            if (commentName && !current.name) current.name = commentName;
            continue;
        }
        // 解析 KEY=VALUE
        const eqIdx = line.indexOf('=');
        if (eqIdx === -1) continue;
        const rawKey = line.slice(0, eqIdx).trim().toUpperCase();
        const value = line.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
        if (!value) continue;
        const mappedKey = keyMap[rawKey];
        if (mappedKey) current[mappedKey] = value;
    }
    flush();

    // 给没有名称的账号自动编号
    let unnamed = 0;
    for (const acc of results) {
        if (!acc.name) acc.name = '账号' + (++unnamed);
    }
    return results;
}

// CSV 格式解析
function parseCSVFormat(lines) {
    if (lines.length < 2) return [];
    const sep = lines[0].includes('|') ? '|' : ',';
    const headers = lines[0].split(sep).map(h => h.trim().toLowerCase());
    const results = [];

    // 表头字段映射
    const fieldMap = {
        'name': 'name', 'alias': 'name', '名称': 'name', '账号': 'name',
        'email': 'Email', '邮箱': 'Email',
        'globalapikey': 'GlobalAPIKey', 'global_api_key': 'GlobalAPIKey', 'apikey': 'GlobalAPIKey', 'api_key': 'GlobalAPIKey',
        'accountid': 'AccountID', 'account_id': 'AccountID', '账户id': 'AccountID',
        'apitoken': 'APIToken', 'api_token': 'APIToken', 'token': 'APIToken',
    };

    const mappedHeaders = headers.map(h => fieldMap[h] || null);

    for (let i = 1; i < lines.length; i++) {
        if (!lines[i] || lines[i].startsWith('#')) continue;
        const values = lines[i].split(sep).map(v => v.trim().replace(/^["']|["']$/g, ''));
        const acc = { name: null, Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null };
        for (let j = 0; j < mappedHeaders.length; j++) {
            if (mappedHeaders[j] && values[j]) acc[mappedHeaders[j]] = values[j];
        }
        if (acc.name && (acc.Email || acc.AccountID)) results.push(acc);
    }
    return results;
}

// 单行紧凑格式解析
function parseCompactFormat(lines) {
    const results = [];
    for (const line of lines) {
        if (!line || line.startsWith('#')) continue;
        const sep = line.includes('|') ? '|' : ',';
        const parts = line.split(sep).map(s => s.trim());
        if (parts.length < 3) continue;

        const [name, field2, field3] = parts;
        // 判断 field2 是 email 还是 accountId
        const isEmail = field2.includes('@');
        if (isEmail) {
            results.push({ name, Email: field2, GlobalAPIKey: field3, AccountID: null, APIToken: null });
        } else {
            results.push({ name, Email: null, GlobalAPIKey: null, AccountID: field2, APIToken: field3 });
        }
    }
    return results;
}

// ======================== 用量查询 ========================

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    const cfg = { "Content-Type": "application/json" };

    try {
        if (!AccountID && (!Email || !GlobalAPIKey)) {
            return { success: false, pages: 0, workers: 0, total: 0, max: 100000, error: '缺少认证信息' };
        }

        if (!AccountID) {
            const r = await fetch(`${API}/accounts`, {
                method: "GET",
                headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
            });
            if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
            const d = await r.json();
            if (!d?.result?.length) throw new Error("未找到账户");
            const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
            AccountID = d.result[idx >= 0 ? idx : 0]?.id;
        }

        const now = new Date();
        now.setUTCHours(0, 0, 0, 0);
        const hdr = APIToken
            ? { ...cfg, "Authorization": `Bearer ${APIToken}` }
            : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

        const res = await fetch(`${API}/graphql`, {
            method: "POST",
            headers: hdr,
            body: JSON.stringify({
                query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                    viewer { accounts(filter: {accountTag: $AccountID}) {
                        pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                        workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
                    } }
                }`,
                variables: {
                    AccountID,
                    filter: {
                        datetime_geq: now.toISOString(),
                        datetime_leq: new Date().toISOString()
                    }
                }
            })
        });

        if (!res.ok) throw new Error(`查询失败: ${res.status}`);
        const result = await res.json();
        if (result.errors?.length) throw new Error(result.errors[0].message);

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) throw new Error("未找到账户数据");

        const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
        const workers = sum(acc.workersInvocationsAdaptive);
        const total = pages + workers;
        return { success: true, pages, workers, total, max: 100000 };
    } catch (error) {
        return { success: false, pages: 0, workers: 0, total: 0, max: 100000, error: error.message };
    }
}

function computeSummary(accountResults) {
    let totalPages = 0, totalWorkers = 0, totalRequests = 0, totalMax = 0;
    let successCount = 0, failCount = 0;
    for (const item of accountResults) {
        if (item.usage?.success) {
            successCount++;
            totalPages += item.usage.pages || 0;
            totalWorkers += item.usage.workers || 0;
            totalRequests += item.usage.total || 0;
            totalMax += item.usage.max || 100000;
        } else {
            failCount++;
        }
    }
    return { totalPages, totalWorkers, totalRequests, totalMax, successCount, failCount, accountCount: accountResults.length };
}

// ======================== 初始化引导页面 ========================

function generateSetupHTML(type) {
    const isKV = type === 'kv';
    const title = isKV ? 'KV 未绑定' : '密码未设置';
    const desc = isKV
        ? '请绑定 KV 命名空间（变量名 <code>KV</code>）'
        : '请设置环境变量 <code>ADMIN</code> 作为管理员密码';
    const stepsWrangler = isKV
        ? `<li>运行 <code>wrangler kv:namespace create "KV"</code></li>
           <li>将返回的 id 填入 <code>wrangler.toml</code> 的 <code>[[kv_namespaces]]</code></li>
           <li>重新部署</li>`
        : `<li>在 <code>wrangler.toml</code> 中添加 <code>ADMIN = "你的密码"</code></li>
           <li>或运行 <code>wrangler secret put ADMIN</code></li>
           <li>重新部署</li>`;
    const stepsDashboard = isKV
        ? `<li>Dashboard -> Workers & Pages -> 你的项目 -> Settings</li>
           <li>Functions -> KV namespace bindings -> 添加 <code>KV</code></li>
           <li>重新部署</li>`
        : `<li>Dashboard -> Workers & Pages -> 你的项目 -> Settings</li>
           <li>Environment variables -> 添加 <code>ADMIN</code></li>
           <li>重新部署</li>`;
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>配置引导</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
:root { --bg: #f8fafc; --card: #fff; --text: #1e293b; --text2: #64748b; --accent: #6366f1; --border: #e2e8f0; --warn: #f97316; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f172a; --card: #1e293b; --text: #f1f5f9; --text2: #94a3b8; --border: #334155; } }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: var(--text); padding: 20px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 32px 40px; max-width: 480px; width: 100%; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
h1 { font-size: 20px; margin-bottom: 8px; color: var(--warn); }
.desc { color: var(--text2); margin-bottom: 28px; font-size: 14px; }
code { background: rgba(99,102,241,0.1); padding: 2px 6px; border-radius: 4px; font-size: 12px; color: var(--accent); }
.method { margin-bottom: 20px; }
.method h2 { font-size: 14px; margin-bottom: 10px; color: var(--accent); }
.method ol { padding-left: 20px; line-height: 1.9; font-size: 13px; color: var(--text2); }
</style>
</head>
<body>
<div class="card">
    <h1>${title}</h1>
    <div class="desc">${desc}</div>
    <div class="method"><h2>wrangler 部署</h2><ol>${stepsWrangler}</ol></div>
    <div class="method"><h2>Dashboard 部署</h2><ol>${stepsDashboard}</ol></div>
</div>
</body>
</html>`;
}

// ======================== 公开页面 ========================

function generatePublicHTML() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CF 用量概览</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
    --bg-body: #f8fafc; --bg-card: #ffffff; --bg-item: #f1f5f9;
    --text-primary: #1e293b; --text-secondary: #64748b; --text-muted: #94a3b8;
    --border: #e2e8f0; --border-light: #f1f5f9;
    --green: #10b981; --yellow: #f59e0b; --orange: #f97316; --red: #ef4444; --accent: #6366f1;
    --shadow: 0 1px 3px rgba(0,0,0,0.1); --shadow-lg: 0 4px 12px rgba(0,0,0,0.08);
}
@media (prefers-color-scheme: dark) {
:root {
    --bg-body: #0f172a; --bg-card: #1e293b; --bg-item: #334155;
    --text-primary: #f1f5f9; --text-secondary: #94a3b8; --text-muted: #64748b;
    --border: #334155; --border-light: #1e293b;
    --shadow: 0 1px 3px rgba(0,0,0,0.3); --shadow-lg: 0 4px 12px rgba(0,0,0,0.4);
}
}
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg-body); min-height: 100vh; color: var(--text-primary); transition: background 0.3s, color 0.3s; }
.container { max-width: 900px; margin: 0 auto; padding: 20px; }
.header { text-align: center; padding: 30px 0; position: relative; }
.header h1 { font-size: 28px; margin-bottom: 8px; }
.header p { color: var(--text-secondary); font-size: 14px; }
.admin-btn { position: absolute; top: 30px; right: 20px; background: var(--bg-item); border: 1px solid var(--border); color: var(--text-secondary); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 13px; transition: all 0.3s; }
.admin-btn:hover { background: var(--accent); color: #fff; border-color: var(--accent); }
.summary-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 24px; margin-bottom: 24px; box-shadow: var(--shadow-lg); }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; }
.summary-item { text-align: center; padding: 16px; background: var(--bg-item); border-radius: 12px; }
.summary-item .value { font-size: 28px; font-weight: 700; color: var(--text-primary); }
.summary-item .label { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
.account-list { display: grid; gap: 12px; }
.account-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; box-shadow: var(--shadow); }
.account-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.account-name { font-weight: 600; font-size: 15px; }
.account-status { font-size: 12px; padding: 4px 10px; border-radius: 20px; background: var(--bg-item); }
.status-ok { background: rgba(16,185,129,0.15); color: var(--green); }
.status-warn { background: rgba(249,115,22,0.15); color: var(--orange); }
.status-err { background: rgba(239,68,68,0.15); color: var(--red); }
.progress-bar { height: 8px; background: var(--bg-item); border-radius: 4px; overflow: hidden; margin-bottom: 8px; }
.progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.usage-text { font-size: 12px; color: var(--text-secondary); }
.usage-detail { display: flex; gap: 16px; margin-top: 8px; font-size: 12px; color: var(--text-muted); }
.refresh-info { text-align: center; padding: 20px; color: var(--text-muted); font-size: 12px; }
.empty-state { text-align: center; padding: 40px; color: var(--text-muted); }
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); backdrop-filter: blur(4px); z-index: 1000; align-items: center; justify-content: center; }
.modal-overlay.show { display: flex; }
.modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 32px; width: 90%; max-width: 360px; box-shadow: var(--shadow-lg); }
.modal h2 { font-size: 20px; margin-bottom: 8px; text-align: center; }
.modal p { color: var(--text-secondary); font-size: 13px; text-align: center; margin-bottom: 24px; }
.modal input { width: 100%; padding: 12px 16px; background: var(--bg-item); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); font-size: 15px; outline: none; margin-bottom: 16px; transition: border-color 0.3s; }
.modal input:focus { border-color: var(--accent); }
.modal-btns { display: flex; gap: 12px; }
.modal-btns button { flex: 1; padding: 12px; border-radius: 8px; font-size: 14px; cursor: pointer; transition: all 0.3s; }
.btn-cancel { background: transparent; border: 1px solid var(--border); color: var(--text-secondary); }
.btn-cancel:hover { background: var(--bg-item); }
.btn-login { background: linear-gradient(135deg, #6c63ff, #3b82f6); border: none; color: #fff; font-weight: 600; }
.btn-login:hover { opacity: 0.9; }
.btn-login:disabled { opacity: 0.5; cursor: not-allowed; }
.modal-error { color: var(--red); font-size: 13px; text-align: center; margin-bottom: 12px; display: none; }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>CF 用量概览</h1>
        <p>Cloudflare Workers/Pages 请求用量监控</p>
        <button class="admin-btn" onclick="openLoginModal()">管理后台</button>
    </div>
    <div class="summary-card">
        <div class="summary-grid">
            <div class="summary-item"><div class="value" id="sumAccounts">-</div><div class="label">账号总数</div></div>
            <div class="summary-item"><div class="value" id="sumTotal">-</div><div class="label">总请求量</div></div>
            <div class="summary-item"><div class="value" id="sumPages">-</div><div class="label">Pages 请求</div></div>
            <div class="summary-item"><div class="value" id="sumWorkers">-</div><div class="label">Workers 请求</div></div>
            <div class="summary-item"><div class="value" id="sumPercent">-</div><div class="label">总使用率</div></div>
        </div>
    </div>
    <div class="account-list" id="accountList"><div class="empty-state">加载中...</div></div>
    <div class="refresh-info" id="refreshInfo"></div>
</div>
<div class="modal-overlay" id="loginModal">
    <div class="modal">
        <h2>管理员登录</h2>
        <p>请输入管理密码访问后台</p>
        <div class="modal-error" id="loginError"></div>
        <input type="password" id="loginPassword" placeholder="管理密码" autocomplete="current-password">
        <div class="modal-btns">
            <button class="btn-cancel" onclick="closeLoginModal()">取消</button>
            <button class="btn-login" id="loginBtn" onclick="doLogin()">登录</button>
        </div>
    </div>
</div>
<script>
function fmtNum(n) { return n == null ? '-' : n.toLocaleString('en-US'); }
function getUsagePercent(t, m) { return m ? Math.min(t / m * 100, 100) : 0; }
function getUsageColor(p) { return p >= 90 ? 'var(--red)' : p >= 70 ? 'var(--orange)' : p >= 50 ? 'var(--yellow)' : 'var(--green)'; }
function getStatusClass(p) { return p >= 90 ? 'status-err' : p >= 70 ? 'status-warn' : 'status-ok'; }

function openLoginModal() { document.getElementById('loginModal').classList.add('show'); document.getElementById('loginPassword').focus(); }
function closeLoginModal() { document.getElementById('loginModal').classList.remove('show'); document.getElementById('loginError').style.display = 'none'; document.getElementById('loginPassword').value = ''; }
document.getElementById('loginModal').addEventListener('click', e => { if (e.target.id === 'loginModal') closeLoginModal(); });
document.getElementById('loginPassword').addEventListener('keypress', e => { if (e.key === 'Enter') doLogin(); });

async function doLogin() {
    const btn = document.getElementById('loginBtn');
    const errEl = document.getElementById('loginError');
    const pwd = document.getElementById('loginPassword').value;
    if (!pwd) { errEl.textContent = '请输入密码'; errEl.style.display = 'block'; return; }
    btn.disabled = true; btn.textContent = '登录中...'; errEl.style.display = 'none';
    try {
        const res = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pwd }) });
        const data = await res.json();
        if (data.success) { window.location.href = '/admin'; } else { errEl.textContent = data.error || '密码错误'; errEl.style.display = 'block'; }
    } catch (e) { errEl.textContent = '网络错误'; errEl.style.display = 'block'; }
    btn.disabled = false; btn.textContent = '登录';
}

async function load() {
    try {
        const res = await fetch('/api/public/usage');
        const data = await res.json();
        renderSummary(data.summary);
        renderAccounts(data.accounts);
        document.getElementById('refreshInfo').textContent = '更新时间: ' + new Date().toLocaleString('zh-CN');
    } catch (e) {
        document.getElementById('accountList').innerHTML = '<div class="empty-state">加载失败: ' + e.message + '</div>';
    }
}

function renderSummary(s) {
    document.getElementById('sumAccounts').textContent = s.accountCount || 0;
    document.getElementById('sumTotal').textContent = fmtNum(s.totalRequests);
    document.getElementById('sumPages').textContent = fmtNum(s.totalPages);
    document.getElementById('sumWorkers').textContent = fmtNum(s.totalWorkers);
    const pct = s.totalMax ? (s.totalRequests / s.totalMax * 100).toFixed(1) : 0;
    document.getElementById('sumPercent').textContent = pct + '%';
}

function renderAccounts(accounts) {
    if (!accounts || !accounts.length) {
        document.getElementById('accountList').innerHTML = '<div class="empty-state">暂无账号数据</div>';
        return;
    }
    const html = accounts.map(acc => {
        const u = acc.usage;
        if (!u || !u.success) {
            return '<div class="account-card"><div class="account-header"><span class="account-name">' + (acc.name || '未知') + '</span><span class="account-status status-err">查询失败</span></div></div>';
        }
        const pct = getUsagePercent(u.total, u.max);
        const color = getUsageColor(pct);
        return '<div class="account-card">' +
            '<div class="account-header"><span class="account-name">' + acc.name + '</span>' +
            '<span class="account-status ' + getStatusClass(pct) + '">' + pct.toFixed(1) + '%</span></div>' +
            '<div class="progress-bar"><div class="progress-fill" style="width:' + pct + '%;background:' + color + '"></div></div>' +
            '<div class="usage-text">今日: ' + fmtNum(u.total) + ' / ' + fmtNum(u.max) + '</div>' +
            '<div class="usage-detail"><span>Pages: ' + fmtNum(u.pages) + '</span><span>Workers: ' + fmtNum(u.workers) + '</span></div>' +
            '</div>';
    }).join('');
    document.getElementById('accountList').innerHTML = html;
}
load();
setInterval(load, 60000);
</script>
</body>
</html>`;
}

// ======================== 管理面板 ========================

function generateAdminHTML() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CF 用量监控面板</title>
<style>
:root {
    --bg-primary: #f8fafc; --bg-secondary: #ffffff; --bg-card: #ffffff;
    --border: #e2e8f0; --border-light: #f1f5f9;
    --text-primary: #1e293b; --text-secondary: #64748b;
    --accent: #6366f1; --accent-hover: #4f46e5;
    --green: #22c55e; --yellow: #eab308; --red: #ef4444; --orange: #f97316;
    --shadow: 0 1px 3px rgba(0,0,0,0.08); --shadow-lg: 0 4px 12px rgba(0,0,0,0.1);
    --input-bg: #f8fafc;
}
@media (prefers-color-scheme: dark) {
:root {
    --bg-primary: #0f172a; --bg-secondary: #1e293b; --bg-card: rgba(30, 41, 59, 0.8);
    --border: rgba(255,255,255,0.08); --border-light: rgba(255,255,255,0.04);
    --text-primary: #f1f5f9; --text-secondary: #94a3b8;
    --shadow: 0 1px 3px rgba(0,0,0,0.3); --shadow-lg: 0 4px 12px rgba(0,0,0,0.4);
    --input-bg: rgba(255,255,255,0.06);
}
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans SC', sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; transition: background 0.3s, color 0.3s; }

.header { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; box-shadow: var(--shadow); }
.header h1 { font-size: 20px; font-weight: 700; background: linear-gradient(135deg, #6366f1, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.header-actions { display: flex; gap: 12px; align-items: center; }
.header-actions button { padding: 8px 16px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg-card); color: var(--text-primary); cursor: pointer; font-size: 13px; transition: all 0.2s; }
.header-actions button:hover { border-color: var(--accent); color: var(--accent); }
.btn-accent { background: var(--accent) !important; border-color: var(--accent) !important; color: #fff !important; }
.btn-accent:hover { background: var(--accent-hover) !important; }
.btn-danger { color: var(--red) !important; }
.btn-danger:hover { border-color: var(--red) !important; }

.container { max-width: 1400px; margin: 0 auto; padding: 24px; }

.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }
.summary-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: var(--shadow); }
.summary-card .label { font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; }
.summary-card .value { font-size: 28px; font-weight: 700; }
.summary-card .sub { font-size: 12px; color: var(--text-secondary); margin-top: 4px; }
.text-green { color: var(--green); }
.text-yellow { color: var(--yellow); }
.text-red { color: var(--red); }
.text-accent { color: var(--accent); }
.text-orange { color: var(--orange); }

.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.section-header h2 { font-size: 18px; font-weight: 600; }
.account-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 16px; }
.account-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: var(--shadow); transition: border-color 0.3s; position: relative; }
.account-card:hover { border-color: rgba(99, 102, 241, 0.3); }
.account-name { font-size: 16px; font-weight: 600; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
.account-meta { font-size: 12px; color: var(--text-secondary); margin-bottom: 16px; }
.account-auth-type { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; background: rgba(99,102,241,0.15); color: var(--accent); }

.usage-section { margin-top: 12px; }
.usage-bar-container { background: var(--border-light); border-radius: 8px; height: 24px; overflow: hidden; margin: 8px 0; position: relative; }
.usage-bar { height: 100%; border-radius: 8px; transition: width 0.6s ease; display: flex; }
.usage-bar .pages-bar { background: linear-gradient(90deg, #6366f1, #818cf8); height: 100%; }
.usage-bar .workers-bar { background: linear-gradient(90deg, #3b82f6, #60a5fa); height: 100%; }
.usage-stats { display: flex; justify-content: space-between; font-size: 12px; color: var(--text-secondary); }
.usage-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; }
.usage-detail-item { display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: var(--border-light); border-radius: 6px; font-size: 13px; }
.usage-detail-item .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.dot-pages { background: #6366f1; }
.dot-workers { background: #3b82f6; }

.account-actions { position: absolute; top: 16px; right: 16px; display: flex; gap: 6px; }
.account-actions button { padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border); background: transparent; color: var(--text-secondary); cursor: pointer; font-size: 12px; transition: all 0.2s; }
.account-actions button:hover { color: var(--text-primary); border-color: var(--text-secondary); }
.account-actions .btn-del:hover { color: var(--red); border-color: var(--red); }

.query-time { font-size: 11px; color: var(--text-secondary); margin-top: 8px; text-align: right; }

.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.status-ok { background: var(--green); }
.status-warn { background: var(--yellow); }
.status-err { background: var(--red); }
.status-idle { background: var(--text-secondary); }

.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 200; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
.modal-overlay.active { display: flex; }
.modal { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 16px; padding: 32px; width: 100%; max-width: 520px; margin: 20px; max-height: 90vh; overflow-y: auto; box-shadow: var(--shadow-lg); }
.modal h2 { font-size: 20px; margin-bottom: 24px; }
.modal .form-group { margin-bottom: 16px; }
.modal .form-group label { display: block; font-size: 13px; color: var(--text-secondary); margin-bottom: 6px; }
.modal .form-group input, .modal .form-group select { width: 100%; padding: 10px 14px; background: var(--input-bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); font-size: 14px; outline: none; transition: border-color 0.3s; }
.modal .form-group input:focus, .modal .form-group select:focus { border-color: var(--accent); }
.modal .form-group textarea { width: 100%; padding: 10px 14px; background: var(--input-bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); font-size: 13px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; outline: none; transition: border-color 0.3s; resize: vertical; line-height: 1.5; }
.modal .form-group textarea:focus { border-color: var(--accent); }
.modal .form-group .hint { font-size: 11px; color: var(--text-secondary); margin-top: 4px; }
.modal-actions { display: flex; gap: 12px; margin-top: 24px; }
.modal-actions button { flex: 1; padding: 12px; border-radius: 8px; border: 1px solid var(--border); cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; }
.modal-actions .btn-save { background: var(--accent); border-color: var(--accent); color: #fff; }
.modal-actions .btn-save:hover { background: var(--accent-hover); }
.modal-actions .btn-cancel { background: transparent; color: var(--text-secondary); }
.modal-actions .btn-cancel:hover { color: var(--text-primary); }

.auth-method-tabs { display: flex; gap: 8px; margin-bottom: 16px; }
.auth-method-tabs button { flex: 1; padding: 10px; border-radius: 8px; border: 1px solid var(--border); background: transparent; color: var(--text-secondary); cursor: pointer; font-size: 13px; transition: all 0.2s; }
.auth-method-tabs button.active { background: rgba(99,102,241,0.15); border-color: var(--accent); color: var(--accent); }
.auth-fields { display: none; }
.auth-fields.active { display: block; }

.format-tabs { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
.format-tabs button { padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border); background: transparent; color: var(--text-secondary); cursor: pointer; font-size: 12px; transition: all 0.2s; }
.format-tabs button.active { background: rgba(99,102,241,0.15); border-color: var(--accent); color: var(--accent); }
.format-tabs button:hover { border-color: var(--accent); }
.import-result { margin-top: 12px; padding: 12px; border-radius: 8px; font-size: 13px; display: none; }
.import-result.show { display: block; }
.import-result.success { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.2); color: var(--green); }
.import-result.error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: var(--red); }
.radio-group { display: flex; gap: 16px; margin-bottom: 8px; }
.radio-group label { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-secondary); cursor: pointer; }
.radio-group input[type="radio"] { accent-color: var(--accent); }

.loading { text-align: center; padding: 40px; color: var(--text-secondary); }
.spinner { display: inline-block; width: 32px; height: 32px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.empty-state { text-align: center; padding: 60px 20px; color: var(--text-secondary); }
.empty-state h3 { font-size: 18px; margin-bottom: 8px; color: var(--text-primary); }
.empty-state p { font-size: 14px; margin-bottom: 24px; }

.toast { position: fixed; bottom: 24px; right: 24px; padding: 12px 20px; border-radius: 8px; font-size: 14px; z-index: 300; transform: translateY(100px); opacity: 0; transition: all 0.3s; }
.toast.show { transform: translateY(0); opacity: 1; }
.toast.success { background: var(--green); color: #fff; }
.toast.error { background: var(--red); color: #fff; }
.toast.info { background: var(--accent); color: #fff; }

@media (max-width: 768px) {
    .header { padding: 12px 16px; flex-wrap: wrap; gap: 12px; }
    .header h1 { font-size: 17px; }
    .container { padding: 16px; }
    .summary-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
    .account-grid { grid-template-columns: 1fr; }
    .summary-card .value { font-size: 22px; }
    .header-actions { flex-wrap: wrap; }
    .header-actions button { padding: 6px 12px; font-size: 12px; }
}
@media (max-width: 480px) {
    .summary-grid { grid-template-columns: 1fr 1fr; }
    .usage-detail { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<div class="header">
    <h1>CF Workers/Pages 用量监控</h1>
    <div class="header-actions">
        <button onclick="refreshAll()" id="refreshBtn">刷新用量</button>
        <button onclick="openAddModal()" class="btn-accent">添加账号</button>
        <button onclick="openBatchImportModal()">批量导入</button>
        <button onclick="exportConfig()">导出</button>
        <button onclick="document.getElementById('importInput').click()">导入JSON</button>
        <input type="file" id="importInput" accept=".json" style="display:none" onchange="importConfig(event)">
        <button onclick="location.href='/logout'" class="btn-danger">登出</button>
    </div>
</div>

<div class="container">
    <div class="summary-grid" id="summaryGrid">
        <div class="summary-card"><div class="label">总账号数</div><div class="value" id="sumAccounts">-</div></div>
        <div class="summary-card"><div class="label">今日总请求</div><div class="value" id="sumTotal">-</div><div class="sub" id="sumTotalSub"></div></div>
        <div class="summary-card"><div class="label">Pages 请求</div><div class="value text-accent" id="sumPages">-</div></div>
        <div class="summary-card"><div class="label">Workers 请求</div><div class="value" style="color:#3b82f6" id="sumWorkers">-</div></div>
        <div class="summary-card"><div class="label">总配额</div><div class="value text-green" id="sumMax">-</div><div class="sub" id="sumMaxSub"></div></div>
        <div class="summary-card"><div class="label">查询状态</div><div class="value" id="sumStatus">-</div></div>
    </div>

    <div class="section-header">
        <h2>账号列表</h2>
        <div style="font-size:13px;color:var(--text-secondary)" id="lastRefresh"></div>
    </div>
    <div id="accountList">
        <div class="loading"><div class="spinner"></div><p style="margin-top:12px">加载中...</p></div>
    </div>
</div>

<div class="modal-overlay" id="accountModal">
    <div class="modal">
        <h2 id="modalTitle">添加账号</h2>
        <input type="hidden" id="editId">
        <div class="form-group">
            <label>账号名称</label>
            <input type="text" id="accName" placeholder="例如：主账号、测试账号">
            <div class="hint">用于区分不同账号，建议使用易辨识的名称</div>
        </div>
        <div class="form-group">
            <label>认证方式</label>
            <div class="auth-method-tabs">
                <button class="active" onclick="switchAuthMethod('email', this)">Email + GlobalAPIKey</button>
                <button onclick="switchAuthMethod('token', this)">AccountID + APIToken</button>
            </div>
        </div>
        <div class="auth-fields active" id="emailFields">
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="accEmail" placeholder="your@email.com">
            </div>
            <div class="form-group">
                <label>Global API Key</label>
                <input type="text" id="accGlobalAPIKey" placeholder="Cloudflare Global API Key">
                <div class="hint">在 Cloudflare Dashboard - My Profile - API Tokens 获取</div>
            </div>
        </div>
        <div class="auth-fields" id="tokenFields">
            <div class="form-group">
                <label>Account ID</label>
                <input type="text" id="accAccountID" placeholder="Cloudflare Account ID">
                <div class="hint">在 Workers & Pages 概览页右侧获取</div>
            </div>
            <div class="form-group">
                <label>API Token</label>
                <input type="text" id="accAPIToken" placeholder="Cloudflare API Token">
                <div class="hint">需要 Account Analytics:Read 权限</div>
            </div>
        </div>
        <div class="modal-actions">
            <button class="btn-cancel" onclick="closeModal()">取消</button>
            <button class="btn-save" onclick="saveAccount()">保存</button>
        </div>
    </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<!-- Batch Import Modal -->
<div class="modal-overlay" id="batchImportModal">
    <div class="modal" style="max-width:680px">
        <h2>批量导入账号凭证</h2>
        <div class="form-group">
            <label>选择格式</label>
            <div class="format-tabs">
                <button class="active" onclick="switchFormatTab('env', this)">ENV 格式</button>
                <button onclick="switchFormatTab('compact', this)">单行格式</button>
                <button onclick="switchFormatTab('csv', this)">CSV 格式</button>
            </div>
        </div>
        <div class="form-group" id="formatHintEnv">
            <div class="hint" style="background:rgba(255,255,255,0.03);padding:10px;border-radius:6px;line-height:1.8;white-space:pre;font-family:monospace;font-size:12px;color:var(--text-secondary)"># 主账号
CF_ACCOUNT_NAME=主账号
CF_EMAIL=your@email.com
CF_GLOBAL_API_KEY=your_global_api_key

# 备用号（Token方式）
CF_ACCOUNT_NAME=备用号
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token</div>
        </div>
        <div class="form-group" id="formatHintCompact" style="display:none">
            <div class="hint" style="background:rgba(255,255,255,0.03);padding:10px;border-radius:6px;line-height:1.8;white-space:pre;font-family:monospace;font-size:12px;color:var(--text-secondary)"># 每行一个账号，逗号或竖线分隔
# 格式: 名称,email,globalApiKey
# 或者: 名称,accountId,apiToken
主账号,your@email.com,your_global_api_key
备用号,your_account_id,your_api_token
测试号|test@mail.com|api_key_here</div>
        </div>
        <div class="form-group" id="formatHintCSV" style="display:none">
            <div class="hint" style="background:rgba(255,255,255,0.03);padding:10px;border-radius:6px;line-height:1.8;white-space:pre;font-family:monospace;font-size:12px;color:var(--text-secondary)"># Email方式
name,Email,GlobalAPIKey
主账号,your@email.com,your_global_api_key

# 或 Token方式
name,AccountID,APIToken
备用号,your_account_id,your_api_token</div>
        </div>
        <div class="form-group">
            <label>粘贴凭证内容 或 <a href="javascript:void(0)" onclick="document.getElementById('envFileInput').click()" style="color:var(--accent);text-decoration:underline">选择文件导入</a></label>
            <input type="file" id="envFileInput" accept=".env,.txt,.csv" style="display:none" onchange="loadEnvFile(event)">
            <textarea id="batchText" rows="10" placeholder="在此粘贴 .env 内容、CSV 或单行格式的凭证..."></textarea>
        </div>
        <div class="form-group">
            <label>导入模式</label>
            <div class="radio-group">
                <label><input type="radio" name="importMode" value="merge" checked> 追加（保留现有账号，跳过同名）</label>
                <label><input type="radio" name="importMode" value="overwrite"> 覆盖（清除现有账号）</label>
            </div>
        </div>
        <div class="import-result" id="importResult"></div>
        <div class="modal-actions">
            <button class="btn-cancel" onclick="closeBatchImportModal()">取消</button>
            <button class="btn-save" onclick="submitBatchImport()">导入</button>
        </div>
    </div>
</div>

<script>
let allAccounts = [];
let currentAuthMethod = 'email';

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
    loadAccounts();
});

// ---- API helpers ----
async function api(path, method = 'GET', body = null) {
    const opts = { method, headers: {} };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    return res.json();
}

// ---- Toast ----
function showToast(msg, type = 'info') {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast ' + type + ' show';
    setTimeout(() => t.classList.remove('show'), 3000);
}

// ---- Number formatting ----
function fmtNum(n) {
    if (n === null || n === undefined || isNaN(n)) return '-';
    return n.toLocaleString('en-US');
}

function getUsagePercent(total, max) {
    if (!max) return 0;
    return Math.min((total / max) * 100, 100);
}

function getUsageColor(percent) {
    if (percent >= 90) return 'var(--red)';
    if (percent >= 70) return 'var(--orange)';
    if (percent >= 50) return 'var(--yellow)';
    return 'var(--green)';
}

function getStatusClass(percent) {
    if (percent >= 90) return 'status-err';
    if (percent >= 70) return 'status-warn';
    return 'status-ok';
}

function computeSummary(accountResults) {
    let totalPages = 0, totalWorkers = 0, totalRequests = 0, totalMax = 0;
    let successCount = 0, failCount = 0;
    for (const item of accountResults) {
        if (item.usage?.success) {
            successCount++;
            totalPages += item.usage.pages || 0;
            totalWorkers += item.usage.workers || 0;
            totalRequests += item.usage.total || 0;
            totalMax += item.usage.max || 100000;
        } else {
            failCount++;
        }
    }
    return { totalPages, totalWorkers, totalRequests, totalMax, successCount, failCount, accountCount: accountResults.length };
}

// ---- Load accounts ----
async function loadAccounts() {
    try {
        const data = await api('/api/accounts');
        allAccounts = data;
        renderAccounts(data);
        // Calculate initial summary from stored data
        const initialSummary = computeSummary(data.map(acc => ({ usage: acc.lastUsage })));
        renderSummary(initialSummary);
        // Auto refresh usage after loading
        refreshAll();
    } catch (e) {
        document.getElementById('accountList').innerHTML = '<div class="empty-state"><h3>加载失败</h3><p>' + e.message + '</p></div>';
    }
}

// ---- Render accounts ----
function renderAccounts(accounts) {
    const container = document.getElementById('accountList');
    if (!accounts || accounts.length === 0) {
        container.innerHTML = '<div class="empty-state"><h3>暂无账号</h3><p>点击右上角「添加账号」开始监控</p><button class="btn-accent" style="padding:10px 24px;border-radius:8px;border:none;cursor:pointer;font-size:14px;color:#fff;background:var(--accent)" onclick="openAddModal()">添加第一个账号</button></div>';
        return;
    }

    container.innerHTML = '<div class="account-grid">' + accounts.map(acc => {
        const usage = acc.lastUsage;
        const hasUsage = usage && usage.success;
        const percent = hasUsage ? getUsagePercent(usage.total, usage.max) : 0;
        const pagesPercent = hasUsage && usage.max ? (usage.pages / usage.max * 100) : 0;
        const workersPercent = hasUsage && usage.max ? (usage.workers / usage.max * 100) : 0;
        const authType = acc.Email ? 'Email' : 'Token';
        const statusCls = hasUsage ? getStatusClass(percent) : 'status-idle';

        return \`<div class="account-card" id="card-\${acc.id}">
            <div class="account-actions">
                <button onclick="queryOne('\${acc.id}')" title="刷新">刷新</button>
                <button onclick="openEditModal('\${acc.id}')" title="编辑">编辑</button>
                <button class="btn-del" onclick="deleteAcc('\${acc.id}', '\${acc.name}')" title="删除">删除</button>
            </div>
            <div class="account-name">
                <span class="status-dot \${statusCls}"></span>
                \${escHtml(acc.name)}
            </div>
            <div class="account-meta">
                <span class="account-auth-type">\${authType}</span>
                \${acc.Email ? ' ' + escHtml(acc.Email) : ''}
                \${acc.AccountID ? ' ID: ' + escHtml(acc.AccountID) : ''}
            </div>
            <div class="usage-section">
                \${hasUsage ? \`
                <div class="usage-bar-container">
                    <div class="usage-bar" style="width:\${Math.max(percent, 0.5)}%">
                        <div class="pages-bar" style="width:\${pagesPercent > 0 ? (pagesPercent / percent * 100) : 0}%"></div>
                        <div class="workers-bar" style="width:\${workersPercent > 0 ? (workersPercent / percent * 100) : 0}%"></div>
                    </div>
                </div>
                <div class="usage-stats">
                    <span style="color:\${getUsageColor(percent)}">\${percent.toFixed(1)}%</span>
                    <span>\${fmtNum(usage.total)} / \${fmtNum(usage.max)}</span>
                </div>
                <div class="usage-detail">
                    <div class="usage-detail-item"><span><span class="dot dot-pages"></span>Pages</span><span>\${fmtNum(usage.pages)}</span></div>
                    <div class="usage-detail-item"><span><span class="dot dot-workers"></span>Workers</span><span>\${fmtNum(usage.workers)}</span></div>
                </div>
                \` : \`
                <div style="color:var(--text-secondary);font-size:13px;padding:12px 0">
                    \${usage?.error ? '查询失败: ' + escHtml(usage.error) : '暂无用量数据，点击刷新查询'}
                </div>
                \`}
            </div>
            <div class="query-time">\${acc.lastQueryTime ? '查询时间: ' + new Date(acc.lastQueryTime).toLocaleString('zh-CN') : ''}</div>
        </div>\`;
    }).join('') + '</div>';
}

// ---- Refresh all ----
async function refreshAll() {
    const btn = document.getElementById('refreshBtn');
    btn.disabled = true;
    btn.textContent = '查询中...';
    
    // Show loading state for all account cards
    document.querySelectorAll('.account-card').forEach(card => {
        card.style.opacity = '0.6';
    });
    
    try {
        const data = await api('/api/usage/all');
        // Update account list with usage data
        if (data.accounts) {
            for (const item of data.accounts) {
                const acc = allAccounts.find(a => a.id === item.id);
                if (acc) {
                    acc.lastUsage = item.usage;
                    acc.lastQueryTime = item.lastQueryTime;
                }
            }
            renderAccounts(allAccounts);
        }
        // Update summary - always try to render summary if possible
        if (data.summary) {
            renderSummary(data.summary);
        } else {
            // If no summary in response, compute it from accounts data
            const summary = computeSummary(data.accounts || []);
            renderSummary(summary);
        }
        document.getElementById('lastRefresh').textContent = '上次刷新: ' + new Date().toLocaleString('zh-CN');
        showToast('用量数据已更新', 'success');
        
    } catch (e) {
        showToast('查询失败: ' + e.message, 'error');
    }
    
    // Restore normal state
    document.querySelectorAll('.account-card').forEach(card => {
        card.style.opacity = '1';
    });
    btn.disabled = false;
    btn.textContent = '刷新用量';
}

// ---- Render summary ----
function renderSummary(s) {
    document.getElementById('sumAccounts').textContent = s.accountCount;
    document.getElementById('sumTotal').textContent = fmtNum(s.totalRequests);
    const totalPct = s.totalMax ? (s.totalRequests / s.totalMax * 100).toFixed(1) : 0;
    document.getElementById('sumTotalSub').textContent = '占总配额 ' + totalPct + '%';
    document.getElementById('sumTotal').style.color = getUsageColor(parseFloat(totalPct));
    document.getElementById('sumPages').textContent = fmtNum(s.totalPages);
    document.getElementById('sumWorkers').textContent = fmtNum(s.totalWorkers);
    document.getElementById('sumMax').textContent = fmtNum(s.totalMax);
    document.getElementById('sumMaxSub').textContent = s.accountCount + ' 个账号 x 100,000';
    document.getElementById('sumStatus').innerHTML = \`<span class="text-green">\${s.successCount} 成功</span>\${s.failCount > 0 ? ' / <span class="text-red">' + s.failCount + ' 失败</span>' : ''}\`;
}

// ---- Query single ----
async function queryOne(id) {
    const card = document.getElementById('card-' + id);
    if (card) card.style.opacity = '0.6';
    try {
        const data = await api('/api/usage/' + id);
        const acc = allAccounts.find(a => a.id === id);
        if (acc) {
            acc.lastUsage = data.lastUsage;
            acc.lastQueryTime = data.lastQueryTime;
        }
        renderAccounts(allAccounts);
        showToast('已更新 ' + (data.name || ''), 'success');
    } catch (e) {
        showToast('查询失败', 'error');
    }
    if (card) card.style.opacity = '1';
}

// ---- Auth method switch ----
function switchAuthMethod(method, btn) {
    currentAuthMethod = method;
    document.querySelectorAll('.auth-method-tabs button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('emailFields').classList.toggle('active', method === 'email');
    document.getElementById('tokenFields').classList.toggle('active', method === 'token');
}

// ---- Modal ----
function openAddModal() {
    document.getElementById('modalTitle').textContent = '添加账号';
    document.getElementById('editId').value = '';
    document.getElementById('accName').value = '';
    document.getElementById('accEmail').value = '';
    document.getElementById('accGlobalAPIKey').value = '';
    document.getElementById('accAccountID').value = '';
    document.getElementById('accAPIToken').value = '';
    switchAuthMethod('email', document.querySelector('.auth-method-tabs button'));
    document.getElementById('accountModal').classList.add('active');
}

function openEditModal(id) {
    const acc = allAccounts.find(a => a.id === id);
    if (!acc) return;
    document.getElementById('modalTitle').textContent = '编辑账号';
    document.getElementById('editId').value = id;
    document.getElementById('accName').value = acc.name || '';
    // Note: credentials are masked, user must re-enter to update
    document.getElementById('accEmail').value = acc.Email || '';
    document.getElementById('accGlobalAPIKey').value = '';
    document.getElementById('accAccountID').value = acc.AccountID || '';
    document.getElementById('accAPIToken').value = '';
    const method = acc.Email ? 'email' : 'token';
    switchAuthMethod(method, document.querySelectorAll('.auth-method-tabs button')[method === 'email' ? 0 : 1]);
    document.getElementById('accountModal').classList.add('active');
}

function closeModal() {
    document.getElementById('accountModal').classList.remove('active');
}

// Close modal on overlay click
document.getElementById('accountModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeModal();
});

// ---- Save account ----
async function saveAccount() {
    const id = document.getElementById('editId').value;
    const name = document.getElementById('accName').value.trim();
    if (!name) { showToast('请输入账号名称', 'error'); return; }

    const body = { name };
    if (currentAuthMethod === 'email') {
        body.Email = document.getElementById('accEmail').value.trim();
        body.GlobalAPIKey = document.getElementById('accGlobalAPIKey').value.trim();
        if (!id && (!body.Email || !body.GlobalAPIKey)) {
            showToast('请填写 Email 和 Global API Key', 'error');
            return;
        }
    } else {
        body.AccountID = document.getElementById('accAccountID').value.trim();
        body.APIToken = document.getElementById('accAPIToken').value.trim();
        if (!id && (!body.AccountID || !body.APIToken)) {
            showToast('请填写 Account ID 和 API Token', 'error');
            return;
        }
    }

    try {
        if (id) {
            // Update: only send non-empty fields
            const updateBody = { name };
            if (body.Email) updateBody.Email = body.Email;
            if (body.GlobalAPIKey) updateBody.GlobalAPIKey = body.GlobalAPIKey;
            if (body.AccountID) updateBody.AccountID = body.AccountID;
            if (body.APIToken) updateBody.APIToken = body.APIToken;
            await api('/api/accounts/' + id, 'PUT', updateBody);
            showToast('账号已更新', 'success');
        } else {
            await api('/api/accounts', 'POST', body);
            showToast('账号已添加', 'success');
        }
        closeModal();
        loadAccounts();
    } catch (e) {
        showToast('保存失败: ' + e.message, 'error');
    }
}

// ---- Delete account ----
async function deleteAcc(id, name) {
    if (!confirm('确认删除账号「' + name + '」？此操作不可撤销。')) return;
    try {
        await api('/api/accounts/' + id, 'DELETE');
        showToast('已删除', 'success');
        loadAccounts();
    } catch (e) {
        showToast('删除失败', 'error');
    }
}

// ---- Export/Import ----
async function exportConfig() {
    try {
        const res = await fetch('/api/export');
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'cf-usage-accounts.json';
        a.click();
        showToast('配置已导出', 'success');
    } catch (e) {
        showToast('导出失败', 'error');
    }
}

async function importConfig(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (!confirm('导入将覆盖现有配置，共 ' + data.length + ' 个账号，确认导入？')) return;
        await api('/api/import', 'POST', data);
        showToast('导入成功', 'success');
        loadAccounts();
    } catch (e) {
        showToast('导入失败: ' + e.message, 'error');
    }
    event.target.value = '';
}

// ---- Batch Import ----
function openBatchImportModal() {
    document.getElementById('batchText').value = '';
    const resultEl = document.getElementById('importResult');
    resultEl.className = 'import-result';
    resultEl.style.display = 'none';
    switchFormatTab('env', document.querySelector('.format-tabs button'));
    document.getElementById('batchImportModal').classList.add('active');
}

function closeBatchImportModal() {
    document.getElementById('batchImportModal').classList.remove('active');
}

document.getElementById('batchImportModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeBatchImportModal();
});

function switchFormatTab(fmt, btn) {
    document.querySelectorAll('.format-tabs button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('formatHintEnv').style.display = fmt === 'env' ? '' : 'none';
    document.getElementById('formatHintCompact').style.display = fmt === 'compact' ? '' : 'none';
    document.getElementById('formatHintCSV').style.display = fmt === 'csv' ? '' : 'none';
}

function loadEnvFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    file.text().then(text => {
        document.getElementById('batchText').value = text;
        showToast('已加载文件: ' + file.name, 'info');
    });
    event.target.value = '';
}

async function submitBatchImport() {
    const text = document.getElementById('batchText').value.trim();
    if (!text) { showToast('请输入或粘贴凭证内容', 'error'); return; }
    const mode = document.querySelector('input[name="importMode"]:checked').value;
    const resultEl = document.getElementById('importResult');

    try {
        const res = await api('/api/import-env', 'POST', { text, mode });
        if (res.error) {
            resultEl.className = 'import-result error show';
            resultEl.textContent = '导入失败: ' + res.error;
            return;
        }
        resultEl.className = 'import-result success show';
        resultEl.textContent = '解析 ' + res.parsed + ' 个账号，成功导入 ' + res.added + ' 个' + (res.skipped > 0 ? '，跳过 ' + res.skipped + ' 个（同名）' : '') + '，当前共 ' + res.total + ' 个账号';
        showToast('批量导入成功', 'success');
        loadAccounts();
    } catch (e) {
        resultEl.className = 'import-result error show';
        resultEl.textContent = '导入失败: ' + e.message;
    }
}

// ---- Utility ----
function escHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
</script>
</body>
</html>`;
}
