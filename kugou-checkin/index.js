// ============================================================
// 酷狗概念版自动签到插件（echomusic 插件）
// 签到逻辑移植自 github.com/zhangye151/kgcheckin
// 无激活码、无卡密，直接用当前在 EchoMusic 登录的账号签到
// ============================================================

// ---------------- 工具函数 ----------------
function utf8Encode(s) { return new TextEncoder().encode(s); }
function utf8Decode(b) { return new TextDecoder().decode(b); }
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------- MD5（纯 JS，RFC 1321） ----------------
function md5(input) {
  const bytes = typeof input === 'object' ? utf8Encode(JSON.stringify(input)) : utf8Encode(String(input));
  const blockSize = 64;
  const msgLen = bytes.length;
  const bitLen = msgLen * 8;
  const bufLen = Math.floor((msgLen + 9 + blockSize - 1) / blockSize) * blockSize;
  const withPad = new Uint8Array(bufLen);
  withPad.set(bytes);
  withPad[msgLen] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 8, bitLen >>> 0, true);
  dv.setUint32(withPad.length - 4, Math.floor(bitLen / 0x100000000) >>> 0, true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const T = new Array(64);
  for (let i = 0; i < 64; i++) T[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
             5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
             4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
             6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const rol = (n, c) => (n << c | n >>> (32 - c)) >>> 0;
  for (let off = 0; off < withPad.length; off += 64) {
    const M = new Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + T[i] + M[g]) >>> 0;
      A = D; D = C; C = B; B = (B + rol(F, S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true); odv.setUint32(4, b0, true); odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
  return bytesToHex(out);
}

// ---------------- AES-256-CBC（WebCrypto） ----------------
async function aesEncrypt(data, keyStr, ivStr) {
  const keyBytes = utf8Encode(keyStr);
  const ivBytes = utf8Encode(ivStr);
  const dataBytes = typeof data === 'object' ? utf8Encode(JSON.stringify(data)) : utf8Encode(data);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
  const buf = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, key, dataBytes);
  return bytesToHex(new Uint8Array(buf));
}

// ---------------- RSA 裸加密（1024 位，BigInt） ----------------
const LITE_N = BigInt('0xc40a2d0da76511f3bb1cc2bbd3afbd8bea83b4d6b05b6c13eb8920c53f1af7679b32ba0d0edb843240ef1b836efed3ee240734c14c1399fd6594d16af22f52525d14d72e0155c6dcc8638d4f7bb94f3a0b1f4c29f991972f2a160a25eb0a9e724336be7f69bbd319ffab1c6dd8470b021dc434f3faba89f4a2a01b33bdbdd08b');
const RSA_E = 65537n;
function modPow(base, exp, mod) {
  let r = 1n, b = base % mod, e = exp;
  while (e > 0n) { if (e & 1n) r = (r * b) % mod; e >>= 1n; b = (b * b) % mod; }
  return r;
}
async function rsaEncrypt(data) {
  const json = typeof data === 'object' ? JSON.stringify(data) : String(data);
  const msg = utf8Encode(json);
  const padded = new Uint8Array(128);
  padded.set(msg, 0);
  let m = 0n;
  for (let i = 0; i < 128; i++) m = (m << 8n) | BigInt(padded[i]);
  const c = modPow(m, RSA_E, LITE_N);
  let hex = c.toString(16).padStart(256, '0');
  return hex;
}

// ---------------- 请求签名 ----------------
const LITE_SIGN_SECRET = 'LnT6xpN3khm36zse0QzvmgTZ3waWdRSA';
function signatureAndroid(params, data) {
  const keys = Object.keys(params).sort();
  const str = keys.map(k => `${k}=${typeof params[k] === 'object' ? JSON.stringify(params[k]) : params[k]}`).join('');
  return md5(LITE_SIGN_SECRET + str + (data || '') + LITE_SIGN_SECRET);
}

// ---------------- 酷狗配置 ----------------
const APPID = 3116;          // liteAppid（概念版）
const CLIENTVER = 11436;     // liteClientver
const DEFAULT_UA = 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi';
const GATEWAY = 'https://gateway.kugou.com';

let ctx = null;
const $vue = { defineComponent: null, h: null, ref: null };
let toastApi = null;

// 从 EchoMusic 的 pinia 读取当前登录账号
function getAuth() {
  try {
    const app = document.querySelector('#app');
    const pinia = app && app.__vue_app__ && app.__vue_app__.config.globalProperties.$pinia;
    const userState = pinia && pinia.state && pinia.state.value && pinia.state.value.user;
    const deviceState = pinia && pinia.state && pinia.state.value && pinia.state.value.device;
    return {
      token: (userState && userState.info && userState.info.token) || '',
      userid: String((userState && userState.info && userState.info.userid) || ''),
      dfid: (deviceState && deviceState.info && deviceState.info.dfid) || '-',
      guid: (deviceState && deviceState.info && deviceState.info.guid) || '',
      dev: (deviceState && deviceState.info && deviceState.info.serverDev) || '',
      mac: (deviceState && deviceState.info && deviceState.info.mac) || '',
    };
  } catch (e) {
    return { token: '', userid: '', dfid: '-', guid: '', dev: '', mac: '' };
  }
}

// 通用请求（移植自 request.js，底层用 ctx.net.fetch）
async function kgRequest(opts) {
  const dfid = (opts.cookie && opts.cookie.dfid) || '-';
  const dfidMd5 = md5(dfid);
  const mid = dfidMd5 + dfidMd5.slice(0, 7);
  const uuid = md5(dfid + mid);
  const token = (opts.cookie && opts.cookie.token) || '';
  const userid = (opts.cookie && opts.cookie.userid) || 0;
  const clienttime = Math.floor(Date.now() / 1000);

  const headers = Object.assign({
    'User-Agent': DEFAULT_UA,
    dfid: String(dfid),
    clienttime: String(clienttime),
    mid: mid,
  }, opts.headers || {});

  const defaultParams = {
    dfid, mid, uuid,
    appid: APPID, clientver: CLIENTVER,
    userid, clienttime,
  };
  if (token) defaultParams.token = token;
  const params = Object.assign({}, defaultParams, opts.params || {});

  let dataStr = '';
  if (opts.data !== undefined && opts.data !== null) {
    dataStr = typeof opts.data === 'object' ? JSON.stringify(opts.data) : String(opts.data);
  }
  if (!params.signature && !opts.notSignature) {
    params.signature = signatureAndroid(params, dataStr);
  }

  const baseURL = opts.baseURL || GATEWAY;
  const qs = Object.keys(params)
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
    .join('&');
  const url = `${baseURL}${opts.url}?${qs}`;

  const fetchOpts = { method: opts.method || 'GET', headers };
  if (dataStr) {
    fetchOpts.method = 'POST';
    fetchOpts.headers['content-type'] = 'application/json; charset=utf-8';
    fetchOpts.body = dataStr;
  }
  const resp = await ctx.net.fetch(url, fetchOpts);
  const body = await resp.json();
  if (!opts.tolerateError && (body.status === 0 || (body.error_code && body.error_code !== 0))) {
    const err = new Error(body.msg || body.message || body.error || ('error_code ' + (body.error_code || body.status)));
    err.body = body;
    throw err;
  }
  return body;
}

// ---------------- 业务接口 ----------------
async function getUserDetail(cookie) {
  const clienttime_ms = Math.floor(Date.now() / 1000);
  const pk = (await rsaEncrypt({ token: cookie.token, clienttime: clienttime_ms })).toUpperCase();
  return kgRequest({
    url: '/v3/get_my_info', method: 'POST',
    data: { visit_time: clienttime_ms, usertype: 1, p: pk, userid: Number(cookie.userid) || 0 },
    params: { plat: 1 }, cookie,
    headers: { 'x-router': 'usercenter.kugou.com' },
  });
}
async function listenSong(cookie) {
  return kgRequest({
    url: '/youth/v2/report/listen_song', method: 'POST',
    data: { mixsongid: 666075191 },
    params: { clientver: 10566 }, cookie,
    headers: { 'user-agent': 'Android13-1070-10566-201-0-ReportPlaySongToServerProtocol-wifi' },
    tolerateError: true,
  });
}
async function watchAd(cookie) {
  const t = Date.now();
  return kgRequest({
    url: '/youth/v1/ad/play_report', method: 'POST',
    data: { ad_id: 12307537187, play_end: t, play_start: t - 30000 },
    cookie,
    tolerateError: true,
  });
}
async function getVipDetail(cookie) {
  return kgRequest({
    baseURL: 'https://kugouvip.kugou.com',
    url: '/v1/get_union_vip', method: 'GET',
    params: { busi_type: 'concept' }, cookie,
    tolerateError: true,
  });
}

// 错误码 → 友好文案（代号只用于日志判断，界面上不直接暴露）
const ERROR_TEXT = {
  130012: '听歌奖励今日已领取',
  130011: '听歌奖励今日尚未开始',
  30002: '今日广告次数已用完',
  20028: '广告奖励今日已领取',
};
function friendlyText(body) {
  if (!body) return '未知错误';
  const code = body.error_code || body.status;
  if (ERROR_TEXT[code]) return ERROR_TEXT[code];
  return body.msg || body.message || body.error || ('错误码 ' + code);
}

// 解析 VIP 到期时间，返回 {valid, remainMs}
function parseVip(endTime) {
  if (!endTime) return { valid: false, remainMs: 0 };
  let ts;
  if (typeof endTime === 'number') ts = endTime < 1e12 ? endTime * 1000 : endTime;
  else {
    const n = Number(endTime);
    if (!isNaN(n)) ts = n < 1e12 ? n * 1000 : n;
    else ts = Date.parse(String(endTime).replace(/-/g, '/'));
  }
  if (isNaN(ts)) return { valid: false, remainMs: 0 };
  const remain = ts - Date.now();
  return { valid: remain > 0, remainMs: remain };
}
// 剩余毫秒 → "X 小时 X 分钟"
function remainText(ms) {
  if (ms <= 0) return '已过期';
  const totalMin = Math.floor(ms / 60000);
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h > 0) return `剩余 ${h} 小时 ${m} 分`;
  return `剩余 ${m} 分钟`;
}
// product_type → 中文名
// svip = 概念会员（完整会员），tvip = 畅听会员（随心畅听包）
const VIP_TYPE_NAME = {
  svip: '概念会员',
  tvip: '畅听会员',
};
function vipLabel(item) {
  return VIP_TYPE_NAME[item.product_type] || item.vip_name || item.name || '会员';
}
// 拉取所有会员状态，返回 [{label, remainMs, valid}]
async function getVipList(cookie) {
  const vip = await getVipDetail(cookie);
  const list = (vip && vip.data && vip.data.busi_vip) || [];
  const out = [];
  for (const item of list) {
    const endTime = item.vip_end_time || item.end_time || item.expire_time || '';
    const parsed = parseVip(endTime);
    out.push({
      label: vipLabel(item),
      remainMs: parsed.remainMs,
      valid: parsed.valid,
      raw: item,
    });
  }
  return out;
}
// 加载时就拉一次会员状态（不依赖签到按钮）
async function refreshVipList(state) {
  try {
    const auth = getAuth();
    if (!auth.token) return;
    const list = await getVipList(auth);
    state.vipList.value = list;
  } catch (e) { /* 静默，签到时会再试 */ }
}

// ---------------- 签到流程 ----------------
const TASK_ID = 'kugou-checkin-sign';
let taskDisposer = null;

function startTask(label) {
  try {
    taskDisposer = ctx.tasks.register({
      id: TASK_ID, name: '酷狗签到',
      icon: ctx.icons && ctx.icons.iconStar,
      status: 'running', retention: 'action-required', priority: 10,
      progress: { done: 0, total: 4, percent: 0, label: label || '正在签到' },
    });
  } catch (e) { taskDisposer = null; }
}
function updateTask(patch) { if (taskDisposer) taskDisposer.update(patch); }
function finishTask(status, patch) {
  if (taskDisposer) { taskDisposer.finish(status, patch); taskDisposer = null; }
}
function dismissTask() { if (taskDisposer) { taskDisposer.dismiss(); taskDisposer = null; } }

const sleep = ms => new Promise(r => setTimeout(r, ms));
function todayStr() { return new Date().toISOString().slice(0, 10); }

async function runSign(state, opts = {}) {
  const { auto = false, force = false } = opts;
  state.busy.value = true;
  state.logs.value = [];
  const log = msg => {
    const t = new Date().toLocaleTimeString();
    state.logs.value.push(`[${t}] ${msg}`);
  };
  const setStatus = (s, text) => { state.status.value = s; state.statusText.value = text; };

  setStatus('loading', '正在获取凭证...');
  const auth = getAuth();
  if (!auth.token) {
    setStatus('error', '未登录');
    if (!auto) toastApi.danger('未获取到登录凭证，请先在 EchoMusic 中登录酷狗概念版');
    state.busy.value = false;
    return;
  }
  log(`已获取账号 userid=${auth.userid}`);

  startTask('验证 token');
  try {
    // 1. 验证 token
    updateTask({ progress: { done: 0, total: 4, percent: 0, label: '验证 token' } });
    const userInfo = await getUserDetail(auth);
    const nickname = (userInfo && userInfo.data && userInfo.data.nickname) || '未知用户';
    log(`账号：${nickname}`);

    // 2. 听歌领 VIP（以"今天签没签过"为准，今天没签就执行，不看当前 VIP 是否还有效，避免晚上断档）
    setStatus('loading', '听歌领取 VIP...');
    updateTask({ progress: { done: 1, total: 4, percent: 25, label: '听歌领取' } });
    const listen = await listenSong(auth);
    if (listen.status === 1) log('听歌领取成功');
    else log('听歌：' + friendlyText(listen));

    // 4. 看广告领 VIP（最多 8 次，成功后间隔 30s）
    setStatus('loading', '看广告领取 VIP...');
    updateTask({ progress: { done: 2, total: 4, percent: 50, label: '广告领取' } });
    let adCount = 0;
    for (let j = 1; j <= 8; j++) {
      const ad = await watchAd(auth);
      if (ad.status === 1) {
        adCount++;
        log(`第 ${j} 次广告领取成功`);
        if (j < 8) await sleep(30 * 1000);
      } else {
        log('广告：' + friendlyText(ad));
        break;
      }
    }

    // 5. 查询会员到期时间（畅听/概念等）
    setStatus('loading', '查询会员到期时间...');
    updateTask({ progress: { done: 3, total: 4, percent: 75, label: '查询会员' } });
    try {
      const vipList = await getVipList(auth);
      state.vipList.value = vipList;
      if (vipList.length === 0) {
        log('未获取到会员信息');
      } else {
        for (const v of vipList) {
          log(v.label + '：' + (v.valid ? remainText(v.remainMs) : '未开通'));
        }
      }
    } catch (e) { log('查询会员到期失败：' + e.message); }

    const today = todayStr();
    await ctx.storage.set('kugou-checkin:lastSignDate', today);
    state.lastSignDate.value = today;
    setStatus('success', adCount > 0 ? `签到完成（领 ${adCount} 次广告）` : '签到完成');
    finishTask('completed', { progress: { done: 4, total: 4, percent: 100, label: '签到完成' } });
    toastApi.success('酷狗签到完成');
  } catch (err) {
    log('签到失败：' + (err.message || err));
    setStatus('error', '签到失败');
    finishTask('error', {
      error: String(err.message || err),
      actions: [{ id: 'retry', label: '重试', variant: 'primary', onClick: () => runSign(state, { force: true }) }],
    });
    if (!auto) toastApi.danger('签到失败：' + (err.message || err));
  } finally {
    state.busy.value = false;
  }
}

// ---------------- UI 组件 ----------------
function buildComponent() {
  const { defineComponent, h, ref } = $vue;
  const state = {
    status: ref('idle'),          // idle/loading/success/error
    statusText: ref('点击开始签到'),
    logs: ref([]),
    busy: ref(false),
    lastSignDate: ref(''),
    vipList: ref([]),
  };

  return defineComponent({
    setup() {
      refreshVipList(state);
      return () => {
        const st = state.status.value;
        const bg = st === 'success'
          ? 'linear-gradient(135deg,#27ae60,#2ecc71)'
          : st === 'error'
            ? 'linear-gradient(135deg,#e74c3c,#c0392b)'
            : st === 'loading'
              ? 'linear-gradient(135deg,#f39c12,#e67e22)'
              : 'var(--color-primary,#409eff)';
        const circle = h('div', {
          style: {
            width: '44px', height: '44px', borderRadius: '50%',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#fff', fontWeight: 700, fontSize: '18px',
            background: bg, flexShrink: 0,
          },
        }, st === 'success' ? '✓' : (st === 'loading' ? '…' : '签'));

        const mainText = h('div', { style: { flex: 1, display: 'flex', flexDirection: 'column' } }, [
          h('div', { style: { fontSize: '14px', fontWeight: 600, color: 'var(--color-text-main,#333)' } }, state.statusText.value),
          state.lastSignDate.value
            ? h('div', { style: { fontSize: '12px', color: 'var(--color-text-secondary,#999)' } }, '上次签到：' + state.lastSignDate.value)
            : null,
        ]);

        const btn = h('div', {
          style: {
            width: '80px', height: '44px', borderRadius: '22px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'var(--color-primary,#409eff)', color: '#fff',
            fontSize: '16px', flexShrink: 0, cursor: state.busy.value ? 'not-allowed' : 'pointer',
            opacity: state.busy.value ? 0.7 : 1,
          },
          onClick: () => { if (!state.busy.value) runSign(state); },
        }, state.busy.value ? '⟳' : '▶');

        const card = h('div', {
          style: {
            display: 'flex', alignItems: 'center', gap: '12px',
            padding: '12px', borderRadius: '12px',
            background: 'var(--color-bg-elevated,#f5f5f5)',
            border: '1px solid var(--border-subtle,#e8e8e8)',
            cursor: state.busy.value ? 'not-allowed' : 'pointer',
          },
          onClick: () => { if (!state.busy.value) runSign(state); },
        }, [circle, mainText, btn]);

        // 会员色：概念会员(svip)橙色，畅听会员(tvip)绿色
        const VIP_COLOR = { '概念会员': '#e67e22', '畅听会员': '#27ae60' };
        const vipRows = state.vipList.value.length
          ? h('div', { style: { display: 'flex', gap: '8px' } },
              state.vipList.value.map(v => h('div', {
                style: {
                  flex: 1, display: 'flex', flexDirection: 'column', gap: '2px',
                  padding: '8px 10px', borderRadius: '8px',
                  background: 'var(--color-bg-elevated,#f5f5f5)',
                  border: '1px solid var(--border-subtle,#e8e8e8)',
                  fontSize: '12px',
                },
              }, [
                h('span', { style: { color: v.valid ? (VIP_COLOR[v.label] || '#e67e22') : 'var(--color-text-secondary,#999)', fontWeight: 600 } }, v.label),
                h('span', { style: { color: v.valid ? (VIP_COLOR[v.label] || '#e67e22') : 'var(--color-text-secondary,#999)' } },
                  v.valid ? remainText(v.remainMs) : '未开通'),
              ])))
          : null;

        const logsNode = state.logs.value.length
          ? h('div', {
              style: {
                marginTop: '12px', padding: '12px', borderRadius: '8px',
                background: 'var(--color-bg-elevated,#f5f5f5)',
                border: '1px solid var(--border-subtle,#e8e8e8)',
                maxHeight: '200px', overflowY: 'auto',
                fontSize: '12px', lineHeight: '1.6',
                fontFamily: 'monospace', whiteSpace: 'pre-wrap',
                color: 'var(--color-text-main,#333)',
              },
            }, state.logs.value.map(line => h('div', null, line)))
          : null;

        return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px', padding: '8px' } }, [
          h('div', { style: { fontSize: '16px', fontWeight: 600, marginBottom: '4px' } }, '酷狗概念版签到'),
          card,
          vipRows,
          h('div', { style: { fontSize: '12px', color: 'var(--color-text-secondary,#999)', padding: '4px 4px 0' } },
            '每日听歌 + 看广告领取 VIP，使用当前登录账号'),
          logsNode,
        ]);
      };
    },
  });
}

// ---------------- 入口 ----------------
export default async function (appCtx) {
  ctx = appCtx;
  const v = ctx.vue || {};
  $vue.defineComponent = v.defineComponent;
  $vue.h = v.h;
  $vue.ref = v.ref;
  toastApi = ctx.toast || { success(){}, danger(){}, warning(){} };

  const Component = buildComponent();
  ctx.ui.settings.define({
    id: 'default',
    title: '酷狗签到',
    description: '酷狗概念版每日自动签到',
    component: Component,
  });

  ctx.dispose(() => { dismissTask(); });

  // 启动时自动签到一次（若今日未签过）
  try {
    const last = await ctx.storage.get('kugou-checkin:lastSignDate') || '';
    if (last !== todayStr()) {
      // 延迟一点，等 app 就绪
      setTimeout(() => runSign({
        status: { value: 'idle' }, statusText: { value: '自动签到' },
        logs: { value: [] }, busy: { value: false }, lastSignDate: { value: last },
        vipList: { value: [] },
      }, { auto: true }), 1500);
    }
  } catch (e) { /* 自动签到失败不阻塞 */ }
}
