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
// 全程静默：不在 echomusic 任务中心注册任何任务，状态只在插件设置页展示
const sleep = ms => new Promise(r => setTimeout(r, ms));
function todayStr() { return new Date().toISOString().slice(0, 10); }
// 把到期/续签时间戳格式化为"约 X 小时 X 分后（HH:mm）"
function formatRenewAt(ts) {
  const diff = Math.max(0, ts - Date.now());
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const when = h > 0 ? `约 ${h} 小时 ${m} 分后` : (m > 0 ? `约 ${m} 分后` : '即将');
  return `${when}（${hh}:${mm}）`;
}

// 全局签到互斥：启动签到、后台续签、手动签到共用，避免并发重复请求
let signing = false;

// ---------------- 搜索快捷键 ----------------
// 快捷键 → 打开 echomusic 搜索页并聚焦顶栏搜索框；组合可在插件设置页自定义
// 按键严格区分：按下 ⌘ 就是 Meta，按下 Ctrl 就是 Ctrl，不做 CmdOrCtrl 合并
function displayAcc(acc) {
  return String(acc || '').replace('Meta', '⌘');
}
let disposeSearchShortcut = null;
async function registerSearchShortcut(acc) {
  if (disposeSearchShortcut) { try { disposeSearchShortcut(); } catch (e) {} disposeSearchShortcut = null; }
  if (!acc) return;
  try {
    disposeSearchShortcut = ctx.shortcuts.register(acc, () => {
      try {
        if (ctx.router.currentRoute.value.name !== 'search') {
          ctx.router.push({ name: 'search' });
        }
        // 打开顶栏搜索：echomusic 的搜索框默认折叠成图标按钮，须先触发展开
        // 折叠态：点击 .tb-search 里的搜索按钮（echomusic 原生展开并聚焦输入框）
        // 展开态：直接聚焦 .tb-search-input
        const openSearch = () => {
          let tries = 0;
          const attempt = () => {
            const input = document.querySelector('.tb-search-expanded .tb-search-input')
              || document.querySelector('.tb-search .tb-search-input');
            if (input) {
              input.focus({ preventScroll: true });
              return;
            }
            const btn = document.querySelector('.tb-search .nav-btn');
            if (btn) {
              btn.click();
              // echomusic 展开后异步加载热搜索再聚焦，补一次兜底聚焦
              setTimeout(() => {
                const el = document.querySelector('.tb-search-expanded .tb-search-input');
                if (el) el.focus({ preventScroll: true });
              }, 350);
              return;
            }
            if (tries < 8) { tries++; setTimeout(attempt, 100); }
          };
          attempt();
        };
        setTimeout(openSearch, 60);
        setTimeout(openSearch, 400);
      } catch (e) { /* 静默 */ }
    });
  } catch (e) {
    // 无效的快捷键组合：不注册，等待设置页重新配置
    disposeSearchShortcut = null;
    throw e;
  }
}

async function runSign(state, opts = {}) {
  const { auto = false, force = false } = opts;
  if (signing) return;
  signing = true;
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
    signing = false;
    return;
  }
  log(`已获取账号 userid=${auth.userid}`);

  try {
    // 1. 验证 token
    const userInfo = await getUserDetail(auth);
    const nickname = (userInfo && userInfo.data && userInfo.data.nickname) || '未知用户';
    log(`账号：${nickname}`);

    // 2. 听歌领 VIP（以"今天签没签过"为准，今天没签就执行，不看当前 VIP 是否还有效，避免晚上断档）
    setStatus('loading', '听歌领取 VIP...');
    const listen = await listenSong(auth);
    if (listen.status === 1) log('听歌领取成功');
    else log('听歌：' + friendlyText(listen));

    // 3. 看广告领 VIP（静默执行：不注册任务、不弹提示；最多 8 次，成功后间隔 30s）
    setStatus('loading', '看广告领取 VIP...');
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

    // 4. 查询会员到期时间（畅听/概念等）
    setStatus('loading', '查询会员到期时间...');
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
    setStatus('success', '签到完成');
    if (!auto) toastApi.success('酷狗签到完成');
  } catch (err) {
    log('签到失败：' + (err.message || err));
    setStatus('error', '签到失败');
    if (!auto) toastApi.danger('签到失败：' + (err.message || err));
  } finally {
    state.busy.value = false;
    signing = false;
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
    nextRenewAt: ref(''),
    searchShortcut: ref('Meta+F'),
  };

  return defineComponent({
    setup() {
      refreshVipList(state);
      ctx.storage.get('kugou-checkin:nextRenewAt').then(ts => {
        if (ts) state.nextRenewAt.value = formatRenewAt(ts);
      }).catch(() => {});
      ctx.storage.get('kugou-checkin:searchShortcut').then(acc => {
        if (acc) state.searchShortcut.value = acc;
      }).catch(() => {});
      // 快捷键捕获：点击输入框后直接按下组合键（如 ⌘⇧F），无需手写格式
      let capturing = false;
      let lastAcc = '';
      const saveSearchShortcut = async () => {
        const acc = String(state.searchShortcut.value || '').trim();
        if (!acc) { toastApi.warning('请先点击输入框并按下组合键'); return; }
        try {
          await registerSearchShortcut(acc);
          await ctx.storage.set('kugou-checkin:searchShortcut', acc);
          toastApi.success('搜索快捷键已保存：' + displayAcc(acc));
        } catch (e) {
          toastApi.danger('快捷键无效：' + (e.message || e));
        }
      };
      const onShortcutKeydown = (e) => {
        if (capturing) {
          e.preventDefault();
          e.stopPropagation();
          if (e.key === 'Escape') {
            capturing = false;
            state.searchShortcut.value = lastAcc;
            e.target.blur();
            return;
          }
          if (e.key === 'Enter') {
            e.target.blur();
            saveSearchShortcut();
            return;
          }
          const parts = [];
          if (e.metaKey) parts.push('Meta');
          if (e.ctrlKey) parts.push('Ctrl');
          if (e.altKey) parts.push('Alt');
          if (e.shiftKey) parts.push('Shift');
          const k = e.key;
          if (!['Control', 'Shift', 'Alt', 'Meta'].includes(k)) {
            parts.push(k === ' ' ? 'Space' : (k.length === 1 ? k.toUpperCase() : k));
          }
          if (parts.length > 1) state.searchShortcut.value = parts.join('+');
        } else if (e.key === 'Enter') {
          saveSearchShortcut();
        }
      };
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
          state.nextRenewAt.value
            ? h('div', { style: { fontSize: '12px', color: 'var(--color-text-secondary,#999)', padding: '4px 4px 0' } },
                '下次自动续签：' + state.nextRenewAt.value)
            : null,
          h('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 4px 0' } }, [
            h('span', { style: { fontSize: '12px', color: 'var(--color-text-secondary,#999)', flexShrink: 0 } }, '搜索快捷键'),
            h('input', {
              style: {
                flex: 1, minWidth: 0, padding: '5px 8px', borderRadius: '6px', fontSize: '12px',
                background: 'var(--color-bg-elevated,#f5f5f5)',
                border: '1px solid var(--border-subtle,#e8e8e8)',
                color: 'var(--color-text-main,#333)', outline: 'none',
              },
              value: displayAcc(state.searchShortcut.value),
              placeholder: '点击后直接按下组合键，如 ⌘F',
              onFocus: (e) => { capturing = true; lastAcc = state.searchShortcut.value; state.searchShortcut.value = ''; e.target.placeholder = '正在捕获，按下组合键或 Esc 取消'; },
              onBlur: (e) => { capturing = false; e.target.placeholder = '点击后直接按下组合键，如 ⌘F'; },
              onKeydown: onShortcutKeydown,
            }),
            h('div', {
              style: {
                flexShrink: 0, padding: '5px 12px', borderRadius: '6px', fontSize: '12px',
                background: 'var(--color-primary,#409eff)', color: '#fff', cursor: 'pointer',
                userSelect: 'none',
              },
              onClick: () => saveSearchShortcut(),
            }, '保存'),
          ]),
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

  // 注册搜索快捷键（默认 Meta+F = Mac ⌘F，可用设置页自定义；⌘ 与 Ctrl 严格区分）
  try {
    const savedAcc = (await ctx.storage.get('kugou-checkin:searchShortcut')) || '';
    await registerSearchShortcut(savedAcc || 'Meta+F');
  } catch (e) { /* 快捷键注册失败不阻塞签到 */ }


  // ---------------- 会员续期循环 ----------------
  // 到期前提前量：会员最先到期时间前 3 小时自动续签（可改为 1 小时 / 2 小时）
  const RENEW_LEAD_MS = 3 * 60 * 60 * 1000;
  // setTimeout 单次上限保护（约 24.8 天）
  const MAX_TIMEOUT_MS = 2147483647;

  // 记录会员到期时间：取所有会员里【最先到期】的时间戳存入 storage
  async function recordExpire(list) {
    let earliest = Infinity;
    for (const v of list) if (v.remainMs < earliest) earliest = v.remainMs;
    const ts = Number.isFinite(earliest) ? Date.now() + earliest : 0;
    await ctx.storage.set('kugou-checkin:vipExpire', ts);
    return ts;
  }

  // 失败/无登录态时的重试间隔（10 分钟），保证续签链条永不断
  const RETRY_MS = 10 * 60 * 1000;

  // 到期驱动的续签循环（自愈版）：任何失败都不会断链，而是排一个短延时重试
  // → 正常情况排"到期前 RENEW_LEAD_MS"触发 → 今日未领则领取 → 记录最先到期时间 → 重排下一次
  async function scheduleRenew() {
    let delay;
    try {
      const auth = getAuth();
      if (!auth.token) {
        delay = RETRY_MS; // 登录态未就绪：10 分钟后重试，等 token 恢复后自动接上
      } else {
        let list = [];
        try { list = await getVipList(auth); } catch (e) { /* 查询失败按重试处理 */ }
        const ts = await recordExpire(list);
        const remainMs = ts ? ts - Date.now() : 0;
        delay = Math.max(0, remainMs - RENEW_LEAD_MS);
        if (ts === 0) delay = Math.max(delay, 60 * 60 * 1000); // 无会员时至少 1 小时后再试
      }
    } catch (e) {
      delay = RETRY_MS; // 任何异常：10 分钟后重试，不断链
    }
    if (delay > MAX_TIMEOUT_MS) delay = MAX_TIMEOUT_MS;

    // 记录下次续签时间，供设置页展示、便于确认定时器已排上
    try { await ctx.storage.set('kugou-checkin:nextRenewAt', Date.now() + delay); } catch (e) { /* 忽略 */ }

    setTimeout(async () => {
      try {
        const auth = getAuth();
        if (auth.token) {
          const last = (await ctx.storage.get('kugou-checkin:lastSignDate')) || '';
          if (last !== todayStr()) {
            // 今日未领：后台自动领取一次
            await runSign({
              status: { value: 'idle' }, statusText: { value: '自动续签' },
              logs: { value: [] }, busy: { value: false }, lastSignDate: { value: last },
              vipList: { value: [] },
            }, { auto: true });
          }
          // 今日已领则保持现状
        }
      } catch (e) { /* 静默 */ }
      finally {
        scheduleRenew(); // 无论成功失败都重排下一次，链条不断
      }
    }, delay);
  }

  // 启动：轮询等待登录态就绪（最多 15 秒）→ 今日未领则先领一次 → 排第一条续签定时器
  // 15 秒内未就绪也不放弃：scheduleRenew 会在无登录态时 10 分钟重试，自动接上
  try {
    const last = (await ctx.storage.get('kugou-checkin:lastSignDate')) || '';
    let waited = 0;
    const timer = setInterval(() => {
      waited += 1000;
      if (getAuth().token) {
        clearInterval(timer);
        (async () => {
          if (last !== todayStr()) {
            await runSign({
              status: { value: 'idle' }, statusText: { value: '自动签到' },
              logs: { value: [] }, busy: { value: false }, lastSignDate: { value: last },
              vipList: { value: [] },
            }, { auto: true });
          }
          scheduleRenew();
        })();
      } else if (waited >= 15000) {
        clearInterval(timer);
        scheduleRenew(); // 登录态未就绪也先排链，内部会 10 分钟重试
      }
    }, 1000);
  } catch (e) { /* 自动签到失败不阻塞 */ }
}
