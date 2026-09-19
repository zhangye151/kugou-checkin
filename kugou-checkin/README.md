# 酷狗概念版自动签到插件（echomusic 插件）

基于 [zhangye151/kgcheckin](https://github.com/zhangye151/kgcheckin) 的签到逻辑，移植为 EchoMusic（酷狗概念版）插件。

**无需激活码 / 卡密**，直接使用你当前在 EchoMusic 里登录的酷狗账号完成每日签到。

## 功能

- 自动读取当前登录账号（token / userid / dfid / guid 等设备信息，从 app 内置状态读取，无需手动粘贴）
- 每日自动签到：打开 app 后若今日未签过则自动执行一次，当天已签过则跳过
- 听歌领取 VIP
- 看广告领取 VIP
- 打开插件即显示会员状态，并排展示：
  - **概念会员（svip）**：橙色，显示剩余时间
  - **畅听会员（tvip）**：绿色，显示剩余时间
- 插件设置页提供手动签到按钮与实时日志

## 安装

把整个 `kugou-checkin` 文件夹放到 EchoMusic 的插件目录里，然后在插件管理页启用：

```
~/Library/Application Support/echo-music/plugins/kugou-checkin/
```

目录名需与 manifest 中的 `id` 一致。

## 文件

```
kugou-checkin/
├── index.js      插件主体（自包含，无外部依赖）
├── manifest.json 插件清单
└── README.md
```

## 实现说明

- 签名算法与 kgcheckin 完全一致：`MD5(secret + 排序拼接的参数 + body + secret)`。
- 加密全部用纯 JS 实现，适配 EchoMusic 的 webview 运行时：
  - MD5：手写 RFC 1321 实现
  - AES-256-CBC：WebCrypto `crypto.subtle`
  - RSA（1024 位，无填充公钥加密）：BigInt 模幂
- 网络请求通过 `ctx.net.fetch`，登录态通过 `#app` 的 Vue app 实例和 pinia 状态读取。

## 注意

- 插件只在你本人已登录的账号上发起酷狗签到接口请求，请自行评估对酷狗用户条款的合规风险。
- 未实现 token 自动刷新；EchoMusic 运行期间 token 由 app 自身保持有效，一般无需刷新。
- 看广告环节每次成功后按原版逻辑等待间隔，一轮签到可能需要几分钟，属正常现象。
