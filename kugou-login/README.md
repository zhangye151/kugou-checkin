# 酷狗概念版每日领取

这是一个独立的 EchoMusic 本地插件，不依赖旧的 `kugou-sign` 目录，也没有激活、联网授权或凭据收集逻辑。

## 安装

将 `kugou-youth-checkin` 目录复制到 EchoMusic 的插件目录，在“插件管理”中启用，然后从侧边栏“插件”打开“概念版领取”。

## 行为

- 使用 EchoMusic 当前已登录的酷狗账号；插件不会读取或保存 Token、Cookie、密码。
- 只在用户点击后调用 EchoMusic 已公开的 `ctx.kugou.user.claimDayVip()` 和 `upgradeDayVip()`。
- 如接口要求安全验证，会交由 EchoMusic 自己的验证窗口完成。
- “刷新记录”读取 EchoMusic 已公开的当月领取记录接口。

请只对自己有权使用的账号操作，并以酷狗与 EchoMusic 的当前规则为准。
