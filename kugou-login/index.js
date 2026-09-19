const formatDate = (date = new Date()) => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const messageFrom = (result, fallback) => {
  if (typeof result === "string") return result;
  if (!result || typeof result !== "object") return fallback;
  return String(
    result.msg || result.message || result.error || result.data?.msg || fallback,
  );
};

const isFailure = (result) => {
  if (!result || typeof result !== "object") return false;
  const status = result.status ?? result.data?.status;
  const errorCode = result.error_code ?? result.errorCode ?? result.data?.error_code;
  return Number(status) === 0 || (errorCode !== undefined && Number(errorCode) !== 0);
};

export default {
  async activate(ctx) {
    const { computed, defineAsyncComponent, defineComponent, h, ref } = ctx.vue;
    const Button = defineAsyncComponent(ctx.ui.components.Button);

    const claiming = ref(false);
    const upgrading = ref(false);
    const refreshing = ref(false);
    const date = ref(formatDate());
    const status = ref("准备就绪。请确认 EchoMusic 已登录酷狗账号。");
    const statusKind = ref("info");
    const record = ref(null);

    const setStatus = (kind, text) => {
      statusKind.value = kind;
      status.value = text;
    };

    const loadRecord = async ({ quiet = false } = {}) => {
      if (!ctx.kugou?.user?.getVipMonthRecord) {
        setStatus("error", "当前 EchoMusic 版本未提供领取记录接口。");
        return;
      }
      refreshing.value = true;
      try {
        const result = await ctx.kugou.user.getVipMonthRecord();
        record.value = result;
        if (!quiet) setStatus("success", "已刷新本月领取记录。");
      } catch (error) {
        setStatus("error", `读取领取记录失败：${error?.message || String(error)}`);
      } finally {
        refreshing.value = false;
      }
    };

    const requestVerificationIfNeeded = async (result) => {
      const eventId = result?.ssaCode || result?.eventId || result?.data?.ssaCode;
      if (!eventId || !ctx.kugouVerification?.request) return false;
      const verified = await ctx.kugouVerification.request(eventId);
      if (!verified?.ok) {
        setStatus("error", verified?.canceled ? "已取消安全验证。" : (verified?.error || "安全验证未完成。"));
        return false;
      }
      return true;
    };

    const claimToday = async () => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date.value)) {
        setStatus("error", "日期格式应为 YYYY-MM-DD。");
        return;
      }
      if (!ctx.kugou?.user?.claimDayVip) {
        setStatus("error", "当前 EchoMusic 版本未提供概念版每日领取接口。");
        return;
      }

      claiming.value = true;
      try {
        let result = await ctx.kugou.user.claimDayVip(date.value);
        if (await requestVerificationIfNeeded(result)) {
          result = await ctx.kugou.user.claimDayVip(date.value);
        }
        if (isFailure(result)) {
          setStatus("error", `领取未完成：${messageFrom(result, "服务未返回成功状态")}`);
          return;
        }
        setStatus("success", `已提交 ${date.value} 的领取请求：${messageFrom(result, "请求成功")}`);
        await loadRecord({ quiet: true });
      } catch (error) {
        setStatus("error", `领取失败：${error?.message || String(error)}`);
      } finally {
        claiming.value = false;
      }
    };

    const upgrade = async () => {
      if (!ctx.kugou?.user?.upgradeDayVip) {
        setStatus("error", "当前 EchoMusic 版本未提供概念版升级接口。");
        return;
      }
      upgrading.value = true;
      try {
        let result = await ctx.kugou.user.upgradeDayVip();
        if (await requestVerificationIfNeeded(result)) {
          result = await ctx.kugou.user.upgradeDayVip();
        }
        if (isFailure(result)) {
          setStatus("error", `升级未完成：${messageFrom(result, "服务未返回成功状态")}`);
          return;
        }
        setStatus("success", `已提交升级请求：${messageFrom(result, "请求成功")}`);
        await loadRecord({ quiet: true });
      } catch (error) {
        setStatus("error", `升级失败：${error?.message || String(error)}`);
      } finally {
        upgrading.value = false;
      }
    };

    const recordText = computed(() => {
      if (!record.value) return "尚未读取";
      return JSON.stringify(record.value, null, 2);
    });

    const Page = defineComponent({
      setup() {
        return () => h("main", { class: "kugou-youth-checkin" }, [
          h("h1", "酷狗概念版每日领取"),
          h("p", { class: "hint" }, "使用 EchoMusic 当前登录账号。插件不收集、不保存账号密码、Token 或激活码。"),
          h("label", { class: "date-field" }, [
            h("span", "领取日期"),
            h("input", {
              type: "date",
              value: date.value,
              disabled: claiming.value,
              onInput: (event) => { date.value = event.target.value; },
            }),
          ]),
          h("div", { class: "actions" }, [
            h(Button, { loading: claiming.value, disabled: upgrading.value, onClick: claimToday }, () => "领取当日权益"),
            h(Button, { loading: upgrading.value, disabled: claiming.value, onClick: upgrade }, () => "升级畅听会员"),
            h(Button, { loading: refreshing.value, disabled: claiming.value || upgrading.value, onClick: () => loadRecord() }, () => "刷新记录"),
          ]),
          h("p", { class: ["status", statusKind.value] }, status.value),
          h("section", { class: "record" }, [
            h("h2", "本月领取记录（原始响应）"),
            h("pre", recordText.value),
          ]),
          h("p", { class: "notice" }, "仅在你点击按钮后发起请求。若酷狗要求安全验证，插件会调用 EchoMusic 的系统验证流程后重试一次。"),
        ]);
      },
    });

    ctx.css.inject(`
      .kugou-youth-checkin { max-width: 720px; padding: 28px; margin: 0 auto; display: grid; gap: 16px; }
      .kugou-youth-checkin h1, .kugou-youth-checkin h2, .kugou-youth-checkin p { margin: 0; }
      .kugou-youth-checkin .hint, .kugou-youth-checkin .notice { color: var(--text-color-3, #6b7280); line-height: 1.65; }
      .kugou-youth-checkin .date-field { display: grid; gap: 8px; font-weight: 600; }
      .kugou-youth-checkin input { width: 220px; padding: 8px 10px; border: 1px solid var(--border-color, #d1d5db); border-radius: 8px; background: transparent; color: inherit; }
      .kugou-youth-checkin .actions { display: flex; flex-wrap: wrap; gap: 10px; }
      .kugou-youth-checkin .status { padding: 12px; border-radius: 8px; background: color-mix(in srgb, currentColor 8%, transparent); line-height: 1.5; }
      .kugou-youth-checkin .status.success { color: #15803d; }
      .kugou-youth-checkin .status.error { color: #dc2626; }
      .kugou-youth-checkin .record { display: grid; gap: 8px; }
      .kugou-youth-checkin pre { max-height: 280px; overflow: auto; padding: 12px; margin: 0; border-radius: 8px; background: var(--code-color, rgba(127, 127, 127, .12)); font-size: 12px; white-space: pre-wrap; word-break: break-word; }
    `, { id: "kugou-youth-checkin-style" });

    ctx.ui.addPage({
      id: "home",
      title: "概念版领取",
      icon: "tabler:calendar-check",
      component: Page,
      sidebar: { section: "plugins", sectionTitle: "插件", order: 20 },
    });

    await loadRecord({ quiet: true });
  },
};
