# -*- coding: utf-8 -*-
"""安徽大学电费查询插件 —— AstrBot 插件入口。

指令：
  /电费        查询当前缴费窗口绑定宿舍的剩余电量（照明 / 空调）
  /电费help    查看使用说明
  /电费bind    在目标 QQ 群/私聊中发送，把当前会话绑定为定时推送目标
  /电费status  查看定时推送状态（启用、cron、目标、下次运行）
"""
from __future__ import annotations

import asyncio
import time

import httpx

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from astrbot.api.event import filter, AstrMessageEvent, MessageChain
from astrbot.api.star import Context, Star, register
from astrbot.api import AstrBotConfig, logger

from .ahu_elec import get_token, query_with_token, AhuElecError

# token 缓存（内存）：{token: str, expire_at: float}。SSO token 有效期约 2 小时，按 1.5h 保守缓存。
_token_cache: dict = {"token": None, "expire_at": 0.0}
_TOKEN_TTL = 5400

CRON_HINT = "标准 5 段 cron 表达式：分 时 日 月 周。示例：\n  0 9 * * *      每天 09:00\n  0 12,18 * * *  每天 12:00 和 18:00\n  30 8 * * 1-5   工作日 08:30\n  0 10 1 * *     每月 1 日 10:00"

DENY_MSG = "无权限，如有需要请联系管理员"

# 三个电控缴费窗口 → feeitemid 映射（来自 /charge/feeitem 接口）
FEE_WINDOWS = {
    "A": {"name": "电控缴费A", "feeitemid": 408},
    "B": {"name": "电控缴费B", "feeitemid": 428},
    "C": {"name": "电控缴费C", "feeitemid": 488},
}


@register("ahu_elec", "秉烛", "查询安徽大学宿舍照明/空调剩余电量", "1.0.1", "")
class AhuElecPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
        self._job = None

    def _resolve_window(self) -> tuple[str, int]:
        """返回 (窗口名, feeitemid)。feeitemid 配置非空时优先（支持 C 的 429/468 等其他 id）。"""
        win = str(self.config.get("fee_window") or "C").strip().upper()
        info = FEE_WINDOWS.get(win, FEE_WINDOWS["C"])
        raw = str(self.config.get("feeitemid") or "").strip()
        try:
            fid = int(raw) if raw else info["feeitemid"]
        except ValueError:
            fid = info["feeitemid"]
        return info["name"], fid

    async def initialize(self):
        """插件加载后启动调度器并注册定时任务。"""
        if not self.scheduler.running:
            self.scheduler.start()
        self._reschedule()
        if self.config.get("schedule_enable"):
            logger.info(f"[ahu_elec] 定时推送已启用：{self.config.get('schedule_cron')}")

    async def terminate(self):
        """插件卸载/停用时关闭调度器。"""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    # ---------------- 指令 ----------------

    def _allowed(self, event: AstrMessageEvent) -> bool:
        """白名单校验：未启用直接放行；群聊按群号、私聊按 QQ 号匹配。"""
        if not self.config.get("whitelist_enable"):
            return True
        try:
            parts = event.unified_msg_origin.split(":", 2)
            if len(parts) != 3:
                return True
            mtype, sid = parts[1], parts[2]
        except Exception:  # noqa: BLE001
            return True
        if mtype == "GroupMessage":
            groups = self.config.get("whitelist_groups") or []
            return sid in {str(g) for g in groups}
        if mtype == "FriendMessage":
            priv = self.config.get("whitelist_private") or []
            return sid in {str(q) for q in priv}
        return True

    # 说明：v4.29+ 中 wake_prefix 为空时，消息不会被剥掉开头的 "/"，
    # 因此除主命令名外再注册带 "/" 的别名，保证 /电费 在两种配置下都能命中。
    @filter.command("电费", alias={"/电费", "电费查询", "/电费查询"})
    async def query_elec_cmd(self, event: AstrMessageEvent):
        """查询绑定宿舍的照明与空调剩余电量"""
        if not self._allowed(event):
            yield event.plain_result(DENY_MSG)
            return
        username = (self.config.get("username") or "").strip()
        password = (self.config.get("password") or "").strip()
        if not username or not password:
            yield event.plain_result("未配置学号/密码。请在 AstrBot 管理面板的插件配置中填写 "
                                     "username（学号）与 password（密码）。")
            return

        window_name, feeitemid = self._resolve_window()
        try:
            result = await query_elec_impl(username, password, feeitemid, window_name)
        except AhuElecError as e:
            yield event.plain_result(f"查询失败：{e}")
            return
        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as e:
            logger.error(f"ahu_elec network error: {type(e).__name__}: {e}")
            yield event.plain_result(
                "查询失败：无法连接学校服务器（网络超时/不通）。\n"
                "请确认 AstrBot 所在网络能访问 one.ahu.edu.cn —— 需要校内网络或已连接校园 VPN。"
            )
            return
        except httpx.HTTPError as e:
            logger.error(f"ahu_elec httpx error: {type(e).__name__}: {e}")
            yield event.plain_result(f"网络错误：{e.__class__.__name__}。请稍后重试。")
            return
        except Exception as e:  # noqa: BLE001 兜底
            logger.error(f"ahu_elec unexpected error: {type(e).__name__}: {e}")
            yield event.plain_result(f"未知错误：{type(e).__name__}: {e}")
            return

        yield event.plain_result(self._format_result(result))

    @filter.command("电费help", alias={"/电费help", "电费帮助", "/电费帮助"})
    async def help_cmd(self, event: AstrMessageEvent):
        """查看使用说明"""
        if not self._allowed(event):
            yield event.plain_result(DENY_MSG)
            return
        yield event.plain_result(self._help_text())

    @filter.command("电费bind", alias={"/电费bind", "电费绑定", "/电费绑定"})
    async def bind_cmd(self, event: AstrMessageEvent):
        """将当前会话绑定为定时推送目标"""
        if not self._allowed(event):
            yield event.plain_result(DENY_MSG)
            return
        umo = event.unified_msg_origin
        self.config["schedule_target"] = umo
        try:
            ret = self.config.save_config()
            if asyncio.iscoroutine(ret):
                await ret
        except Exception as e:  # noqa: BLE001
            logger.error(f"[ahu_elec] 保存配置失败: {e}")
            yield event.plain_result(f"保存配置失败：{e}")
            return
        self._reschedule()
        yield event.plain_result(
            f"已将当前会话绑定为定时推送目标：\n{umo}\n"
            "（若已在插件配置中启用定时推送，将按 cron 定时向此会话发送电费信息）"
        )

    @filter.command("电费status", alias={"/电费status", "电费状态", "/电费状态"})
    async def status_cmd(self, event: AstrMessageEvent):
        """查看定时推送状态"""
        if not self._allowed(event):
            yield event.plain_result(DENY_MSG)
            return
        enabled = bool(self.config.get("schedule_enable"))
        cron = (self.config.get("schedule_cron") or "").strip()
        target = self.config.get("schedule_target") or ""
        lines = [
            "【电费定时推送状态】",
            f"启用：{'是' if enabled else '否'}",
            f"cron：{cron if cron else '（未设置）'}",
            f"目标会话：{target if target else '（未绑定，可在目标会话发送 /电费bind）'}",
        ]
        if enabled and self._job:
            lines.append(f"下次运行：{self._job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if self._job.next_run_time else '未知'}")
            lines.append("任务状态：已注册（修改配置后请重载插件以生效）")
        elif enabled and not self._job:
            lines.append("提示：cron 表达式无效或未设置，请检查插件配置。")
        yield event.plain_result("\n".join(lines))

    # ---------------- 定时推送 ----------------

    def _reschedule(self):
        """按当前配置重建 cron 任务（配置/绑定变更后调用）。"""
        if self._job:
            try:
                self._job.remove()
            except Exception:  # noqa: BLE001
                pass
            self._job = None
        if not self.config.get("schedule_enable"):
            return
        cron = (self.config.get("schedule_cron") or "").strip()
        if not cron:
            logger.warning("[ahu_elec] 已启用定时推送但未设置 cron 表达式。")
            return
        try:
            trigger = CronTrigger.from_crontab(cron, timezone="Asia/Shanghai")
        except ValueError as e:
            logger.error(f"[ahu_elec] cron 表达式无效（{cron}）：{e}")
            return
        self._job = self.scheduler.add_job(
            self._push_elec, trigger,
            id="ahu_elec_push", replace_existing=True, misfire_grace_time=300,
        )
        logger.info(f"[ahu_elec] 定时推送已注册：{cron} -> {self.config.get('schedule_target')}")

    async def _push_elec(self):
        """定时任务：查询电量并推送到目标会话。失败只记日志，不打扰会话。"""
        if not self.config.get("schedule_enable"):
            return
        target = (self.config.get("schedule_target") or "").strip()
        if not target:
            logger.warning("[ahu_elec] 定时推送未绑定目标会话，已跳过。")
            return
        username = (self.config.get("username") or "").strip()
        password = (self.config.get("password") or "").strip()
        if not username or not password:
            logger.warning("[ahu_elec] 未配置学号/密码，定时推送已跳过。")
            return
        window_name, feeitemid = self._resolve_window()
        try:
            result = await query_elec_impl(username, password, feeitemid, window_name)
            text = self._format_result(result)
            chain = MessageChain().message(text)
            ok = await self.context.send_message(target, chain)
            if not ok:
                # 容错：UMO 第一段若填了适配器名（如 aiocqhttp）而非平台 id，按平台列表自动修正后重发
                fixed = self._fix_umo(target)
                if fixed and fixed != target:
                    logger.warning(f"[ahu_elec] 平台未匹配，尝试修正 UMO：{target} -> {fixed}")
                    ok = await self.context.send_message(fixed, chain)
            if ok:
                logger.info(f"[ahu_elec] 定时推送成功 -> {target}")
            else:
                logger.error(f"[ahu_elec] 定时推送失败：找不到平台 {target}。"
                             "请在目标会话发送 /电费bind 重新绑定，或把 schedule_target 填为 /sid 返回的 UMO。")
        except AhuElecError as e:
            logger.error(f"[ahu_elec] 定时推送查询失败：{e}")
        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as e:
            logger.error(f"[ahu_elec] 定时推送失败：无法连接学校服务器（{type(e).__name__}）。"
                         "请确认 AstrBot 所在网络能访问 one.ahu.edu.cn（校内网或校园 VPN）。")
        except Exception as e:  # noqa: BLE001
            logger.error(f"[ahu_elec] 定时推送失败：{type(e).__name__}: {e}")

    def _fix_umo(self, umo: str) -> str | None:
        """尝试把 UMO 第一段（可能是适配器名）替换为已加载平台的 meta().id。"""
        parts = umo.split(":", 2)
        if len(parts) != 3:
            return None
        name, mtype, sid = parts
        insts = getattr(getattr(self.context, "platform_manager", None), "platform_insts", None)
        if not insts:
            return None
        for p in insts:
            try:
                meta = p.meta()
            except Exception:  # noqa: BLE001
                continue
            if meta.name == name and meta.id != name:
                return f"{meta.id}:{mtype}:{sid}"
        return None

    # ---------------- 公共 ----------------

    def _format_result(self, result: dict) -> str:
        window_name = result.get("window") or "电控缴费"
        lines = [f"【安大电费查询】{result['campus']}（{window_name}）"]
        for r in result.get("rooms") or []:
            lines.append("")
            lines.append(f"🏢 {r['kind']}：{r['room']}")
            if r.get("kwh") is not None:
                price = r.get("price")
                price_txt = f"（单价 {price} 元/度）" if price is not None else ""
                lines.append(f"⚡ 剩余电量：{r['kwh']:.2f} 度{price_txt}")
            else:
                lines.append(f"⚡ {r.get('text') or '未获取到电量信息'}")
        lines.extend([
            "",
            f"查询时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"注：数据来自 ycard.ahu.edu.cn {window_name}，日结时段（23:30-00:30）可能不准。",
        ])
        return "\n".join(lines)

    def _help_text(self) -> str:
        return (
            "安徽大学电费查询插件 v1.0.1\n"
            "指令：\n"
            "  /电费 —— 查询当前窗口的剩余电量\n"
            "  /电费bind —— 把当前会话设为定时推送目标\n"
            "  /电费status —— 查看定时推送状态\n"
            "配置（管理面板 → 插件 → 安大电费查询）：\n"
            "  username：学号\n"
            "  password：统一身份认证密码\n"
            "  fee_window：缴费窗口，选 A / B / C（默认 C）\n"
            "  feeitemid：高级项。留空按窗口自动（A=408 / B=428 / C=488），\n"
            "             若 C 查不到可试 429 或 468\n"
            "  schedule_enable：是否启用定时推送（bool）\n"
            "  schedule_cron：定时表达式，5 段 cron（分 时 日 月 周），如 \"0 9 * * *\"\n"
            "  schedule_target：推送目标会话（也可在目标会话发 /电费bind 自动填入）\n"
            "  whitelist_enable：是否启用会话白名单（bool）\n"
            "  whitelist_groups：允许使用的 QQ 群号列表，如 [\"123456789\"]\n"
            "  whitelist_private：允许使用的 QQ 号（私聊）列表，如 [\"10001\"]\n"
            "前提：账号需已在 ycard.ahu.edu.cn 手机端对应缴费窗口中绑定宿舍；\n"
            "      每个窗口的绑定是独立的，换窗口需重新绑定。"
        )


async def query_elec_impl(username: str, password: str, feeitemid: int = 488,
                          window_name: str = "") -> dict:
    """带 token 缓存的查询实现：缓存未过期直接复用，过期才重新 CAS 登录。"""
    global _token_cache
    timeout = httpx.Timeout(30.0, connect=15.0)
    async with httpx.AsyncClient(timeout=timeout,
                                 headers={"User-Agent": "AstrBot-AhuElec/1.0"}) as client:
        now = time.time()
        token = _token_cache["token"]
        if not token or _token_cache["expire_at"] <= now:
            token = await get_token(client, username, password)
            _token_cache["token"] = token
            _token_cache["expire_at"] = time.time() + _TOKEN_TTL
        res = await query_with_token(client, token, feeitemid, window_name)
        res["window"] = window_name or f"电控缴费(feeitemid={feeitemid})"
        return res
