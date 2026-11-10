# -*- coding: utf-8 -*-
"""ahu_elec.py
安徽大学电费查询核心模块（纯 Python + httpx 异步，无浏览器、无 node）。

链路：
1. CAS 登录 one.ahu.edu.cn（自定义 3DES 加密 rsa，见 synjones_des.py）
2. 换 ycard 一卡通 SSO access_token（JWT）
3. 通过电控缴费（A/B/C 三个窗口之一）的 /charge/* 接口查询绑定房间
4. 若绑定房间名含「空调」/「照明」，自动推导同楼同层的另一路房间并查询，
   返回照明/空调两路剩余电量；只绑一路时只返回该路
"""
from __future__ import annotations

import re
import time
from urllib.parse import unquote

import httpx

from .synjones_des import str_enc  # noqa: F401

BASE_CAS = "https://one.ahu.edu.cn"
BASE_YCARD = "https://ycard.ahu.edu.cn"
SERVICE = BASE_YCARD + "/berserker-auth/cas/login/neusoftCas"

# ycard 两个 Basic 客户端凭证（来自 charge-app 前端 app.js / plat_login2.js，明文写死）
BASIC_MOBILE = "bW9iaWxlX3NlcnZpY2VfcGxhdGZvcm06bW9iaWxlX3NlcnZpY2VfcGxhdGZvcm1fc2VjcmV0"
BASIC_CHARGE = "Y2hhcmdlOmNoYXJnZV9zZWNyZXQ="

UA = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")


class AhuElecError(Exception):
    """插件业务错误，message 会直接展示给用户。"""


def _parse_sceneinfo(sceneinfo: str) -> dict:
    """解析 sceneinfo: 'campus:XXX&XX校区#$#XX校区;building:...'
    返回 {key: value}, value 形如 'XXX&XX校区'（getThirdData 需要的完整 value）。"""
    out = {}
    for part in sceneinfo.split(";"):
        if not part:
            continue
        key, _, rest = part.partition(":")
        out[key.strip()] = rest.split("#$#")[0]
    return out


async def cas_login_and_token(client: httpx.AsyncClient, username: str, password: str) -> str:
    """CAS → SSO token 全链路，返回 access_token。"""
    # 1. 取登录页隐藏字段
    r = await client.get(f"{BASE_CAS}/cas/login", params={"service": SERVICE},
                         follow_redirects=False)
    html = r.text
    lt = re.search(r'id="lt"[^>]*value="([^"]+)"', html)
    execution = re.search(r'name="execution"[^>]*value="([^"]+)"', html)
    if not lt or not execution:
        raise AhuElecError("登录页解析失败（lt/execution 缺失），可能登录页结构已变更或需要验证码。")
    lt, execution = lt.group(1), execution.group(1)

    # 2. 自定义 3DES 加密（纯 Python 实现）
    rsa = str_enc(username + password + lt, "1", "2", "3")

    # 3. 设备预检
    r = await client.post(f"{BASE_CAS}/cas/device",
                          data={"ul": len(username), "pl": len(password),
                                "rsa": rsa, "method": "login"})
    try:
        if r.json().get("info") != "ok":
            raise AhuElecError(f"CAS 设备校验失败：{r.text[:200]}")
    except ValueError:
        raise AhuElecError(f"CAS 设备校验响应异常：{r.text[:200]}")

    # 4. 表单登录 → 302 带 ticket
    r = await client.post(f"{BASE_CAS}/cas/login", params={"service": SERVICE},
                          data={"rsa": rsa, "ul": len(username), "pl": len(password),
                                "lt": lt, "execution": execution, "_eventId": "submit"},
                          follow_redirects=False)
    m = re.search(r"ticket=([^&]+)", r.headers.get("Location", ""))
    if not m:
        # 检查是否提示错误（如密码错误、验证码）
        raise AhuElecError(f"CAS 登录失败（未获得 ticket）：{r.text[:300]}")
    st = m.group(1)

    # 5. 回调 ycard SSO → 二次 ticket
    r = await client.get(SERVICE, params={"ticket": st}, follow_redirects=True)
    m2 = re.search(r"ticket=([^&]+)", str(r.url))
    if not m2:
        raise AhuElecError("SSO 回调未获得二次 ticket。")
    t1 = unquote(m2.group(1))

    # 6. 换 access_token
    r = await client.post(
        f"{BASE_YCARD}/berserker-auth/oauth/token",
        data={"username": t1, "password": t1, "grant_type": "password", "scope": "all",
              "loginFrom": "app", "logintype": "sso", "device_token": "h5"},
        headers={"Authorization": "Basic " + BASIC_MOBILE,
                 "Content-Type": "application/x-www-form-urlencoded"})
    try:
        at = r.json().get("access_token")
    except ValueError:
        raise AhuElecError(f"获取 access_token 失败：{r.text[:200]}")
    if not at:
        raise AhuElecError("获取 access_token 失败（响应中无 access_token）。")
    return at


def _charge_headers(token: str) -> dict:
    return {"synjones-auth": "bearer " + token,
            "Authorization": "Basic " + BASIC_CHARGE}


async def _get_scene_bind(client: httpx.AsyncClient, token: str, feeitemid: int,
                          window_name: str = "") -> dict:
    """获取当前账号在指定 feeitem 下的绑定房间，返回 sceneinfo 解析后的 dict。"""
    r = await client.get(f"{BASE_YCARD}/charge/sceneBind/getList",
                         params={"feeitemid": feeitemid}, headers=_charge_headers(token))
    j = r.json()
    binds = j.get("sceneBinds") or []
    if not binds:
        label = f"{window_name}（feeitemid={feeitemid}）" if window_name else f"feeitemid={feeitemid}"
        raise AhuElecError(f"该账号在 {label} 下没有绑定房间。"
                           "请先在 ycard.ahu.edu.cn 手机端对应缴费窗口中绑定宿舍。")
    # 取第一条（通常只有一条）
    scene = _parse_sceneinfo(binds[0]["sceneinfo"])
    if "room" not in scene:
        raise AhuElecError("绑定信息缺少房间，无法查询。")
    return scene


async def _get_third_data(client: httpx.AsyncClient, token: str, feeitemid: int,
                          params: dict) -> dict:
    """IEC/select 查询。params 为 form 字段。返回响应 map。"""
    r = await client.post(f"{BASE_YCARD}/charge/feeitem/getThirdData", data=params,
                          headers={**_charge_headers(token),
                                   "Content-Type": "application/x-www-form-urlencoded"})
    j = r.json()
    m = j.get("map") or {}
    if j.get("code") != 200:
        raise AhuElecError(f"查询接口异常：{j.get('msg') or j}")
    return m


ROOM_KINDS = ("空调", "照明")


def _room_kind(name: str) -> str | None:
    for kind in ROOM_KINDS:
        if kind in name:
            return kind
    return None


def _swap_kind(name: str, target_kind: str) -> str | None:
    """把名称中的 空调/照明 替换为目标类型；不含这两类时返回 None。"""
    for kind in ROOM_KINDS:
        if kind in name:
            return name.replace(kind, target_kind, 1)
    return None


async def _find_building(client: httpx.AsyncClient, token: str, feeitemid: int,
                         campus: str, src_building_name: str, target_kind: str) -> str:
    """在 campus 下找与 src 同名的目标类型楼栋 value（如 XX号楼空调 -> XX号楼照明）。"""
    target = _swap_kind(src_building_name, target_kind)
    if not target:
        raise AhuElecError(f"楼栋名 {src_building_name} 不含空调/照明，无法推导{target_kind}楼栋。")
    m = await _get_third_data(client, token, feeitemid, {
        "feeitemid": feeitemid, "type": "select", "level": 1, "campus": campus})
    for b in m.get("data") or []:
        if b.get("name") == target:
            return b["value"]
    # 兜底：同前缀且含目标类型
    base = src_building_name.replace(_room_kind(src_building_name) or "", "", 1)
    for b in m.get("data") or []:
        if b.get("name", "").startswith(base) and target_kind in b["name"]:
            return b["value"]
    raise AhuElecError(f"在楼栋列表中找不到 {target}（楼栋列表已更新？）。")


async def _find_room(client: httpx.AsyncClient, token: str, feeitemid: int,
                     campus: str, building: str, floor: str,
                     src_room_name: str, target_kind: str) -> str:
    """在目标楼栋/楼层下找与 src 同名的目标类型房间 value。"""
    target = _swap_kind(src_room_name, target_kind)
    if not target:
        raise AhuElecError(f"房间名 {src_room_name} 不含空调/照明，无法推导{target_kind}房间。")
    m = await _get_third_data(client, token, feeitemid, {
        "feeitemid": feeitemid, "type": "select", "level": 3,
        "campus": campus, "building": building, "floor": floor})
    for rm in m.get("data") or []:
        if rm.get("name") == target:
            return rm["value"]
    # 兜底：按房号匹配（-XXXX 结尾）
    suffix = "-" + src_room_name.rsplit("-", 1)[-1]
    for rm in m.get("data") or []:
        if rm.get("name", "").endswith(suffix) and target_kind in rm["name"]:
            return rm["value"]
    raise AhuElecError(f"在 {target.rsplit('-', 1)[0]} 楼层中找不到 {target} 房间。")


def _parse_elec(m: dict) -> dict:
    info = (m.get("showData") or {}).get("信息", "")
    mnum = re.search(r"剩余电量([\d.]+)", info)
    price = re.search(r"单价([\d.]+)", info)
    return {"text": info,
            "kwh": float(mnum.group(1)) if mnum else None,
            "price": float(price.group(1)) if price else None}


async def get_token(client: httpx.AsyncClient, username: str, password: str) -> str:
    """CAS 登录获取 access_token。"""
    return await cas_login_and_token(client, username, password)


async def query_with_token(client: httpx.AsyncClient, token: str,
                           feeitemid: int = 488, window_name: str = "") -> dict:
    """查询指定缴费窗口当前绑定房间的电量，并自动补齐另一路（照明/空调）。"""
    scene = await _get_scene_bind(client, token, feeitemid, window_name)

    campus = scene["campus"]
    building = scene["building"]
    floor = scene["floor"]
    room = scene["room"]
    room_name = room.split("&")[1]
    kind = _room_kind(room_name)

    # 1) 当前绑定房间的电量
    main_map = await _get_third_data(client, token, feeitemid, {
        "feeitemid": feeitemid, "type": "IEC", "level": 4,
        "campus": campus, "building": building, "floor": floor, "room": room})
    rooms = [{"kind": kind or "用电", "room": room_name, **_parse_elec(main_map)}]

    # 2) 互补房间：绑空调则补照明，绑照明则补空调（找不到时不影响主结果）
    if kind:
        other = "照明" if kind == "空调" else "空调"
        try:
            ob = await _find_building(client, token, feeitemid, campus,
                                      building.split("&")[1], other)
            orm = await _find_room(client, token, feeitemid, campus, ob, floor,
                                   room_name, other)
            om = await _get_third_data(client, token, feeitemid, {
                "feeitemid": feeitemid, "type": "IEC", "level": 4,
                "campus": campus, "building": ob, "floor": floor, "room": orm})
            rooms.append({"kind": other, "room": orm.split("&")[1], **_parse_elec(om)})
        except AhuElecError:
            pass

    return {"campus": campus.split("&")[1], "feeitemid": feeitemid, "rooms": rooms}
