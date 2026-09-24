"""单封邮件接收链可信边界分析（复用 Received 解析结果）。

检查口径：
- 复用 :func:`mailtrace.parsing.parser.analyze_headers` 的 Received 解析
  （from/by 主机、对端 IP、时间、原文），不重复实现头部解析。
- ``Received`` 由最终接收服务器在头部**顶部**追加，因此本视图按
  **头部原文自上而下**（``analyze_headers`` 的 ``path`` 为发件方 →
  收件方，这里取反向）逐跳检查 ``by`` 主机名。
- 只有**自顶端起连续命中**本组织接收服务器名单的跳才标记为可信；
  首个 ``by`` 未命中名单或缺少 ``by`` 的跳即为**可信边界**，其后所有跳
  一律不可信——即使 ``by`` 再次命中名单也不得重新接入。
- 主机名比较忽略大小写与末尾点。名单规范化后为空属于输入错误；
  顶端即未命中、或头部中没有 ``Received`` 字段时，明确返回
  ``status="no_chain"``（无法建立可信链），不输出边界与交接点。
- “最后可信跳”是可信链上最靠近边界的一跳；其 ``from`` 主机与对端 IP
  即外部向本组织交接邮件的位置，用于定位外部交接点。
"""

from __future__ import annotations

import re

from mailtrace.parsing.parser import analyze_headers

# 边界/不可信原因
REASON_NOT_LISTED = "by_not_listed"
REASON_MISSING_BY = "missing_by"
REASON_AFTER_BOUNDARY = "after_boundary"

REASON_LABELS = {
    REASON_NOT_LISTED: "by 主机不在本组织接收服务器名单中",
    REASON_MISSING_BY: "该 Received 跳缺少 by 主机名",
    REASON_AFTER_BOUNDARY: "位于可信边界之后，不再接入可信链",
}

STATUS_ESTABLISHED = "established"
STATUS_NO_CHAIN = "no_chain"

_STATUS_LABELS = {
    STATUS_ESTABLISHED: "可信链已建立",
    STATUS_NO_CHAIN: "无法建立可信链",
}

# 页面文本框中主机名可按换行 / 逗号 / 分号 / 空白分隔
_HOST_SPLIT_RE = re.compile(r"[\s,;]+")


def normalize_host(host: str | None) -> str | None:
    """规范化主机名：去空白、转小写、去末尾点；为空返回 None。"""
    if not host:
        return None
    host = host.strip().lower().rstrip(".").strip()
    return host or None


def parse_host_list_text(text: str) -> list[str]:
    """把页面文本框内容切分为原始主机名列表（尚未规范化）。"""
    if not text:
        return []
    return [item for item in _HOST_SPLIT_RE.split(text.strip()) if item]


def normalize_host_list(hosts) -> list[str]:
    """规范化主机名名单：逐项去空白 / 小写 / 去末尾点、丢弃空项并去重
    （保留首次出现顺序）。"""
    result: list[str] = []
    seen: set[str] = set()
    for item in hosts or []:
        if not isinstance(item, str):
            continue
        norm = normalize_host(item)
        if norm is not None and norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result


def _hop_view(hop: dict, index: int, total: int) -> dict:
    """头部自上而下顺序中的一跳公共字段。"""
    if index == 1:
        hint = "头部最上方（最终接收服务器）"
    elif index == total:
        hint = "头部最下方（最早一跳）"
    else:
        hint = "中转节点"
    return {
        "hop_index": index,
        "node": hop.get("node"),
        "by_host": hop.get("by_host"),
        "from_host": hop.get("from_host"),
        "ip": hop.get("ip"),
        "time_utc": hop.get("time_utc"),
        "date_raw": hop.get("date_raw"),
        "raw": hop.get("raw"),
        "position_hint": hint,
    }


def analyze_trust_boundary(raw_headers: str, trusted_hosts: list[str]) -> dict:
    """分析单封邮件接收链的可信边界。

    参数 ``trusted_hosts`` 为本组织接收服务器主机名原始列表（页面文本框
    或 API 数组均可）；规范化（忽略大小写与末尾点）后为空时返回带
    ``error`` 的输入错误字典。成功时返回 ``status`` 为
    ``established`` / ``no_chain`` 的结构化结果。
    """
    hosts = normalize_host_list(trusted_hosts)
    if not hosts:
        return {
            "error": "本组织接收服务器主机名名单不能为空"
            "（请每行填写一个本组织接收服务器的 by 主机名）"
        }
    trusted_set = set(hosts)

    analyzed = analyze_headers(raw_headers)
    # path 为发件方 -> 收件方；反向即头部原文自上而下（最终接收方在顶端）。
    top_down = list(reversed(analyzed.get("path", [])))

    base = {
        "status_label": _STATUS_LABELS[STATUS_NO_CHAIN],
        "hop_count": len(top_down),
        "trusted_count": 0,
        "trusted_hosts": hosts,
        "boundary": None,
        "last_trusted": None,
        "hops": [],
    }

    if not top_down:
        base["status"] = STATUS_NO_CHAIN
        base["message"] = "头部中未找到任何 Received 字段，无法建立可信链。"
        return base

    hops_out: list[dict] = []
    boundary: dict | None = None
    chain_broken = False

    for index, hop in enumerate(top_down, start=1):
        view = _hop_view(hop, index, len(top_down))
        by_norm = normalize_host(hop.get("by_host"))
        listed = by_norm is not None and by_norm in trusted_set

        trusted = False
        reason: str | None = None
        rejoin_blocked = False

        if not chain_broken:
            if listed:
                trusted = True
            else:
                chain_broken = True
                reason = (
                    REASON_MISSING_BY if by_norm is None else REASON_NOT_LISTED
                )
                boundary = {
                    "hop_index": index,
                    "node": hop.get("node"),
                    "by_host": hop.get("by_host"),
                    "reason": reason,
                    "reason_label": REASON_LABELS[reason],
                }
        else:
            # 边界之后：即使再次命中名单也不得重新接入
            reason = REASON_AFTER_BOUNDARY
            rejoin_blocked = listed

        view.update(
            {
                "status": "trusted" if trusted else "untrusted",
                "trusted": trusted,
                "listed": listed,
                "reason": reason,
                "reason_label": REASON_LABELS[reason] if reason else None,
                "rejoin_blocked": rejoin_blocked,
            }
        )
        hops_out.append(view)

    trusted_indices = [h["hop_index"] for h in hops_out if h["trusted"]]
    base["hops"] = hops_out
    base["trusted_count"] = len(trusted_indices)
    base["boundary"] = boundary

    if not trusted_indices:
        # 顶端第一跳即未命中 / 缺 by：可信链没有起点
        first = hops_out[0]
        if first["reason"] == REASON_MISSING_BY:
            detail = "头部最上方的第一条 Received 缺少 by 主机名"
        else:
            detail = (
                "头部最上方第一条 Received 的 by 主机"
                f"“{first['by_host']}”不在本组织接收服务器名单中"
            )
        base["status"] = STATUS_NO_CHAIN
        base["message"] = (
            f"{detail}，无法自收件端建立可信链；请核对名单是否包含"
            "本组织最外侧接收服务器的主机名。"
        )
        return base

    last_index = trusted_indices[-1]
    last_hop = hops_out[last_index - 1]
    base["last_trusted"] = {
        "hop_index": last_index,
        "by_host": last_hop["by_host"],
        "from_host": last_hop["from_host"],
        "ip": last_hop["ip"],
    }
    base["status"] = STATUS_ESTABLISHED
    base["status_label"] = _STATUS_LABELS[STATUS_ESTABLISHED]
    if boundary is None:
        base["message"] = (
            f"全部 {len(hops_out)} 跳的 by 主机均连续命中名单，"
            "头部范围内未出现边界外交接点。"
        )
    else:
        peer = last_hop["from_host"] or "（未记录 from 主机）"
        base["message"] = (
            f"可信链含 {len(trusted_indices)} 跳；边界位于头部自上而下"
            f"第 {boundary['hop_index']} 跳（{boundary['node']}）。"
            f"最后可信跳为第 {last_index} 跳（{last_hop['by_host']}），"
            f"其记录的外部交接对端为 {peer}"
            + (f" / {last_hop['ip']}" if last_hop["ip"] else "（未记录对端 IP）")
            + "。"
        )
    return base
