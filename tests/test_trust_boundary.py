"""接收链可信边界分析测试（解析核心仅依赖标准库）。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import analyze_trust_boundary  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_HEADERS_TRUST  # noqa: E402
from mailtrace.parsing.trust_boundary import (  # noqa: E402
    REASON_AFTER_BOUNDARY,
    REASON_MISSING_BY,
    REASON_NOT_LISTED,
    normalize_host,
    normalize_host_list,
    parse_host_list_text,
)

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def _received(by, frm="peer.example", ip=None, date=None):
    parts = [f"Received: from {frm}"]
    if ip:
        parts.append(f" ({frm} [{ip}])")
    parts.append(f"\n\tby {by} with ESMTP")
    if date:
        parts.append(f"; {date}")
    return "".join(parts)


def _headers(received_lines):
    """received_lines 按头部自上而下顺序给出（最终接收方在最前）。"""
    return "\n".join(received_lines) + "\nDate: Thu, 24 Sep 2026 02:00:00 +0000\n"


D1 = "Thu, 24 Sep 2026 02:05:00 +0000"
D2 = "Thu, 24 Sep 2026 02:04:00 +0000"
D3 = "Thu, 24 Sep 2026 02:03:00 +0000"
D4 = "Thu, 24 Sep 2026 02:02:00 +0000"


class NormalizationTests(unittest.TestCase):
    def test_normalize_host_case_and_trailing_dot(self):
        self.assertEqual(normalize_host("Mailbox.Example."), "mailbox.example")
        self.assertEqual(normalize_host("  MX.EXAMPLE  "), "mx.example")
        self.assertIsNone(normalize_host(""))
        self.assertIsNone(normalize_host("   "))
        self.assertIsNone(normalize_host(None))

    def test_normalize_host_list_dedup(self):
        self.assertEqual(
            normalize_host_list(["A.Example.", "a.example", " B "]),
            ["a.example", "b"],
        )
        self.assertEqual(normalize_host_list(["", "  ", None, 1]), [])

    def test_parse_host_list_text_separators(self):
        text = "mailbox.example, edge.example\nrelay.example;mx.example"
        self.assertEqual(
            parse_host_list_text(text),
            ["mailbox.example", "edge.example", "relay.example", "mx.example"],
        )
        self.assertEqual(parse_host_list_text(""), [])


class TrustBoundaryCoreTests(unittest.TestCase):
    def test_empty_host_list_is_input_error(self):
        result = analyze_trust_boundary(_received("a.example"), [])
        self.assertIn("error", result)
        # 全空白项规范化后为空，同样报错
        result = analyze_trust_boundary(_received("a.example"), ["", "  "])
        self.assertIn("error", result)

    def test_no_received_returns_no_chain(self):
        result = analyze_trust_boundary("From: a@example.com\n", ["mx.example"])
        self.assertEqual(result["status"], "no_chain")
        self.assertEqual(result["hop_count"], 0)
        self.assertIsNone(result["boundary"])
        self.assertIsNone(result["last_trusted"])
        self.assertIn("未找到", result["message"])

    def test_top_not_listed_returns_no_chain(self):
        headers = _headers(
            [
                _received("unknown.example", "p1.example", "192.0.2.1", D1),
                _received("mx.example", "p2.example", "198.51.100.2", D2),
            ]
        )
        result = analyze_trust_boundary(headers, ["mx.example"])
        self.assertEqual(result["status"], "no_chain")
        self.assertEqual(result["trusted_count"], 0)
        # 顶端未命中：边界点仍定位为第 1 跳，但没有“最后可信跳”
        self.assertEqual(result["boundary"]["hop_index"], 1)
        self.assertIsNone(result["last_trusted"])
        hops = result["hops"]
        # 顶端未命中，后续即使 by=mx.example 命中名单也不可信
        self.assertFalse(hops[0]["trusted"])
        self.assertEqual(hops[0]["reason"], REASON_NOT_LISTED)
        self.assertFalse(hops[1]["trusted"])
        self.assertTrue(hops[1]["rejoin_blocked"])
        self.assertEqual(hops[1]["reason"], REASON_AFTER_BOUNDARY)

    def test_top_missing_by_returns_no_chain(self):
        line = (
            "Received: from peer.example (192.0.2.1) with ESMTP"
            f"; {D1}"
        )
        headers = _headers([line])
        result = analyze_trust_boundary(headers, ["mx.example"])
        self.assertEqual(result["status"], "no_chain")
        self.assertIsNone(result["hops"][0]["by_host"])
        self.assertEqual(result["hops"][0]["reason"], REASON_MISSING_BY)

    def test_continuous_trusted_then_boundary(self):
        headers = _headers(
            [
                _received("mailbox.final.example", "edge.final.example", "10.0.0.2", D1),
                _received("edge.final.example", "relay.provider.example", "203.0.113.22", D2),
                _received("relay.provider.example", "outgoing.example.org", "192.0.2.50", D3),
                _received("edge.final.example", "smtp01.corp.example.net", "198.51.100.77", D4),
            ]
        )
        result = analyze_trust_boundary(
            headers, ["Mailbox.Final.Example.", "EDGE.final.example"]
        )
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["hop_count"], 4)

        hops = result["hops"]
        self.assertTrue(hops[0]["trusted"])
        self.assertTrue(hops[1]["trusted"])
        self.assertFalse(hops[2]["trusted"])
        self.assertFalse(hops[3]["trusted"])

        # 边界为第 3 跳（by 未命中）
        self.assertEqual(result["boundary"]["hop_index"], 3)
        self.assertEqual(result["boundary"]["by_host"], "relay.provider.example")
        self.assertEqual(result["boundary"]["reason"], REASON_NOT_LISTED)
        self.assertEqual(hops[2]["reason"], REASON_NOT_LISTED)

        # 第 4 跳 by 再次命中名单，但不得重新接入
        self.assertEqual(hops[3]["reason"], REASON_AFTER_BOUNDARY)
        self.assertTrue(hops[3]["rejoin_blocked"])
        self.assertTrue(hops[3]["listed"])

        # 最后可信跳为第 2 跳：from 主机与对端 IP 即外部交接点
        last = result["last_trusted"]
        self.assertEqual(last["hop_index"], 2)
        self.assertEqual(last["by_host"], "edge.final.example")
        self.assertEqual(last["from_host"], "relay.provider.example")
        self.assertEqual(last["ip"], "203.0.113.22")

    def test_boundary_on_missing_by_mid_chain(self):
        line_without_by = (
            "Received: from relay.provider.example (203.0.113.22) with ESMTP"
            f"; {D2}"
        )
        headers = _headers(
            [
                _received("mailbox.final.example", "edge.final.example", "10.0.0.2", D1),
                line_without_by,
            ]
        )
        result = analyze_trust_boundary(headers, ["mailbox.final.example"])
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["boundary"]["hop_index"], 2)
        self.assertEqual(result["boundary"]["reason"], REASON_MISSING_BY)
        self.assertFalse(result["hops"][1]["listed"])
        last = result["last_trusted"]
        self.assertEqual(last["hop_index"], 1)
        self.assertEqual(last["ip"], "10.0.0.2")

    def test_all_trusted_no_boundary(self):
        headers = _headers(
            [
                _received("mailbox.final.example", "edge.final.example", "10.0.0.2", D1),
                _received("edge.final.example", "relay.provider.example", "203.0.113.22", D2),
            ]
        )
        result = analyze_trust_boundary(
            headers, ["mailbox.final.example", "edge.final.example"]
        )
        self.assertEqual(result["status"], "established")
        self.assertIsNone(result["boundary"])
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["last_trusted"]["hop_index"], 2)
        self.assertTrue(all(h["trusted"] for h in result["hops"]))

    def test_host_matching_case_and_trailing_dot_insensitive(self):
        headers = _headers(
            [
                _received("Mailbox.Final.Example.", "edge.final.example", "10.0.0.2", D1),
                _received("EDGE.final.EXAMPLE", "relay.example", "203.0.113.1", D2),
                _received("relay.example", "out.example", "192.0.2.1", D3),
            ]
        )
        result = analyze_trust_boundary(
            headers, ["mailbox.final.example.", "edge.final.example"]
        )
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["boundary"]["hop_index"], 3)

    def test_sample_headers(self):
        result = analyze_trust_boundary(
            SAMPLE_HEADERS_TRUST,
            ["mailbox.final.example", "edge.final.example"],
        )
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["boundary"]["hop_index"], 3)
        last = result["last_trusted"]
        self.assertEqual(last["from_host"], "relay.provider.example")
        self.assertEqual(last["ip"], "203.0.113.22")
        # 示例最下方一跳 by 再次命中 edge，必须被拦在边界外
        self.assertTrue(result["hops"][3]["rejoin_blocked"])


@unittest.skipIf(create_app is None, "未安装 Flask")
class TrustBoundaryApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_success(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={
                "headers": SAMPLE_HEADERS_TRUST,
                "trusted_hosts": ["mailbox.final.example", "edge.final.example"],
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "established")
        self.assertEqual(data["boundary"]["hop_index"], 3)
        self.assertEqual(
            data["last_trusted"]["from_host"], "relay.provider.example"
        )

    def test_api_empty_hosts_returns_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": SAMPLE_HEADERS_TRUST, "trusted_hosts": []},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("trusted_hosts", resp.get_json()["error"])

    def test_api_missing_hosts_key_returns_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": SAMPLE_HEADERS_TRUST},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_bad_hosts_type_returns_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": SAMPLE_HEADERS_TRUST, "trusted_hosts": [1, 2]},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_empty_headers_returns_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": "   ", "trusted_hosts": ["mx.example"]},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_no_received_is_200_no_chain(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": "From: a@b.example\n", "trusted_hosts": ["mx.example"]},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "no_chain")

    def test_api_top_not_listed_is_200_no_chain(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={
                "headers": _received("unknown.example", date=D1),
                "trusted_hosts": ["mx.example"],
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "no_chain")
        self.assertIn("unknown.example", data["message"])

    def test_api_form_encoded_with_textarea_hosts(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            data={
                "headers": SAMPLE_HEADERS_TRUST,
                "trusted_hosts": "mailbox.final.example\nedge.final.example",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "established")

    def test_page_form_renders_result(self):
        resp = self.client.post(
            "/trust-boundary",
            data={
                "headers_trust": SAMPLE_HEADERS_TRUST,
                "trusted_hosts": "mailbox.final.example\nedge.final.example\n",
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("外部交接点", body)
        self.assertIn("relay.provider.example", body)
        self.assertIn("203.0.113.22", body)
        self.assertIn("不重新接入", body)

    def test_page_form_empty_hosts_shows_banner(self):
        resp = self.client.post(
            "/trust-boundary",
            data={"headers_trust": SAMPLE_HEADERS_TRUST, "trusted_hosts": "  "},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("名单不能为空", resp.get_data(as_text=True))

    def test_index_page_has_trust_section(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("/api/analyze/trust-boundary", body)
        self.assertIn('action="/trust-boundary"', body)


if __name__ == "__main__":
    unittest.main()
