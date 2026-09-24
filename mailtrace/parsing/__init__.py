"""邮件原始头部解析包。"""

from .arc import check_arc_chain
from .batch import BATCH_DELIMITER, batch_delay_analysis, split_batch_headers
from .compare import compare_headers
from .dkim import audit_dkim_coverage
from .parser import analyze_headers, parse_header_blocks
from .share import build_share_report

__all__ = [
    "BATCH_DELIMITER",
    "analyze_headers",
    "audit_dkim_coverage",
    "batch_delay_analysis",
    "build_share_report",
    "check_arc_chain",
    "compare_headers",
    "parse_header_blocks",
    "split_batch_headers",
]
