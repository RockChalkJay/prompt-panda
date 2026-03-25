# ipi_filter.py — Indirect Prompt Injection detection
# Regex-only, no external dependencies, runs instantly.
from __future__ import annotations
import re
from typing import Optional

_PATTERNS = [re.compile(p, re.I | re.M) for p in [
    # Direct override attempts
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
    r"disregard\s+(your\s+)?(system\s+prompt|instructions?|rules?)",
    r"forget\s+(everything|all)\s+(you('ve| have)\s+been\s+told|above)",
    r"override\s+(your\s+)?(previous\s+)?(instructions?|prompt|rules?)",
    # Role reassignment
    r"you\s+are\s+now\s+(a|an|the)\s+\w+",
    r"act\s+as\s+(if\s+you('re| are)\s+)?(a|an|the)\s+\w+",
    r"pretend\s+(you('re| are)|to\s+be)\s+(a|an|the)?\s*\w+",
    r"from\s+now\s+on\s+(you\s+are|act\s+as|you('re| will\s+be))",
    r"your\s+(new\s+)?(role|identity|persona|name)\s+is",
    # Authority spoofing
    r"(as|from)\s+(your\s+)?(developer|anthropic|openai|the\s+admin|system)",
    r"this\s+is\s+(a\s+)?(system|admin|developer|official)\s+message",
    r"i\s+am\s+(your\s+)?(creator|developer|administrator|owner)",
    r"\[system\]|\[admin\]|\[override\]|\[instruction\]",
    # Jailbreak framing
    r"(without|ignore)\s+(any\s+)?(safety|ethical|moral)\s+(guidelines?|rules?|constraints?|filters?)",
    r"DAN\s+mode|jailbreak|do\s+anything\s+now",
    r"developer\s+mode",
    # Exfiltration probes
    r"(repeat|print|output|show|reveal|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|rules?|configuration)",
    r"what\s+(are\s+)?(your|the)\s+(exact\s+)?(instructions?|system\s+prompt|rules?)",
    # Context termination tricks
    r"</?(context|system|prompt|instruction)>",
    r"\[end\s+(of\s+)?(system|context|instructions?)\]",
    r"---+\s*(system|instructions?|prompt)\s*---+",
    # Data injection via markup
    r"<\s*instructions?\s*>",
    r"\[\s*instructions?\s*\]",
    r"#{1,6}\s*(system|new\s+instructions?|override)",
]]


def ipi_check(text: str) -> Optional[str]:
    """
    Returns the matched snippet if IPI is detected, else None.
    Call this on any untrusted text before passing it to the LLM.
    """
    for pattern in _PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None
