from __future__ import annotations

import re
from datetime import datetime

from django import template


register = template.Library()


_ACRONYMS = {
    "api": "API",
    "http": "HTTP",
    "https": "HTTPS",
    "ssh": "SSH",
    "uid": "UID",
    "ip": "IP",
    "dns": "DNS",
    "url": "URL",
    "id": "ID",
    "sha": "SHA",
}


@register.filter
def display_value(value):
    if value is None:
        return ""

    raw_value = getattr(value, "value", value)

    if raw_value is None:
        return ""

    text = str(raw_value).strip()

    if not text:
        return ""

    words = re.split(r"[_\-\s]+", text)

    formatted = []

    for word in words:
        if not word:
            continue

        lower = word.lower()

        if lower in _ACRONYMS:
            formatted.append(_ACRONYMS[lower])
        else:
            formatted.append(lower[:1].upper() + lower[1:])

    return " ".join(formatted)


@register.filter
def display_datetime(value):
    """
    Format a datetime as YYYY-MM-DD HH:MM:SS.
    """

    if value is None:
        return ""

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    text = str(value).strip()

    if not text:
        return ""

    try:
        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text