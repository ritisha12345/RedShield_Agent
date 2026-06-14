"""Utilities for isolating user-provided content in LLM prompts."""

from html import escape


def xml_wrap_user_content(name: str, content: str) -> str:
    """Wrap user-provided content in XML tags after escaping it."""

    safe_name = _safe_xml_name(name)
    escaped_content = escape(content or "", quote=False)
    return f"<{safe_name}>\n{escaped_content}\n</{safe_name}>"


def _safe_xml_name(name: str) -> str:
    """Normalize a simple XML tag name for prompt delimiting."""

    normalized = "".join(
        character if character.isalnum() or character in {"_", "-"} else "_"
        for character in name.strip()
    )
    return normalized or "user_content"
