"""
utils/eml_parser.py - Safe RFC 822 / MIME .eml Parsing Engine

Parses .eml files and raw email text using Python standard library email parsing
with modern policy.default. Treats uploaded email files as untrusted data, safely
extracting body text, HTML, headers, Received chain, URLs, domains, and IPs
without executing attachments or embedded scripts.
"""

import re
import hashlib
from email import policy
from email.parser import Parser, BytesParser
from typing import Union, Dict, Any, List

def extract_email_address(header_value: str) -> str:
    """Extract clean email address from a header value like 'Display Name <user@domain.com>'."""
    if not header_value:
        return ""
    match = re.search(r'<([^>]+)>', str(header_value))
    if match:
        return match.group(1).strip()
    if "@" in str(header_value):
        return str(header_value).strip().strip('"\'')
    return ""

def extract_domain_from_email(email_str: str) -> str:
    """Extract clean domain from an email address."""
    addr = extract_email_address(email_str)
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""

def parse_eml_file(file_content: Union[str, bytes]) -> Dict[str, Any]:
    """
    Safely parse raw email content (.eml or text) into a structured inspection dict.
    
    Never raises on malformed input or unusual encoding.
    Does NOT execute attachments or embedded scripts.
    """
    if isinstance(file_content, bytes):
        try:
            msg = BytesParser(policy=policy.default).parsebytes(file_content)
        except Exception:
            msg = Parser(policy=policy.default).parsestr(file_content.decode("utf-8", errors="ignore"))
    elif isinstance(file_content, str):
        try:
            msg = Parser(policy=policy.default).parsestr(file_content)
        except Exception:
            msg = Parser(policy=policy.default).parsestr(file_content)
    else:
        msg = Parser(policy=policy.default).parsestr(str(file_content))

    headers: Dict[str, Any] = {}
    received_chain: List[str] = []
    attachments: List[Dict[str, Any]] = []
    body_text_parts: List[str] = []
    body_html_parts: List[str] = []

    # Extract all headers
    all_header_tuples = []
    for k, v in msg.items():
        if not k:
            continue
        k_str = str(k)
        v_str = str(v)
        all_header_tuples.append((k_str, v_str))
        if k_str.lower() == "received":
            received_chain.append(v_str)
        else:
            headers[k_str] = v_str

    has_headers = len(all_header_tuples) > 0

    # Walk message payload
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                content_type = part.get_content_type()
                filename = part.get_filename()

                if filename or "attachment" in content_disposition.lower():
                    # Attachment metadata only (never execute)
                    attachments.append({
                        "filename": filename or "unnamed_attachment",
                        "content_type": content_type,
                        "size": len(part.get_payload(decode=True) or b"")
                    })
                elif content_type == "text/plain":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_text_parts.append(content)
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_html_parts.append(content)
                    except Exception:
                        pass
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if isinstance(content, str):
                    if content_type == "text/html":
                        body_html_parts.append(content)
                    else:
                        body_text_parts.append(content)
            except Exception:
                body_text_parts.append(msg.get_payload() or "")
    except Exception:
        pass

    full_body_text = "\n\n".join(body_text_parts)
    full_body_html = "\n\n".join(body_html_parts)

    # Fallback to raw text if parsing body yielded nothing but input exists
    if not full_body_text and isinstance(file_content, str):
        full_body_text = file_content

    # Core metadata
    from_header = headers.get("From", "")
    from_email = extract_email_address(from_header)
    sender_domain = extract_domain_from_email(from_email)
    subject = headers.get("Subject", "")
    date_str = headers.get("Date", "")
    message_id = headers.get("Message-ID", "")

    # Extract URLs from body + HTML
    from utils import extract_urls
    extracted_urls = extract_urls(full_body_text + " " + full_body_html)

    # Extract candidate IPs from headers
    from services.ip_extractor import extract_ips_from_email
    ip_extraction = extract_ips_from_email(file_content)

    return {
        "headers": headers,
        "all_headers": all_header_tuples,
        "received_chain": received_chain,
        "from_header": from_header,
        "from_email": from_email,
        "sender_domain": sender_domain,
        "subject": subject,
        "date": date_str,
        "message_id": message_id,
        "body_text": full_body_text,
        "body_html": full_body_html,
        "attachments": attachments,
        "urls": extracted_urls,
        "ip_extraction": ip_extraction,
        "has_headers": has_headers,
    }
