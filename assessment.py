"""Inspect visible URLs and turn validated observations into a result."""

import re
from urllib.parse import urlsplit

from guidance import PAID_NEXT_STEP, next_steps, reports_payment

# Also recognize a domain pasted on its own, such as example.com/login.
BARE_DOMAIN = r"(?:[a-z0-9-]+\.)+[a-z]{2,63}"
URL = re.compile(
    r"https?://[^\s<>\"']+|\bwww\.[^\s<>\"']+"
    + rf"|^\s*{BARE_DOMAIN}(?::[0-9]+)?(?:[/#?][^\s<>\"']*)?\s*$",
    re.I,
)
SENSITIVE = re.compile(
    r"[\w.+%-]+@[\w.-]+\.[a-z]{2,}"
    r"|(?<!\w)\+?\d(?:[ ().-]*\d){3,}(?!\w)"
    r"|\b(?:password|passcode|pin|otp)\s*[:=]\s*\S+",
    re.I,
)

# Screening the whole message also excludes quotes taken from inside a URL or identifier.
CONTACT_TOKEN = re.compile(r"(?<!\S)\S*(?:@|://|[\w-]\.[^\W\d_])\S*")
QUOTE_TEXT = re.compile(r"[\w ,.!?'’$€£%()\-]+")
SIGNALS = {
    "credentials_requested": "The message asks for login credentials.",
    "verification_code_requested": "The message asks you to share a security code. Keep the code private.",
    "payment_details_requested": "The message asks for card or bank details.",
    "unexpected_payment_requested": "The message asks for an unusual or poorly explained payment.",
    "sensitive_information_requested": "The message asks for sensitive personal details.",
    "software_or_access_requested": "The message asks you to install software, open an attachment, or grant access.",
    "identity_mismatch": "The claimed sender conflicts with visible contact or link details.",
    "misleading_link": "The link's visible wording or destination is potentially misleading.",
    "unverified_contact_requested": "The message directs you to an unverified contact channel.",
    "pressure_or_threat": "The message uses a deadline or threat to push you to act.",
    "secrecy_or_process_bypass": "The message asks you to keep the request secret or skip a verification step.",
    "reward_lure": "The message uses a reward to encourage a risky action.",
}


THREAT_CATEGORIES = {"phishing", "malware", "phishing and fraud"}
VERDICTS = ("Looks routine", "Unclear", "Suspicious", "Likely scam")

PAGE_SIGNALS = {
    "scan_sensitive_request": "The captured page appears to request sensitive information in a suspicious context.",
    "scan_impersonation": "The captured page shows signs of impersonation.",
    "scan_threat_category": "Cloudflare assigned a threat-related category to the scanned site.",
}


# Local wording weights. Zero-point phrases consume their own words, e.g. "do not click".
QUICK_PHRASE_WEIGHTS = {
    "payment": 10,
    "immediately": 5,
    "now": 2,
    "click": 5,
    "gift card": 20,
    "run command": 50,
    "delivery of your parcel is on hold": 10,
    "complete payment for delivery": 30,
    "outstanding delivery fee": 30,
    "to avoid cancellation": 15,
    "will be blocked today": 15,
    "final notice": 5,
    "pay now": 10,
    "typo in your delivery address": 10,
    "your address must be corrected": 15,
    "confirm the delivery address here": 15,
    "check turn on last location": 10,
    "complete your refund": 15,
    "click here to claim your tax refund": 25,
    "submit your fica documents to receive your refund": 30,
    "enter your banking details to receive your tax refund": 35,
    "confirm your bank details to release your refund": 35,
    "reply to this email with your banking details and id number": 35,
    "to secure your position": 30,
    "pay a deposit to secure the job": 60,
    "pay to secure your interview": 60,
    "pay the interview fee": 60,
    "pay the recruitment fee": 60,
    "get paid to like videos": 10,
    "earn money by liking videos": 10,
    "deposit money to unlock the next task": 55,
    "top up to unlock more tasks": 55,
    "pay to unlock your commission": 55,
    "deposit your own money to earn more": 55,
    "claim your winnings": 10,
    "keep this transaction confidential": 15,
    "pay the fee to release your winnings": 50,
    "pay the clearance fee to receive your inheritance": 50,
    "pay the release fee to receive the funds": 50,
    "a criminal case has been opened against you": 10,
    "pay to make the case disappear": 60,
    "pay us to drop the charges": 60,
    "pay to avoid arrest": 60,
    "buy some gift cards": 20,
    "send me the gift card numbers": 55,
    "send a photo of the gift card pin": 60,
    "send me the numbers on the back of the gift cards": 60,
    "send the voucher pin": 60,
    "verify your banking details using this link": 25,
    "reply with your card details": 35,
    "tell me your banking pin": 60,
    "send me your online banking password": 60,
    "reply with your pin": 60,
    "paste the command into terminal": 50,
    "paste the command into powershell": 50,
    "run the command to complete verification": 60,
    "run this command to verify you are human": 60,
    "give me remote access to your computer": 50,
    "payment received": 0,
    "payment successful": 0,
    "do not click": 0,
    "gift cards available in store": 0,
    "each update costs": 0,
    "never share your sign in code": 0,
    # Previously recognized first-impression phrases.
    "enter your password": 25,
    "send your verification code": 60,
    "share your one time code": 60,
    "enter your card details": 25,
    "redelivery fee": 15,
    "pay immediately": 15,
    "account will be suspended": 15,
    "urgent action required": 15,
    "pay with gift cards": 50,
    "send gift card codes": 55,
    "claim your prize": 15,
    "verify your account": 15,
    "seed phrase": 15,
    "wire transfer": 15,
    "send your otp": 60,
    "urgent": 15,
    "redelivery": 15,
}
# At each starting word, try longer phrases first so their component words score only once.
QUICK_PATTERN = re.compile(
    r"\b(?:(?P<negation>do not|don t|never) )?(?P<phrase>"
    + "|".join(re.escape(phrase) for phrase in sorted(QUICK_PHRASE_WEIGHTS, key=len, reverse=True))
    + r")\b"
)


def is_url_only(message):
    return URL.fullmatch(message.strip()) is not None


def quick_phrases(message):
    text = CONTACT_TOKEN.sub(" | ", URL.sub(" | ", message)).casefold()
    # Keep sentence breaks and removed URLs as boundaries, including between "pay" and "now".
    words = " ".join(re.findall(r"[^\W_]+|[.!?;|]", text))
    matches = {}
    for match in QUICK_PATTERN.finditer(words):
        phrase = match["phrase"]
        if not match["negation"] and QUICK_PHRASE_WEIGHTS[phrase]:
            matches[phrase] = QUICK_PHRASE_WEIGHTS[phrase]
    return sorted(matches, key=matches.get, reverse=True)


def parse_url(value: str):
    value = value.strip().rstrip(".,!?;)")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        value = "https://" + value
    return urlsplit(value)


def comparison_url(url):
    parts = parse_url(url)
    return parts._replace(netloc=parts.netloc.lower(), path=parts.path or "/", fragment="").geturl()


def target_urls(message):
    """Return the first eligible hostname, fragment-free URL and homepage."""
    for match in URL.finditer(message):
        try:
            link = parse_url(match.group())
            host = (link.hostname or "").encode("idna").decode().lower()
            if link.username is not None or link.port not in (None, 80, 443):
                continue
            if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
                continue
            if host.endswith((".internal", ".localhost", ".local", ".lan", ".onion", ".test", ".example", ".invalid", ".home.arpa")):
                continue
            authority = host if link.port is None else f"{host}:{link.port}"
            origin = f"{link.scheme}://{authority}/"
            return host, comparison_url(link._replace(netloc=authority).geturl()), origin
        except (ValueError, UnicodeError):
            continue
    return None


def visible_links(message):
    """Locally extracted links for display as inert text. Never visit them."""
    return list(dict.fromkeys(match.group().strip().rstrip(".,!?;)") for match in URL.finditer(message)))[:10]


def visible_hostnames(message):
    hosts = []
    for match in URL.finditer(message):
        try:
            host = parse_url(match.group()).hostname
        except ValueError:
            continue
        if host and host not in hosts:
            hosts.append(host)
            if len(hosts) == 10:
                break
    return hosts


def quotable_text(text):
    return CONTACT_TOKEN.sub("\0", SENSITIVE.sub("\0", URL.sub("\0", text)))


def ai_review(observations, message, web_view, scan=None, *, with_context=False, source_flagged=False):
    url_only = is_url_only(message)
    findings = []
    access_review = any(signal["code"] == "software_or_access_requested"
                        or signal.get("risk_action") == "install_or_grant_access" for signal in observations["signals"])
    descriptions = {**SIGNALS, **PAGE_SIGNALS, "provider_warning": "A source reported a threat relevant to this link."}
    for signal in observations["signals"]:
        code = signal["code"]
        if code == "observation":
            source = {"input": "Submitted URL" if url_only else "Submitted text", "page_text": "Captured page text",
                      "scan_record": "Cloudflare scan record", "screenshot": "AI reading of screenshot"}[signal["source"]]
            # The validator has checked textual spans against their named source.
            material = {"input": message, "page_text": scan.page_text if scan else ""}.get(
                signal["source"], "\n".join(signal["evidence"]))
        elif code == "provider_warning":
            source, material = "Source report", "\n".join(signal["evidence"])
        elif code == "scan_threat_category":
            source, material = "Domain category", "\n".join(scan.categories)
        elif code in PAGE_SIGNALS:
            source, material = "Captured page text", scan.page_text
        else:
            source, material = "Submitted URL" if url_only else "Submitted text", message
        evidence = signal["evidence"]
        # A second finding can quote the same session link as the access finding.
        submitted = code in SIGNALS or signal.get("source") == "input"
        filter_quotes = not web_view or (access_review and submitted) or signal.get("risk_action") == "install_or_grant_access"
        if filter_quotes:
            visible = quotable_text(material)
            evidence = [span for span in evidence if span in visible and (web_view or QUOTE_TEXT.fullmatch(span))]
        description = signal["label"] if code == "observation" else descriptions[code]
        if code == "software_or_access_requested" and signal.get("risk_action") == "run_command":
            description = "The message asks you to run a command on your device."
        finding = {"code": code, "description": description, "evidence_source": source, "evidence": evidence}
        if code == "observation":
            finding["source"] = signal["source"]
        if signal.get("risk_action"):
            finding["risk_action"] = signal["risk_action"]
        meaning = signal.get("english_meaning")
        if meaning and (not filter_quotes or (evidence == signal["evidence"] and quotable_text(meaning) == meaning)):
            finding["english_meaning"] = meaning
        findings.append(finding)

    notes = []
    if url_only and not findings:
        if not scan:
            notes.append("The AI had no captured page text or screenshot to examine. The URL and reputation lookups alone could not establish what this site does.")
        elif not (scan.page_text or observations.get("image_sent")):
            notes.append("The AI had Cloudflare scan metadata, but no page text or screenshot to examine.")
        else:
            notes.append("The AI could not establish a specific warning from the available URL and scan evidence.")
    elif not findings:
        notes.append("The AI reported no supported warning signs in this material.")
    if not findings and source_flagged:
        notes.append("An independent source flagged this link.")
    routine_evidence = observations.get("routine_evidence")
    routine_source = scan.page_text if url_only and scan else message
    if routine_evidence and (web_view or routine_evidence in quotable_text(routine_source)):
        source = "captured page" if url_only else "message"
        notes.append(f'The AI read this {source} wording as routine: “{routine_evidence}”.')
    if observations["evidence_status"] == "insufficient":
        notes.append("There was too little context for a full assessment.")
    title = "Message with source context" if with_context else "Submitted message"
    if url_only:
        title = "URL with source reports" if with_context else "Submitted URL"
    if scan:
        title += f" · Cloudflare {scan.scope} · {scan.capture_date}"
    details = {} if url_only else observations.get("request_details", {})
    if not web_view or access_review:
        # Keep session links out of remote-access findings, including verbatim request details.
        visible = quotable_text(message)
        if web_view:
            details = {key: value for key, value in details.items() if value in visible}
        else:
            details = {key: (value if not value or value in visible else "Omitted in chat") for key, value in details.items()}
    return {"request_details": details, "stage": "context" if with_context else "message", "title": title, "verdict": observations["verdict"],
            "evidence_status": observations["evidence_status"], "signals": findings, "note": " ".join(notes)}


def display_quote(spans: list[str], used: list[str], web_view: bool) -> str | None:
    if len(used) >= 2:
        return None
    for span in spans:
        quote = span.strip()
        if len(quote) > 120 or not quote.isprintable():
            continue
        if not web_view and len(quote.split()) < 2:
            continue
        if any(quote in prior or prior in quote for prior in used):
            continue
        return quote
    return None


def assess(message: str, opinion: dict | None = None, scan=None,
           *, with_context=False, web_view=False, reputation_checks=()) -> dict:
    direct_findings = [detail for status, detail in reputation_checks if status != "unavailable"]
    if scan and scan.categories:
        direct_findings.append(f"Cloudflare scan categories ({scan.scope}, {scan.date}): " + ", ".join(scan.categories) + ".")
    if scan and scan.indicators:
        indicators = "; ".join(scan.indicators)
        if not web_view:
            indicators = indicators.replace(".", "[.]").replace("://", "[://]")
        direct_findings.append(f"Cloudflare scan observations ({scan.scope}, {scan.date}): {indicators}.")
    if scan and scan.page_text:
        direct_findings.append(f"Cloudflare captured readable page text from the {scan.scope} on {scan.capture_date}.")
    if scan and scan.malicious is None:
        direct_findings.append(f"Cloudflare supplied no overall threat verdict for the {scan.scope} on {scan.date}.")
    if scan and scan.malicious:
        direct_findings.append(f"Cloudflare flagged the {scan.scope} as malicious at scan time.")

    verdict = opinion["verdict"] if opinion else "Unclear"
    reviews = []
    reasons = []
    wording_only = bool(opinion and opinion.get("wording_only"))
    if opinion:
        flagged = any(status == "flagged" for status, _ in reputation_checks)
        if scan and (scan.malicious or any(label.casefold() in THREAT_CATEGORIES for label in scan.categories)):
            flagged = True
        for index, (text, part) in enumerate(opinion.get("parts", [(message, opinion)]), 1):
            if part:
                review = ai_review(part, text, web_view, None if wording_only else scan,
                                   with_context=with_context and not wording_only, source_flagged=flagged)
                if wording_only:
                    review["wording_only"] = True
            else:
                review = {"stage": "message", "title": "Submitted message", "signals": [], "request_details": {},
                          "verdict": "Unclear", "evidence_status": "insufficient", "note": "We couldn’t finish reviewing this part."}
            if "parts" in opinion:
                review["part_number"] = index
                quote = part.get("routine_evidence") if part else None
                if quote and quote in quotable_text(text):
                    review["part_summary"] = f'This part says “{quote}”'
                elif review["signals"]:
                    review["part_summary"] = review["signals"][0]["description"]
                else:
                    review["part_summary"] = "This part looks routine." if review["verdict"] == "Looks routine" else review["note"]
            reviews.append(review)
        used_quotes = []
        findings = [finding for review in reviews for finding in review["signals"]]
        for finding in findings[:3]:
            reason = finding["description"]
            quote = display_quote(finding["evidence"], used_quotes, web_view)
            if quote:
                reason += f' {finding["evidence_source"]}: “{quote}”'
                used_quotes.append(quote)
            reasons.append(reason)
    if not reasons:
        reasons = [detail for status, detail in reputation_checks if status == "flagged"]
        if scan and scan.malicious:
            reasons.append(direct_findings[-1])

    url_only = is_url_only(message)
    next_step, recovery, options = next_steps(opinion["signals"] if opinion else [], has_link=bool(URL.search(message)),
                                              url_only=url_only, verdict=verdict)
    already_paid = reports_payment(URL.sub(" ", message))
    if already_paid:
        next_step = PAID_NEXT_STEP

    scope_notes = []
    if wording_only:
        scope_notes.append("This verdict is based on the message wording. The link’s destination remains unverified.")
    if url_only:
        scope_notes.append("This check cannot verify who operates the site or what it serves now.")
    if scan and scan.scope == "site homepage":
        scope_notes.append(f"Page evidence covers the homepage as captured on {scan.capture_date}.")
    scope_note = " ".join(scope_notes)
    limitations = ["AI analysis completed." if opinion else "Limited check. No AI opinion is available.", *scope_notes]
    if opinion and opinion["evidence_status"] == "insufficient":
        limitations.append("The available evidence is limited.")
    for status, detail in reputation_checks:
        if status == "unavailable":
            limitations.append(detail)
    return {"input_type": "url" if url_only else "message", "verdict": verdict, "reasons": reasons, "next_step": next_step, "limitations": " ".join(limitations),
            "already_paid": already_paid, "recovery_steps": recovery, "recovery_options": options, "scope_note": scope_note, "direct_findings": direct_findings, "ai_reviews": reviews}
