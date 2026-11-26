"""User guidance for actions identified in a message or captured page."""

import json
import re
from pathlib import Path

with (Path(__file__).parent / "static" / "recovery.json").open(encoding="utf-8") as source:
    RECOVERY_CHOICES = json.load(source)
RESCUE_OPTIONS = {choice["action"]: choice for choice in RECOVERY_CHOICES if "action" in choice}
COMMAND_RECOVERY = next(choice for choice in RECOVERY_CHOICES if choice["reply"] == "COMMAND")

PAID_NEXT_STEP = "Before sending any more money, please follow the steps in Already clicked or paid?"
PAYMENT_REPORT = re.compile(
    r"\b(?:i|we)(?:'ve|\s+(?:have|had|did))?\s+(?:(?:already|just|also|actually)\s+)*"
    r"(?:paid\b(?!\s+(?:attention|tribute|a visit|my respects|nothing|no\b))"
    r"|made\s+(?:(?:a|an|the|my|our)\s+)?(?:payment|bank transfer|transfer|deposit|eft)\b"
    r"|(?:sent|wired|transferred|deposited)\s+(?:(?:them|him|her)\s+)?"
    r"(?:(?:(?:the|my|our|some|a)\s+)?(?:money|funds|payment|deposit|fee)\b"
    r"|(?:[$£€]|(?:r|zar|usd|gbp|eur)\s*)\d|\d[\d ,.]*\s*(?:rand|dollars?|pounds?|euros?)\b))",
    re.I,
)


def reports_payment(message):
    """Recognize explicit English self-reports in the submitter’s own wording."""
    text = message.casefold().replace("’", "'").replace("‘", "'")
    text = re.sub(r'''["“][^"”]*["”]|(?<!\w)'.*?'(?!\w)|^\s*>[^\n]*''', " ", text, flags=re.M)
    if re.match(r"^\s*already\s+", text):
        text = "i " + text.lstrip()
    # A separate clause can contain an actual payment after quoting someone else's request.
    for clause in re.split(r"[.!;,\n]|(?<=\?)|\b(?:but|so|and)\b", text):
        match = PAYMENT_REPORT.search(clause)
        if not match:
            continue
        prefix = clause[:match.start()].strip()
        if clause.rstrip().endswith("?") and not prefix and not re.search(r"\b(?:what|why|how|can|should|is|was)\b", clause[match.end():]):
            continue
        if prefix.endswith(":") and prefix not in {"me:", "update:"}:
            continue
        if not re.search(r"\b(?:if|whether|wish|suppose|pretend|said|says?|asked|told|claims?|wrote|reads?)\b|\b(?:did|have|had)\s*$", prefix):
            return True
    return False

PAYMENT_RECOVERY = (
    "If you paid, contact your bank or payment provider through its official app now. "
    "Ask whether it can stop, recall or dispute the payment. Save the receipt and conversation."
)
PASSWORD_RECOVERY = (
    "If you entered a password, use the service’s official app or a known address to change it. "
    "Sign out other sessions, enable two-step verification and change that password anywhere you reused it."
)

# Each entry pairs a preventive step with a conditional recovery step.
ADVICE = {
    "buy_gift_card": (
        "Buy the gift card directly from the retailer or a seller listed on its official site. Skip this discounted offer.",
        PAYMENT_RECOVERY,
    ),
    "pay_by_gift_card": (
        "Keep the gift card and its redemption code. A request to settle a bill or fee with gift cards is a warning sign.",
        " ".join(RESCUE_OPTIONS["pay_by_gift_card"]["paragraphs"]),
    ),
    "pay_in_chat": (
        "Keep payment out of the seller’s private chat. Use a checkout with buyer protection.",
        PAYMENT_RECOVERY,
    ),
    "pay_delivery_fee": (
        "Check the shipment in the courier’s official app using the tracking number from your original order before paying a fee.",
        PAYMENT_RECOVERY,
    ),
    "send_money": (
        "Pause the payment. Confirm the request and payment details with the recipient using a contact method you already trust.",
        PAYMENT_RECOVERY,
    ),
    "give_card_details": (
        "Keep your card details off this form. Open the merchant’s official app or site independently.",
        "If you entered card details, lock the card if your banking app allows it. Call the issuer using the number on the card to ask about replacement and dispute any unfamiliar charges.",
    ),
    "give_password": (
        "Open the service’s official app yourself to check your account. Keep your password out of the supplied form or chat.",
        PASSWORD_RECOVERY,
    ),
    "give_security_code": (
        "Keep the one-time code private and decline any sign-in or payment approval you did not start.",
        "If you shared a code or approved a prompt, contact the service through its official app now. Ask it to secure the account and check for unauthorized sign-ins or payments.",
    ),
    "share_identity_details": (
        "Verify who needs the information and why through an official channel before sharing identity details or documents.",
        " ".join(RESCUE_OPTIONS["share_identity_details"]["paragraphs"]),
    ),
    "install_or_grant_access": (
        "Leave the attachment or download unopened and decline requests for remote access. Contact support independently.",
        " ".join(RESCUE_OPTIONS["install_or_grant_access"]["paragraphs"]),
    ),
    "run_command": (
        "Don’t paste or run the command. If you already ran it, open “Already clicked or paid?” "
        f"and choose “{COMMAND_RECOVERY['label']}”.",
        " ".join(COMMAND_RECOVERY["paragraphs"]),
    ),
    "contact_stranger": (
        "Verify the request independently before replying or moving to a private conversation.",
        " ".join(RESCUE_OPTIONS["contact_stranger"]["paragraphs"]),
    ),
}

DEFAULT_ACTION = {
    "credentials_requested": "give_password",
    "verification_code_requested": "give_security_code",
    "payment_details_requested": "give_card_details",
    "unexpected_payment_requested": "send_money",
    "sensitive_information_requested": "share_identity_details",
    "software_or_access_requested": "install_or_grant_access",
    "unverified_contact_requested": "contact_stranger",
}


def next_steps(signals, *, has_link, url_only, verdict):
    prevention = []
    recovery = []
    for signal in signals:
        action = signal.get("risk_action") or DEFAULT_ACTION.get(signal["code"])
        if action in ADVICE:
            before, after = ADVICE[action]
            if before not in prevention:
                prevention.append(before)
            if after not in recovery:
                recovery.append(after)
            if action == "pay_in_chat" and ADVICE["contact_stranger"][1] not in recovery:
                recovery.append(ADVICE["contact_stranger"][1])

    if not prevention:
        if verdict == "Looks routine":
            prevention.append("If you recognize the notice, use your usual app or bookmark for any follow-up.")
        elif url_only:
            prevention.append("Leave this link unopened. If you need the site, reach it through a bookmark or an address you already trust.")
        else:
            prevention.append("Verify the request using the organization’s official app or a contact method you already trust.")
        if verdict != "Looks routine":
            recovery.extend([PAYMENT_RECOVERY, PASSWORD_RECOVERY])

    if has_link:
        recovery.append("If you only opened the link, close the page. Leave downloads unopened and decline any permission prompts.")
    elif not recovery:
        recovery.append("If you only read the message, no account changes are usually needed. You can check any unexpected activity in the official app.")
    elif not signals:
        recovery.append(ADVICE["contact_stranger"][1])
    options = [{"label": choice["label"], "advice": ADVICE[action][1], "reply": choice["reply"]}
               for action, choice in RESCUE_OPTIONS.items()
               if ADVICE[action][1] in recovery]
    return " ".join(prevention), recovery, options
