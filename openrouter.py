"""Send submitted text to OpenRouter and validate the returned observations."""

import asyncio
import json
import logging
import os
import re
from time import monotonic
from pathlib import Path

import httpx

from guidance import ADVICE
from assessment import PAGE_SIGNALS, SIGNALS, THREAT_CATEGORIES, URL, VERDICTS, is_url_only, target_urls, visible_hostnames

logger = logging.getLogger("uvicorn.error")
AI_TIMEOUT = 20
VISUAL_REVIEW_TIMEOUT = 55
API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
MODEL = os.getenv("OPENROUTER_MODEL", "").strip()
LOG_AI_RESPONSES = os.getenv("LOG_AI_RESPONSES") == "1"
PROMPT = Path(__file__).with_name("PHISHING_PROMPT.md").read_text().split("```text\n", 1)[1].split("\n```", 1)[0]


def routing_hint(response: httpx.Response) -> str:
    """Classify OpenRouter's 404 without logging potentially sensitive upstream text."""
    try:
        message = response.json()["error"]["message"]
    except (ValueError, KeyError, TypeError, RecursionError):
        return "unspecified"
    if not isinstance(message, str):
        return "unspecified"
    message = message.lower()
    if any(term in message for term in ("data policy", "privacy", "data collection", "data retention", "zdr")):
        return "privacy_policy"
    if any(term in message for term in ("not a valid model", "unknown model", "model not found")):
        return "model_not_found"
    if "no endpoints" in message or "no available provider" in message:
        return "no_matching_endpoint"
    return "unspecified"


def visual_brand(value):
    """Keep the image interpretation bounded and separate from verified text evidence."""
    if not isinstance(value, dict) or value.keys() != {"status", "name", "cue"}:
        return None
    status, name, cue = value["status"], value["name"], value["cue"]
    if status == "no_clear_brand" and name is None and cue is None:
        return {"status": status}
    if status not in ("brand_visible", "possible_impersonation") or cue not in ("logo", "wordmark", "branded_form"):
        return None
    if not isinstance(name, str) or not 1 <= len(name) <= 60 or not any(c.isalpha() for c in name):
        return None
    if not all(c.isalnum() or c in " .&+!-'’" for c in name) or name != name.strip():
        return None
    return {"status": status, "name": name, "cue": cue}


class UnsupportedFindings(ValueError):
    """The model proposed a warning without a finding we could validate."""


class InvalidReply(ValueError):
    """A fixed diagnostic code safe for logs even when raw response logging is off."""


DETAIL_FIELDS = ("claimed_sender", "recipient", "action", "reason", "method", "deadline", "amount", "consequence")


def assessment_format(codes, threat_categories, flagged_details, *, image_sent, url_only):
    def obj(**properties):
        return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}

    def choice(values):
        return {"type": ["string", "null"] if None in values else "string", "enum": values}

    nullable = {"type": ["string", "null"]}
    evidence = {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 2,
                "description": "For page text copy short, contiguous quotes exactly. Put separate excerpts in separate items."}
    annotations = {
        "evidence": evidence,
        "english_meaning": {**nullable, "description": "Translate non-English quotes into English. Use null for English evidence."},
        "risk_action": {**choice([*ADVICE, None]), "description": "The action supported by the evidence. Use null if none applies."},
    }
    sources = ["input", "page_text", "scan_record", "screenshot"] if image_sent else ["input"]
    observation = obj(code=choice(["observation"]), source=choice(sources),
                      label={"type": "string"}, **annotations)
    variants = [observation]
    named_codes = [c for c in codes if c not in ("observation", "scan_threat_category", "provider_warning")]
    variants.append(obj(code=choice(named_codes), **annotations))
    # The model can select a known warning without retyping punctuation or confusing tags with categories.
    for code, choices in (("scan_threat_category", threat_categories), ("provider_warning", flagged_details)):
        if choices:
            fields = {**annotations, "evidence": {**evidence, "items": choice(choices), "description": "Select a supplied source value."}}
            variants.append(obj(code=choice([code]), **fields))
    brand = obj(status=choice(["brand_visible", "possible_impersonation", "no_clear_brand"]),
                name=nullable, cue=choice(["logo", "wordmark", "branded_form", None]))
    extra = {"brand_check": brand} if image_sent else {}
    if not url_only:
        extra["request_details"] = obj(**dict.fromkeys(DETAIL_FIELDS, nullable))
    schema = obj(verdict=choice(list(VERDICTS)), evidence_status=choice(["assessable", "insufficient"]),
                 signals={"type": "array", "items": {"anyOf": variants}, "maxItems": 5},
                 routine_evidence=nullable, **extra)
    return {"type": "json_schema", "json_schema": {"name": "assessment", "strict": True, "schema": schema}}


def validate(raw: str, message: str, scan=None, reports=(), *, image_sent=False) -> dict:
    return validate_opinion(json.loads(raw), message, scan, reports, image_sent=image_sent)


def validate_opinion(result, message, scan, reports, *, image_sent):
    if not isinstance(result, dict):
        raise ValueError("Expected an assessment object")
    result = result.copy()
    brand = result.pop("brand_check", None)
    details = result.pop("request_details", None)
    routine_evidence = result.pop("routine_evidence", None)
    if result.keys() != {"signals", "evidence_status", "verdict"}:
        raise ValueError("Invalid assessment shape")
    if result["verdict"] not in VERDICTS:
        raise ValueError("Invalid verdict")
    if result["evidence_status"] not in ("assessable", "insufficient"):
        raise ValueError("Invalid evidence status")
    signals = result["signals"]
    if not isinstance(signals, list) or len(signals) > 5:
        raise ValueError("Invalid signal list")
    accepted = []
    seen = set()
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        # A translation is presentation only. Verify the original excerpts independently.
        signal = signal.copy()
        meaning = signal.pop("english_meaning", None)
        action = signal.pop("risk_action", None)
        try:
            check_signal(signal, message, scan, reports, image_sent=image_sent)
        except ValueError:
            continue
        key = (signal["code"], signal.get("source"), signal.get("label"))
        if key not in seen:
            if (isinstance(action, str) and action in ADVICE
                    and signal["code"] not in ("provider_warning", "scan_threat_category")
                    and signal.get("source") != "scan_record"):
                signal["risk_action"] = action
            if (isinstance(meaning, str) and 0 < len(meaning) <= 180 and meaning.strip()
                    and meaning.isprintable() and signal.get("source") != "screenshot"):
                signal["english_meaning"] = meaning
            accepted.append(signal)
            seen.add(key)
    if result["verdict"] == "Looks routine":
        wording = message
        if is_url_only(message):
            wording = scan.page_text if scan and scan.scope == "linked page" else ""
        if (signals or result["evidence_status"] != "assessable" or not isinstance(routine_evidence, str)
                or not routine_evidence.strip() or not routine_evidence.isprintable() or len(routine_evidence) > 160
                or routine_evidence not in URL.sub("\0", wording)):
            raise ValueError("Routine verdict requires grounded, assessable wording and no warning signals")
        result["routine_evidence"] = routine_evidence
    if not accepted and (signals or result["verdict"] in ("Suspicious", "Likely scam")):
        raise UnsupportedFindings("No supported signals from this review")
    if len(accepted) != len(signals):
        result["omitted_signals"] = len(signals) - len(accepted)
    result["signals"] = accepted
    if is_url_only(message) or not isinstance(details, dict):
        details = {}
    grounded = {}
    for key in DETAIL_FIELDS:
        span = details.get(key)
        valid = isinstance(span, str) and 0 < len(span) <= 160 and span.strip() and span.isprintable() and span in message
        if valid:
            grounded[key] = span
    result["request_details"] = grounded
    if image_sent:
        result["brand_check"] = visual_brand(brand)
    result["image_sent"] = image_sent
    return result


def check_signal(signal, message, scan, reports, *, image_sent=False):
    if not isinstance(signal, dict):
        raise ValueError("Invalid signal shape")
    code = signal.get("code")
    custom = code == "observation"
    fields = {"code", "evidence", "label", "source"} if custom else {"code", "evidence"}
    if signal.keys() != fields:
        raise ValueError("Invalid signal shape")
    spans = signal["evidence"]
    if custom:
        label, source = signal["label"], signal["source"]
        if not isinstance(label, str) or not re.fullmatch(r"[^\W\d_][\w ’'(),%:;–—-]{2,79}", label):
            raise ValueError("Invalid observation label")
        if source not in ("input", "page_text", "scan_record", "screenshot") or (source != "input" and not scan):
            raise ValueError("Observation source unavailable")
        if source == "screenshot" and not (image_sent and scan.image):
            raise ValueError("Screenshot was not attached")
    elif not isinstance(code, str) or not (code in SIGNALS or (scan and code in PAGE_SIGNALS) or (reports and code == "provider_warning")):
        raise ValueError("Invalid code for this review")
    elif is_url_only(message) and code in SIGNALS and code != "misleading_link":
        raise ValueError("A URL alone does not contain a sender's request")
    minimum = 2 if code == "identity_mismatch" else 1
    if not isinstance(spans, list) or not minimum <= len(spans) <= 2:
        raise ValueError("Invalid evidence list")
    for span in spans:
        if not isinstance(span, str) or not span.strip() or len(span) > 180:
            raise ValueError("Invalid evidence span")
        if custom:
            if source == "scan_record":
                matches = span in [scan.title, scan.landing_host, *scan.indicators, *scan.categories]
            elif source == "screenshot":
                # Pixels have no exact text source. Display these cues explicitly as AI interpretations.
                matches = span.isprintable()
            else:
                matches = span in (message if source == "input" else scan.page_text)
        elif code == "provider_warning":
            matches = any(row["status"] == "flagged" and row["detail"] == span for row in reports)
        elif code == "scan_threat_category":
            matches = span in scan.categories and span.casefold() in THREAT_CATEGORIES
        else:
            matches = span in (scan.page_text if code in PAGE_SIGNALS else message)
        if not matches:
            raise ValueError("Evidence missing from its source")
    if len(set(spans)) != len(spans):
        raise ValueError("Duplicate evidence spans")


def log_configuration() -> None:
    missing = []
    if not API_KEY:
        missing.append("OPENROUTER_API_KEY")
    if not MODEL:
        missing.append("OPENROUTER_MODEL")
    if missing:
        logger.info("Message AI disabled. Missing %s", ", ".join(missing))
    else:
        logger.info("OpenRouter configured. Submissions will attempt AI analysis.")
    if LOG_AI_RESPONSES:
        logger.warning("AI response logging enabled. Replies may quote submitted text.")


async def analyze(
    message: str, *, api_key: str = API_KEY, model: str = MODEL, prompt: str = PROMPT, scan=None, reports=(), logger=logger,
    on_failure=None
) -> dict | None:
    if not (api_key and model):
        logger.info("Assessment message review skipped reason=ai_disabled")
        return None
    settings = dict(api_key=api_key, model=model, prompt=prompt, logger=logger, on_failure=on_failure)
    parts = separate_messages(message) if not (scan or reports) else []
    if not parts:
        return await analyze_one(message, scan=scan, reports=reports, **settings)

    opinions = await asyncio.gather(*(analyze_one(part, **settings) for part in parts))
    if not any(opinions):
        return None
    verdicts = [op["verdict"] if op else "Unclear" for op in opinions]
    return {
        "verdict": max(verdicts, key=VERDICTS.index),
        "signals": [signal for op in opinions if op for signal in op["signals"]],
        "evidence_status": "assessable" if all(op and op["evidence_status"] == "assessable" for op in opinions) else "insufficient",
        "parts": list(zip(parts, opinions)),
    }


def separate_messages(message):
    """Recognize a comparison of complete quotations, preserving surrounding narrative in ordinary messages."""
    chunks = re.split(r'(?<=["”])(?:\s*/\s*|[ \t]*\n\s*)(?=["“])', message.strip())
    if not 2 <= len(chunks) <= 4 or URL.search(message):
        return []
    parts = []
    for chunk in chunks:
        match = re.fullmatch(r'"([^"“”]+)"|“([^"“”]+)”', chunk)
        if not match:
            return []
        text = (match[1] or match[2]).strip()
        if not text or is_url_only(text):
            return []
        parts.append(text)
    return parts


async def analyze_one(message, *, api_key, model, prompt, logger, on_failure, scan=None, reports=()):
    started = monotonic()
    url_only = is_url_only(message)
    if (scan or url_only) and not (scan and scan.has_html and scan.image):
        logger.info("Assessment skipped reason=incomplete_website_capture")
        return None
    stage = "context" if scan or reports else "message"
    logger.info("Assessment OpenRouter request started stage=%s", stage)
    input_codes = ["observation", "misleading_link"] if url_only else ["observation", *SIGNALS]
    codes = input_codes.copy()
    threat_categories = [c for c in scan.categories if c.casefold() in THREAT_CATEGORIES] if scan else []
    if scan:
        codes.extend(c for c in PAGE_SIGNALS if c != "scan_threat_category" or threat_categories)
    flagged_details = list(dict.fromkeys(report["detail"] for report in reports if report["status"] == "flagged"))
    if flagged_details:
        codes.append("provider_warning")
    message_input = {"review_stage": "message", "input_type": "url" if url_only else "message",
                     "response_language": "English", "allowed_signal_codes": input_codes, "visible_hostnames": visible_hostnames(message),
                     "allowed_risk_actions": list(ADVICE), "message": message}
    user_input = {**message_input, "review_stage": stage, "allowed_signal_codes": codes}
    if stage == "context":
        target = target_urls(message)
        user_input["checked_url"] = target[1] if target else None
        user_input["source_reports"] = reports
    if scan:
        user_input["cloudflare_scan"] = {
            "scope": scan.scope, "date": scan.date, "categories": scan.categories,
            "indicators": scan.indicators, "title": scan.title, "landing_host": scan.landing_host,
            "flagged_malicious": scan.malicious, "page_text": scan.page_text,
        }
    image_sent = bool(scan and scan.image)
    if scan:
        user_input["cloudflare_scan"]["screenshot_attached"] = image_sent
        if scan.live_date:
            user_input["cloudflare_scan"]["live_capture"] = {"date": scan.live_date, "landing_host": scan.live_landing_host}
    text = json.dumps(user_input)
    user_message = {"role": "user", "content": text}
    if image_sent:
        user_message["content"] = [
            {"type": "text", "text": text},
            {"type": "image_url", "image_url": {"url": scan.image}},
        ]
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": prompt}, user_message],
        "max_tokens": 3000 if image_sent else 1500,
        "provider": {"data_collection": "deny", "zdr": True},
    }
    payload["response_format"] = assessment_format(codes, threat_categories, flagged_details, image_sent=image_sent, url_only=url_only)
    brand = None
    timeout = VISUAL_REVIEW_TIMEOUT if image_sent else AI_TIMEOUT
    failure_note = "We couldn’t get a usable answer from the AI. You can run the check again."
    try:
        async with asyncio.timeout(timeout), httpx.AsyncClient(timeout=timeout) as client:
            endpoint = "https://openrouter.ai/api/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}"}
            response = await client.post(endpoint, json=payload, headers=headers)
            if response.status_code in (400, 404, 422) and any(
                term in response.text.lower() for term in ("response_format", "json_schema", "structured output", "requested parameters")
            ):
                # Some vision routes support the image and prompt but not JSON Schema.
                logger.info("Assessment retry reason=structured_output_unsupported")
                del payload["response_format"]
                response = await client.post(endpoint, json=payload, headers=headers)

            def read_opinion(reply, review_scan, review_reports):
                nonlocal brand
                reply.raise_for_status()
                try:
                    choice = reply.json()["choices"][0]
                    content = choice["message"]["content"]
                except (ValueError, KeyError, IndexError, TypeError) as error:
                    raise InvalidReply("invalid_provider_envelope") from error
                if choice.get("finish_reason") == "length":
                    raise InvalidReply("output_truncated")
                if not isinstance(content, str) or not content.strip():
                    raise InvalidReply("missing_content")
                if LOG_AI_RESPONSES:
                    logger.info("AI response content=%s", json.dumps(content))
                content = content.strip()
                fence = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n\s*```", content, re.I | re.S)
                try:
                    raw = json.loads(fence[1] if fence else content)
                except (ValueError, RecursionError) as error:
                    raise InvalidReply("invalid_json") from error
                sent_image = bool(review_scan and review_scan.image)
                if sent_image and isinstance(raw, dict):
                    brand = visual_brand(raw.get("brand_check")) or brand
                try:
                    return validate_opinion(raw, message, review_scan, review_reports, image_sent=sent_image)
                except UnsupportedFindings as error:
                    raise InvalidReply("no_grounded_signals") from error
                except (TypeError, ValueError, KeyError) as error:
                    raise InvalidReply("invalid_assessment_schema") from error

            try:
                observations = read_opinion(response, scan, reports)
            except InvalidReply as error:
                logger.info("Assessment review retry stage=%s detail=%s", stage, error)
                if not url_only:
                    correction = ("\nAssess the submitted wording independently. Identify the requested action, deadline and visible link. "
                                  "Return exactly one JSON object with the required fields and verbatim supporting evidence. "
                                  "Make no claims about a website, redirect destination or reputation report.")
                    payload["messages"][1] = {"role": "user", "content": json.dumps(message_input)}
                    if "response_format" in payload:
                        payload["response_format"] = assessment_format(input_codes, [], [], image_sent=False, url_only=False)
                else:
                    correction = (
                        "\nReassess independently. Return one JSON object. "
                        "Use scan_threat_category only for an exact threat label in categories. "
                        "Verdict tags and phishing indicators belong to observation, source scan_record. "
                        "For a login form visible in the screenshot, cite a short visible cue with source screenshot. "
                        "For wording from the page use code observation, source page_text, "
                        "a descriptive English label, and short verbatim evidence from cloudflare_scan.page_text. "
                        "Use one or two short, contiguous quotes per finding. Never join excerpts with ellipses. "
                        "For each requested action include its matching risk_action. Give an English translation "
                        "of non-English quotes in english_meaning. For a visual cue use source screenshot "
                        "only if pixels are attached. Use only allowed_signal_codes. Omit request_details. "
                        "Choose Unclear if the available material is insufficient."
                    )
                payload["messages"][0] = {"role": "system", "content": prompt + correction}
                retry = await client.post(endpoint, json=payload, headers=headers)
                observations = read_opinion(retry, scan if url_only else None, reports if url_only else ())
                if not url_only and stage == "context":
                    observations["wording_only"] = True
    except httpx.HTTPStatusError as error:
        status = error.response.status_code
        if status == 404:
            # The model can come from a free-text development field.
            model_id = model if re.fullmatch(r"[\w.-]+/[\w.:-]+", model, re.ASCII) and api_key not in model else "(unverified ID)"
            logger.warning(
                "Assessment ai_unavailable stage=%s reason=provider_http_error status=404 "
                "model=%s routing_hint=%s zdr=true data_collection=deny",
                stage, model_id, routing_hint(error.response),
            )
        else:
            logger.warning("Assessment ai_unavailable stage=%s reason=provider_http_error status=%d", stage, status)
    except (TimeoutError, httpx.TimeoutException):
        failure_note = "The review took too long. You can run the check again."
        logger.warning("Assessment ai_unavailable stage=%s reason=provider_timeout", stage)
    except httpx.RequestError:
        failure_note = "We lost the connection to the AI service. You can run the check again."
        logger.warning("Assessment ai_unavailable stage=%s reason=provider_connection_error", stage)
    except InvalidReply as error:
        logger.warning("Assessment ai_unavailable stage=%s reason=invalid_model_response detail=%s", stage, error)
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        logger.warning("Assessment ai_unavailable stage=%s reason=invalid_model_response", stage)
    else:
        logger.info("Assessment ai_completed stage=%s duration_ms=%d signals=%d omitted=%d",
                    stage, (monotonic() - started) * 1000,
                    len(observations["signals"]), observations.get("omitted_signals", 0))
        if brand:
            observations["brand_check"] = brand
        return observations
    if on_failure:
        on_failure(failure_note)
    if brand:
        logger.info("Assessment retained screenshot finding after overall review failed")
        return {"brand_check": brand}
    return None
