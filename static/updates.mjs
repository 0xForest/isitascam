// Allow for the queued scan, artifact downloads and the final model request.
export const CHECK_TIMEOUT_MS = 300_000;
export const DISCLAIMER = "Disclaimer: This assessment is AI-generated and may be inaccurate. Use it as a guide. Before you pay or share personal details, verify the request through the organisation's official app, website or a number you already trust.";

export function checkProgress(result, previous = 0) {
  const pending = result.pending;
  if (!pending.length) return { step: 5, label: result.ai_enabled && !result.ai_reviews?.length ? "The check finished with limited information." : "Check complete." };
  if (pending.some(stage => stage.endsWith("analysis"))) return { step: 4, label: result.brand_check?.status === "checking" ? "Reviewing the screenshot and checking what the page asks you to do…" : "Reviewing the wording and looking for signs of a scam…" };
  if (pending.includes("Cloudflare live capture")) return { step: 3, label: "Taking a fresh screenshot and reading the page…" };
  const html = pending.includes("Cloudflare page text");
  const image = pending.includes("Cloudflare screenshot");
  if (html || image) {
    const needed = html && image ? "page text and screenshot" : html ? "page text" : "screenshot";
    return { step: 3, label: "Retrieving the " + needed + "…" };
  }
  if (pending.includes("Cloudflare scan")) return { step: 2, label: "Waiting for the page capture. Your result will update here automatically." };
  return { step: Math.max(1, previous), label: pending.includes("Cloudflare lookup") ? "Looking for a recent capture of this website…" : "Checking available sources for warnings…" };
}

// Both clients use the same framing for assessment updates.
export async function* readUpdates(response) {
  if (!response.headers.get("content-type")?.includes("application/x-ndjson")) {
    yield { ...await response.json(), pending: [] };
    return;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const update = JSON.parse(buffer.slice(0, newline));
        buffer = buffer.slice(newline + 1);
        yield update;
        if (update.pending.length === 0) return;
      }
      if (done) throw new Error("The connection closed before the check finished.");
    }
  } finally {
    try {
      await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
}


export function brandFinding(brand, { chat = false } = {}) {
  if (!brand?.scope || !brand.date) return "";
  const capture = "the " + brand.scope + " capture from " + brand.date;
  if (brand.status === "no_clear_brand") return "No clear brand was identifiable in " + capture + ".";
  if (brand.status !== "brand_visible" && brand.status !== "possible_impersonation") return "";
  const cue = { logo: "logo", wordmark: "wordmark", branded_form: "branded form" }[brand.cue];
  if (!cue || !brand.name) return "";
  const title = brand.status === "possible_impersonation" ? "Possible impersonation of " : "Visible branding: ";
  // Some brands use a domain as their name. Keep that text inert in a chat client.
  const name = chat ? brand.name.replaceAll(".", "[.]") : brand.name;
  return title + name + ". The AI identified a " + cue + " in " + capture + ". Affiliation is unverified.";
}

const DANGEROUS = "This is dangerous";

function wordingRating(quick) {
  if (quick?.wording_score >= 50) return "Strong warning signs";
  if (quick?.wording_score >= 15) return "Use caution";
  return "";
}

export function wordingSummary(quick) {
  if (!quick?.phrases?.length || (quick.wording_score != null && !wordingRating(quick))) return "";
  return "The wording check matched " + quick.phrases.slice(0, 3).map(phrase => "“" + phrase + "”").join(", ") + ".";
}

export function quickRating(quick) {
  if (quick.flagged_sources.length) return DANGEROUS;
  const wording = wordingRating(quick);
  if (wording) return wording;
  if ((quick.wording_score == null && quick.phrases?.length) || quick.shortened || quick.domain_cautions?.length || quick.site_age_note) return "Use caution";
  return "No quick warnings yet";
}

export function finalRating(result) {
  if (result.quick_check?.flagged_sources?.length) return DANGEROUS;
  if (!result.pending.length && !result.ai_reviews?.length) {
    const wording = wordingRating(result.quick_check);
    if (wording) return wording;
    if (result.ai_enabled && result.input_type === "message" && result.quick_check?.shortened) return "Use caution";
    if (result.capture_failure && result.input_type === "url") return "There isn’t enough evidence to tell";
    if (result.ai_enabled) return "We couldn’t finish this check";
  }
  return verdictLabel(result.verdict);
}

export function verdictLabel(verdict) {
  return ({
    "Looks routine": "This looks routine",
    "Unclear": "There isn’t enough evidence to tell",
    "Suspicious": "This looks suspicious",
    "Likely scam": "This is likely a scam",
  })[verdict] ?? verdict;
}

export function ratingTone(label) {
  switch (label) {
    case "This looks routine": return "routine";
    case "Use caution":
    case "This looks suspicious": return "caution";
    case DANGEROUS:
    case "Strong warning signs":
    case "This is likely a scam": return "danger";
    default: return "neutral";
  }
}

export function assessmentSummary(result) {
  if (result.ai_reviews?.[0]?.part_number) {
    return result.ai_reviews.map(review => `Part ${review.part_number} — ${review.part_summary}`).join("\n");
  }
  const signals = result.ai_reviews?.[0]?.signals ?? [];
  if (!result.ai_reviews?.length && wordingRating(result.quick_check) && !result.quick_check.flagged_sources?.length) {
    return wordingSummary(result.quick_check);
  }
  if (result.quick_check?.flagged_sources?.length) {
    const warning = signals.find(s => s.code === "provider_warning" && s.evidence?.length);
    if (warning) return warning.evidence[0];
  }
  const finding = signals.find(s => s.risk_action) ?? signals.find(s => !["scan_threat_category", "provider_warning"].includes(s.code)) ?? signals[0];
  if (!finding) return result.review_note || "";
  if (finding.code === "provider_warning" && finding.evidence?.length) return finding.evidence[0];
  return finding.description;
}

export function requestRows(details) {
  if (!details || !Object.keys(details).length) return [];
  const labels = { claimed_sender: "Claimed sender", recipient: "Intended recipient", action: "Requested action",
    reason: "Stated reason", method: "What it's asking you to do.", deadline: "Deadline", amount: "Amount", consequence: "Stated consequence" };
  return Object.entries(labels).filter(([key]) => details[key]).map(([key, label]) => [label, details[key]]);
}
