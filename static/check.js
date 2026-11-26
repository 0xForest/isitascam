import { CHECK_TIMEOUT_MS, DISCLAIMER, assessmentSummary, brandFinding, checkProgress, finalRating, quickRating, ratingTone, readUpdates, requestRows, verdictLabel, wordingSummary } from "./updates.mjs";

const form = document.querySelector("#checker");
const message = document.querySelector("#message");
const status = document.querySelector("#status");
const elapsed = document.querySelector("#elapsed");
const disclaimer = document.querySelector("#assessment-disclaimer");
disclaimer.textContent = DISCLAIMER;
const progressBar = document.querySelector("#check-progress");
const result = document.querySelector("#result");
const submit = form.querySelector("[type=submit]");
const scanAnother = document.querySelector("#scan-another");

const exampleButtons = form.querySelectorAll("#sample, #sample-url");

const preview = document.querySelector("#scan-preview");
const scanImage = document.querySelector("#scan-image");
const caption = document.querySelector("#scan-caption");
const visualReview = document.querySelector("#visual-review");
const retryCapture = document.querySelector("#retry-capture");
let lastSubmission;
const visualFinding = document.querySelector("#visual-finding");

function showPreview(scan) {
  const image = scan?.image;
  preview.hidden = !image?.startsWith("data:image/png;base64,");
  scanImage.hidden = preview.hidden;
  scanImage.removeAttribute("src");
  caption.textContent = scan?.caption || "";
  if (!preview.hidden) scanImage.src = image;
}

scanImage.addEventListener("error", () => {
  if (preview.hidden || !scanImage.complete || scanImage.naturalWidth) return;
  showPreview(null);
  showUnavailableScreenshot();
});

const progress = document.querySelector("#progress");
const stages = ["quick", "ai", "brand"];
const idleText = Object.fromEntries(stages.map(name => [name, document.querySelector("#" + name + "-text").textContent]));

function setStage(name, state, text) {
  document.querySelector("#" + name + "-stage").dataset.state = state;
  const description = document.querySelector("#" + name + "-text");
  if (description.textContent !== text) description.textContent = text;
}

function resetCheck() {
  result.hidden = true;
  delete result.dataset.risk;
  for (const element of result.querySelectorAll("#verdict, #assessment-summary, #next-step, #link-list, #detail-list, #ai-reviews, #limitations")) {
    element.replaceChildren();
  }
  for (const section of document.querySelectorAll("#recovery[open], #recovery details[open]")) section.open = false;
  document.querySelector("#recovery-options").replaceChildren();
  showPreview(null);
  scanAnother.hidden = true;
  for (const name of stages) setStage(name, "idle", idleText[name]);
  document.querySelector("#quick-rating").hidden = true;
  document.querySelector("#certificate-credit").hidden = true;
  document.querySelector("#google-advisory").hidden = true;
  status.textContent = "Waiting for a message or link";
  progressBar.hidden = true;
  progressBar.value = 0;
  progressBar.removeAttribute("aria-valuetext");
  retryCapture.hidden = true;
  visualReview.hidden = true;
  visualReview.ariaBusy = "false";
  delete visualReview.dataset.unavailable;
  visualFinding.textContent = "";
}

document.querySelector("#guide-link").addEventListener("click", () => {
  document.querySelector("#how-it-works").open = true;
});

const paidGuidance = document.querySelector("#paid-guidance");
paidGuidance.addEventListener("click", () => {
  document.querySelector("#recovery").open = true;
  document.querySelector("#recovery-bank").open = true;
});

function prepareInput(text) {
  lastSubmission = undefined;
  resetCheck();
  message.value = text;
  message.focus();
}

scanAnother.addEventListener("click", () => prepareInput(""));
document.querySelector("#sample").addEventListener("click", () => {
  prepareInput("Parcel Notice: Pay a redelivery fee within 2 hours. Enter your card details at https://parcel-redelivery.example/confirm.");
});
document.querySelector("#sample-url")?.addEventListener("click", () => {
  prepareInput("https://example.com/");
});

function visibleQuote(span) {
  // Expose invisible direction and control characters within untrusted evidence.
  return span.replace(/[\p{Cc}\p{Cf}]/gu, char => "\\u{" + char.codePointAt(0).toString(16) + "}");
}

function renderReview(review) {
  const group = document.createElement("div");
  if (review.part_number) {
    const heading = document.createElement("h4");
    const label = verdictLabel(review.verdict);
    heading.textContent = "Part " + review.part_number + " · " + label;
    heading.dataset.risk = ratingTone(label);
    group.append(heading);
  }
  if (review.signals.length) {
    const list = document.createElement("ul");
    for (const signal of review.signals) {
      const item = document.createElement("li");
      item.textContent = signal.description;
      if (signal.evidence.length) {
        const quote = document.createElement("div");
        quote.className = "signal-evidence";
        quote.textContent = signal.evidence_source + ": " + signal.evidence.map(span => "“" + visibleQuote(span) + "”").join(" · ");
        item.append(quote);
      }
      if (signal.english_meaning) {
        const translation = document.createElement("div");
        translation.textContent = "AI translation: " + visibleQuote(signal.english_meaning);
        item.append(translation);
      }
      list.append(item);
    }
    group.append(list);
  }
  if (review.note) {
    const note = document.createElement("p");
    note.textContent = review.note;
    group.append(note);
  }
  return group;
}

function showProgress(data) {
  const quick = data.quick_check;
  const rating = document.querySelector("#quick-rating");
  rating.hidden = false;
  rating.textContent = quickRating(quick);
  document.querySelector("#certificate-credit").hidden = !quick.site_age_note;
  document.querySelector("#google-advisory").hidden = !data.google_warning;
  const details = [];
  if (quick.site_age_note) details.push(quick.site_age_note);
  const wording = wordingSummary(quick);
  if (wording) details.push(wording);
  if (quick.shortened) details.push("The shortened link conceals its destination.");
  setStage("quick", ratingTone(rating.textContent), details.join(" "));

  const review = data.ai_reviews[0];
  if (review) {
    const label = verdictLabel(data.verdict);
    setStage("ai", ratingTone(label), label);
  } else if (data.pending.some(stage => ["URL analysis", "Message analysis", "Context analysis"].includes(stage))) {
    setStage("ai", "working", data.input_type === "url" ? "Reviewing the link…" : "Reviewing the message…");
  } else if (data.ai_enabled && data.pending.some(stage => ["Cloudflare scan", "Cloudflare page text", "Cloudflare screenshot", "Cloudflare live capture"].includes(stage))) {
    setStage("ai", "idle", "Waiting for the captured page text and screenshot…");
  } else if (data.ai_enabled && data.pending.length) {
    setStage("ai", "idle", "Gathering evidence…");
  } else {
    setStage("ai", "idle", data.review_note || (data.ai_enabled ? "We couldn’t finish this check." : "AI review is off for this check."));
  }

  showVisualReview(data);
}

function showUnavailableScreenshot() {
  visualReview.dataset.unavailable = "";
  visualReview.ariaBusy = "false";
  visualFinding.textContent = "Screenshot not available for this URL.";
  setStage("brand", "idle", "No screenshot to review.");
}

function showVisualReview(data) {
  const brand = data.brand_check;
  const finding = brandFinding(brand);
  visualReview.hidden = !data.capture_note;
  let explanation = data.capture_note || "No link to review.";
  retryCapture.hidden = !(data.can_retry_capture || data.can_retry_review);
  const waitingForCapture = data.pending.some(stage => ["Cloudflare lookup", "Cloudflare scan", "Cloudflare screenshot", "Cloudflare live capture"].includes(stage));
  if (data.capture_note && preview.hidden && !waitingForCapture) {
    showUnavailableScreenshot();
    return;
  }
  delete visualReview.dataset.unavailable;
  visualReview.ariaBusy = String(progress.dataset.screenshots === "on" &&
    (waitingForCapture || brand?.status === "checking" || brand?.status === "waiting"));
  if (brand?.status === "checking") {
    setStage("brand", "working", "Inspecting the screenshot for visible branding…");
    explanation = "The AI is checking the capture for logos, brand names and signs of impersonation.";
  } else if (brand?.status === "waiting") {
    setStage("brand", "idle", "Screenshot ready. Waiting for the earlier checks.");
    explanation = "The screenshot is ready. Its AI review will begin when the remaining link checks finish.";
  } else if (finding) {
    setStage("brand", brand.status === "possible_impersonation" ? "caution" : "done", "See the screenshot review below.");
    explanation = finding;
  } else if (brand?.status === "unavailable") {
    setStage("brand", "idle", "Visual assessment unavailable.");
    explanation = data.review_note || (data.ai_reviews.length
      ? "The AI review returned no usable brand finding for this screenshot."
      : "We received the screenshot. Run the check again to get a second look.");
  } else if (data.capture_note && progress.dataset.screenshots === "on" && waitingForCapture) {
    setStage("brand", "working", explanation);
  } else if (!data.ai_enabled && !preview.hidden) {
    setStage("brand", "idle", "Screenshot ready. AI review is off.");
    explanation = "AI review is off for this check.";
  } else {
    setStage("brand", "idle", data.capture_note ? "No screenshot to review." : explanation);
  }
  const screenshotFindings = data.ai_reviews.flatMap(review => review.signals)
    .filter(signal => signal.source === "screenshot")
    .map(signal => signal.description + ".");
  if (screenshotFindings.length) explanation = [...screenshotFindings, explanation].join(" ");
  if (visualFinding.textContent !== explanation) visualFinding.textContent = explanation;
}

function showResult(data) {
  if (data.scan_preview) showPreview(data.scan_preview);
  showProgress(data);
  const label = data.pending.length ? quickRating(data.quick_check) : finalRating(data);
  document.querySelector("#verdict").textContent = label;
  document.querySelector("#result-label").textContent = data.pending.length ? "Assessment so far" : "Final assessment";
  const summary = document.querySelector("#assessment-summary");
  summary.textContent = data.pending.length ? "" : assessmentSummary(data);
  summary.hidden = !summary.textContent;
  disclaimer.hidden = !!data.pending.length || !data.ai_reviews.length;
  result.dataset.risk = ratingTone(label);
  const links = data.quick_check.links || [];
  document.querySelector("#extracted-links").hidden = !links.length;
  document.querySelector("#link-list").replaceChildren(...links.map(link => {
    const item = document.createElement("li");
    item.textContent = visibleQuote(link);
    return item;
  }));
  const rows = data.input_type === "url" || data.ai_reviews[0]?.part_number ? [] : requestRows(data.ai_reviews[0]?.request_details);
  document.querySelector("#request-details").hidden = !rows.length;
  document.querySelector("#detail-list").replaceChildren(...rows.flatMap(([label, value]) => {
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = visibleQuote(value);
    return [term, description];
  }));
  const paid = data.already_paid === true;
  document.querySelector("#next-step-title").textContent = paid ? "Since you’ve already paid" : "What to do now";
  document.querySelector("#before-acting").hidden = paid;
  const nextStep = document.querySelector("#next-step");
  nextStep.hidden = paid;
  nextStep.textContent = paid ? "" : data.next_step;
  paidGuidance.hidden = !paid;
  paidGuidance.textContent = paid ? data.next_step : "";
  if (!data.pending.length) {
    document.querySelector("#recovery-options").replaceChildren(...(data.recovery_options || []).map(option => {
      const choice = document.createElement("details");
      const label = document.createElement("summary");
      label.textContent = option.label;
      const advice = document.createElement("p");
      advice.textContent = option.advice;
      choice.append(label, advice);
      return choice;
    }));
  }
  document.querySelector("#limitations").textContent = data.pending.length ? "" : data.scope_note;
  const reviews = data.ai_reviews;
  document.querySelector("#ai-reviews").replaceChildren(...reviews.map(renderReview));
  document.querySelector("#ai-findings").hidden = reviews.length === 0;
  result.hidden = false;
}

async function runCheck(body) {
  if (submit.disabled) return;
  resetCheck();
  submit.disabled = true;
  for (const button of exampleButtons) button.disabled = true;
  status.textContent = "Starting check…";
  progressBar.hidden = false;
  progress.dataset.running = "true";
  const started = performance.now();
  const ticker = setInterval(() => {
    const seconds = Math.floor((performance.now() - started) / 1000);
    elapsed.hidden = false;
    elapsed.textContent = "Still working · " + seconds + "s elapsed";
  }, 1000);
  progressBar.setAttribute("aria-valuetext", status.textContent);
  progress.focus();
  try {
    const response = await fetch("/assess", {
      method: "POST",
      headers: {"Content-Type": "text/plain; charset=utf-8", "X-Assessment-View": "web", Accept: "application/x-ndjson"},
      body,
      signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error((await response.json()).detail);
    for await (const update of readUpdates(response)) {
      showResult(update);
      const { step, label } = checkProgress(update, progressBar.value);
      progressBar.value = step;
      progressBar.setAttribute("aria-valuetext", label);
      if (status.textContent !== label) status.textContent = label;
    }
  } catch (error) {
    progressBar.hidden = true;
    if (!visualReview.hidden && visualReview.ariaBusy === "true") {
      retryCapture.hidden = false;
      visualReview.ariaBusy = "false";
      if (preview.hidden) showUnavailableScreenshot();
      else visualFinding.textContent = "The screenshot review was interrupted.";
    }
    for (const name of stages) {
      const stage = document.querySelector("#" + name + "-stage");
      if (stage.dataset.state === "working" || stage.dataset.state === "idle") {
        setStage(name, "idle", "No further result available.");
      }
    }
    status.textContent = error instanceof SyntaxError || error instanceof TypeError || error.name === "TimeoutError"
      ? "The check could not finish. Try again shortly."
      : error.message;
  } finally {
    clearInterval(ticker);
    delete progress.dataset.running;
    elapsed.hidden = true;
    submit.disabled = false;
    scanAnother.hidden = false;
    for (const button of exampleButtons) button.disabled = false;
  }
}

form.addEventListener("submit", event => {
  event.preventDefault();
  if (submit.disabled) return;
  lastSubmission = message.value;
  runCheck(lastSubmission);
});

retryCapture.addEventListener("click", () => {
  if (lastSubmission) runCheck(lastSubmission);
});
