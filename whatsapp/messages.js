import { CHECK_TIMEOUT_MS, assessmentSummary, brandFinding, checkProgress, finalRating, ratingTone, readUpdates } from "../static/updates.mjs";
import recoveryChoices from "../static/recovery.json" with { type: "json" };
import { createHash } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import { getContentType, isLidUser, isPnUser, jidDecode, normalizeMessageContent } from "@whiskeysockets/baileys";

const MEDIA = new Set(["imageMessage", "videoMessage", "audioMessage", "documentMessage", "stickerMessage"]);
const MAX_MESSAGE_BYTES = 12_000;
const MIN_CHECK_LENGTH = 24;
const SHORT_PAYMENT_REPORT = /^(?:i\b|we\b|already\b).*\b(?:paid|payment|sent|wired|transferred|deposited)\b/i;
const LINK = /\b(?:https?:\/\/|www\.)[^\s<>"']+|(?:^|\s)(?:[a-z0-9-]+\.)+[a-z]{2,63}(?=$|[\s/:?#.,!)])/i;
const HELP = "Hi! Forward the message you’re unsure about, paste its wording here, or send the link on its own. I’ll send the verdict and signs of a scam I find. Already clicked or paid? Send RESCUE for help. Checks log your WhatsApp number when available. Please leave out passwords, security codes and card numbers."
  + (process.env.REPUTATION_HOST_PROVIDERS ? " Hostname checks use " + process.env.REPUTATION_HOST_PROVIDERS + "." : "")
  + (process.env.REPUTATION_URL_PROVIDERS ? " The first eligible URL, including its path and query, goes to " + process.env.REPUTATION_URL_PROVIDERS + "." : "")
  + (process.env.REPUTATION_SCAN_NOTICE ? " " + process.env.REPUTATION_SCAN_NOTICE : "");
function progressLine(step, label) {
  return "▰".repeat(step) + "▱".repeat(5 - step) + "  " + label;
}
const RECEIVED = "Thanks, I’ve got it. While you wait, leave any links unopened.\n\n" + progressLine(0, "Queued for checking.");
const PNG_PREFIX = "data:image/png;base64,";

function rescueMenu(options = []) {
  const choices = recoveryChoices.filter(choice => !choice.action || options.some(option => option.reply === choice.reply));
  return ["🛟 *Already clicked or paid?*", "What happened? Reply with the matching word.",
    ...choices.map(choice => `*${choice.reply}* — ${choice.label}`)].join("\n");
}

export function log(message) {
  process.stdout.write(`${new Date().toISOString()} ${message}\n`);
}

export function incoming(event) {
  const key = event.key;
  const chat = key?.remoteJid;
  if (!key?.id || key.fromMe || !(isPnUser(chat) || isLidUser(chat))) return;
  const content = normalizeMessageContent(event.message);
  if (!content) return;
  const type = getContentType(content);
  const text = content.conversation ?? content.extendedTextMessage?.text ?? "";
  let instruction;
  if (text && Buffer.byteLength(text) > MAX_MESSAGE_BYTES) {
    instruction = "That message is too long to check. Please send a shorter excerpt.";
  } else if (!text.trim()) {
    if (!MEDIA.has(type)) return;
    instruction = "I can check text and links. Please paste the wording from that attachment or send the link it contains.";
  } else {
    const reply = text.trim().toUpperCase();
    const choice = recoveryChoices.find(choice => choice.reply === reply || choice.label.toUpperCase() === reply
      || choice.aliases?.some(alias => alias.toUpperCase() === reply));
    if (choice) instruction = [`*${choice.label}*`, ...choice.paragraphs].join("\n\n");
    else if (reply === "RESCUE") instruction = rescueMenu();
    else if ([...text.trim()].length < MIN_CHECK_LENGTH && !LINK.test(text) && !SHORT_PAYMENT_REPORT.test(text.trim())) instruction = HELP;
  }
  const id = createHash("sha256").update(chat + "\0" + key.id).digest("hex");
  return { id, chat, phoneJid: [chat, key.remoteJidAlt].find(isPnUser), text: instruction ? "" : text, instruction };
}

function reviewText(result) {
  const reviews = result.ai_reviews || [];
  if (!reviews.some(review => review.signals?.length)) return assessmentSummary(result);

  const sections = ["*AI signals*"];
  let googleAttributed = false;
  for (const review of reviews) {
    const bullets = new Set();
    for (const signal of review.signals || []) {
      const lines = [signal.description];
      const evidence = signal.evidence || [];
      if (evidence.length) {
        const source = signal.evidence_source || (signal.code === "provider_warning" ? "Source report" : "Evidence");
        lines.push(source + ": " + evidence.map(quote => "“" + quote + "”").join(" · "));
        if (result.google_warning && evidence.includes(result.google_warning)) googleAttributed = true;
      }
      if (signal.english_meaning) lines.push("AI translation: " + signal.english_meaning);
      const text = lines.filter(Boolean).join("\n");
      if (text) bullets.add("• " + text);
    }
    const body = [...bullets].join("\n") || review.part_summary;
    if (body) sections.push(review.part_number ? "*Part " + review.part_number + "*\n" + body : body);
  }
  if (googleAttributed) sections.push("Advisory provided by Google: https://developers.google.com/safe-browsing/v4/advisory");
  return sections.join("\n");
}

function finalAssessment(result) {
  const finding = brandFinding(result.brand_check, { chat: true });
  const label = finalRating(result);
  const indicator = { routine: "🟢 ", caution: "🟡 ", danger: "🔴 " }[ratingTone(label)] || "";
  const scope = result.ai_reviews?.[0]?.wording_only && result.scope_note;
  return [indicator + label, reviewText(result), finding && "*What the AI sees*\n" + finding,
    scope, result.quick_check?.site_age_note, result.already_paid && "*Since you’ve already paid*\n" + result.next_step
  ].filter(Boolean).join("\n\n");
}

function finalReply(text, screenshot, options) {
  const menu = rescueMenu(options);
  if (screenshot) return { text, screenshot: { ...screenshot, caption: menu } };
  return { text: text + "\n\n" + menu };
}

export async function* assessText(text, senderNumber) {
  const origin = "http://127.0.0.1:8000";
  let screenshot;
  let step = 0;
  let lastProgress;
  try {
    const response = await fetch(origin + "/assess", {
      method: "POST",
      headers: {
        Origin: origin, Accept: "application/x-ndjson", "Content-Type": "text/plain; charset=utf-8",
        "X-Scan-Preview": "1", "X-Bridge-Token": process.env.CHECK_BRIDGE_TOKEN || "",
        "X-WhatsApp-Number": senderNumber || "",
      },
      body: text,
      signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
      redirect: "error",
    });
    if (!response.ok) throw new Error("Assessment unavailable");
    for await (const result of readUpdates(response)) {
      const preview = result.scan_preview;
      if (!screenshot && preview?.image?.startsWith(PNG_PREFIX)) {
        screenshot = { image: Buffer.from(preview.image.slice(PNG_PREFIX.length), "base64"),
          mimetype: "image/png" };
      }
      if (!result.pending.length) {
        yield finalReply(finalAssessment(result), screenshot, result.recovery_options);
        return;
      }
      const phase = checkProgress(result, step);
      step = phase.step;
      const progress = progressLine(step, phase.label);
      if (progress !== lastProgress) {
        lastProgress = progress;
        yield { text: progress };
      }
    }
  } catch {
    yield finalReply("I couldn’t complete this check. Please try sending the message again.", screenshot);
  }
}

// The intake queue owns the receipt file. Slow assessments run on a separate queue.
export async function messageHandler({ receiptFile, assess, send, allowedNumbers, lookupPhone }) {
  let receipts;
  try {
    receipts = new Map(JSON.parse(await readFile(receiptFile, "utf8")));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    receipts = new Map();
  }
  const pending = new Set();
  let intake = Promise.resolve();
  let checks = Promise.resolve();

  async function senderNumber(message) {
    let jid = message.phoneJid;
    if (!jid) {
      try {
        jid = await lookupPhone(message.chat);
      } catch {
        return;
      }
    }
    const number = isPnUser(jid) && jidDecode(jid)?.user;
    if (/^[1-9][0-9]{6,14}$/.test(number)) return number;
  }

  async function acknowledge(message) {
    if (allowedNumbers.size) {
      message.number = await senderNumber(message);
      if (!allowedNumbers.has(message.number)) return;
    }
    // Record before sending. A crash during delivery may lose a reply.
    const now = Date.now();
    for (const [id, time] of receipts) {
      if (now - time >= 86_400_000 || receipts.size >= 4096) receipts.delete(id);
      else break;
    }
    receipts.set(message.id, now);
    await writeFile(receiptFile + ".tmp", JSON.stringify([...receipts]), { mode: 0o600 });
    await rename(receiptFile + ".tmp", receiptFile);
    const key = await send(message.chat, { text: message.instruction || RECEIVED });
    if (!message.instruction) return { key };
  }

  async function deliver(message, key) {
    let missedEdit;
    let screenshotSent = false;
    const number = message.number ?? await senderNumber(message);
    for await (const { text, screenshot } of assess(message.text, number)) {
      if (!key) {
        key = await send(message.chat, { text });
      } else {
        try {
          await send(message.chat, { text, edit: key });
          missedEdit = undefined;
        } catch {
          missedEdit = text;
        }
      }
      if (screenshot && !screenshotSent) {
        if (missedEdit) {
          await send(message.chat, { text: missedEdit });
          missedEdit = undefined;
        }
        screenshotSent = true;
        try {
          await send(message.chat, screenshot);
        } catch {
          log("WhatsApp screenshot could not be delivered.");
          const fallback = ["I couldn’t attach the screenshot for this check.", screenshot.caption].filter(Boolean).join("\n\n");
          await send(message.chat, { text: fallback }).catch(reportFailure);
        }
      }
    }
    if (missedEdit) await send(message.chat, { text: missedEdit });
  }

  function reportFailure() {
    log("WhatsApp reply could not be delivered.");
  }

  return function handle({ type, messages }) {
    if (type !== "notify") return;
    const deliveries = [];
    for (const event of messages) {
      const message = incoming(event);
      if (!message || receipts.has(message.id) || pending.has(message.id)) continue;
      if (pending.size >= 32) {
        log("WhatsApp queue full. Skipping incoming message.");
        continue;
      }
      pending.add(message.id);
      intake = intake.then(() => acknowledge(message)).catch(reportFailure);
      const delivery = intake.then(ready => {
        if (ready) {
          checks = checks.then(() => deliver(message, ready.key)).catch(reportFailure);
          return checks;
        }
      });
      deliveries.push(delivery.finally(() => pending.delete(message.id)));
    }
    return Promise.all(deliveries);
  };
}
