import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assessmentSummary, finalRating, quickRating, ratingTone } from "../static/updates.mjs";
import { assessText, incoming, messageHandler } from "../whatsapp/messages.js";

const MENU = "🛟 *Already clicked or paid?*\nWhat happened? Reply with the matching word."
  + "\n*LINK* — I opened the link\n*CODE* — I shared a password or code\n*BANK* — I shared card details or paid"
  + "\n*COMMAND* — I ran a command from a message or website";

test("ratings retain a written verdict and multipart summaries retain both assessments", () => {
  for (const [verdict, tone] of [["Looks routine", "routine"], ["Unclear", "neutral"], ["Suspicious", "caution"], ["Likely scam", "danger"]]) {
    assert.equal(ratingTone(finalRating({ verdict, ai_reviews: [{}], pending: [] })), tone);
  }
  assert.equal(ratingTone(finalRating({ ai_enabled: true, pending: [] })), "neutral");
  assert.equal(ratingTone(finalRating({ verdict: "Looks routine", ai_reviews: [{}], quick_check: {flagged_sources: ["DNS"]}, pending: [] })), "danger");
  const reviews = [{ part_number: 1, part_summary: "Keep the code private." }, { part_number: 2, part_summary: "Hang up if asked." }];
  assert.equal(assessmentSummary({ ai_reviews: reviews }), "Part 1 — Keep the code private.\nPart 2 — Hang up if asked.");
});

test("weighted wording sets the first impression and explains a local-only result", async t => {
  for (const [score, expected] of [[0, "No quick warnings yet"], [14, "No quick warnings yet"],
                                   [15, "Use caution"], [49, "Use caution"], [50, "Strong warning signs"]]) {
    assert.equal(quickRating({ wording_score: score, phrases: ["payment"], flagged_sources: [] }), expected);
  }
  const quick_check = { wording_score: 60, phrases: ["pay the recruitment fee"], flagged_sources: [] };
  const result = { verdict: "Unclear", ai_enabled: false, ai_reviews: [], quick_check };
  t.mock.method(globalThis, "fetch", async () => Response.json(result));
  const [reply] = await Array.fromAsync(assessText("Pay the recruitment fee"));
  assert.equal(reply.text, "🔴 Strong warning signs\n\nThe wording check matched “pay the recruitment fee”.\n\n" + MENU);
  assert.equal(finalRating({ ...result, pending: [], ai_reviews: [{}], verdict: "Looks routine" }), "This looks routine");
  quick_check.flagged_sources.push("Cloudflare DNS");
  assert.equal(quickRating(quick_check), "This is dangerous");
  assert.equal(finalRating({ ...result, pending: [] }), "This is dangerous");
});

test("direct messages, history filtering, tester routing and restart deduplication", async t => {
  const dir = await mkdtemp(join(tmpdir(), "wa-test-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const receiptFile = join(dir, "receipts.json");
  const chat = "1234567@s.whatsapp.net";
  const calls = [];
  const replies = [];
  const options = {
    receiptFile,
    allowedNumbers: new Set(["1234567"]),
    lookupPhone: async () => chat,
    assess: async function* (text) { calls.push(text); yield { text: "Assessment result" }; },
    send: async (jid, content) => replies.push([jid, content.text]),
  };
  const event = { key: { id: "first", remoteJid: chat }, message: {
    extendedTextMessage: { text: "Private test of a forwarded payment request", contextInfo: { isForwarded: true } },
  }};
  const handle = await messageHandler(options);
  const send = (messages, type = "notify") => handle({ type, messages });
  await send([event], "append");
  await send([event, event, { ...event, key: { ...event.key, fromMe: true, id: "out" } },
    { ...event, key: { remoteJid: "123@g.us", id: "group" } },
    { ...event, key: { remoteJid: "7654321@s.whatsapp.net", id: "unknown" } }]);
  await (await messageHandler(options))({ type: "notify", messages: [event] });
  await send([{ ...event, key: { remoteJid: "123@lid", id: "second" }, message: { imageMessage: {} } }]);
  assert.deepEqual(calls, ["Private test of a forwarded payment request"]);
  assert.match(replies[0][1], /got it/);
  assert.deepEqual(replies[1], [chat, "Assessment result"]);
  assert.equal(replies.length, 3);
  assert.equal(replies[2][0], "123@lid");
  assert.match(replies[2][1], /paste the wording/);
  const disk = await readFile(receiptFile, "utf8");
  assert.doesNotMatch(disk, /Private test of a forwarded payment request|s.whatsapp.net|@lid|first/);
});

test("WhatsApp formats a final JSON reply", async t => {
  const first = "The message requests a fee. From the message: “Pay a redelivery fee”";
  const second = "The message uses a deadline. From the message: “within two hours”";
  t.mock.method(globalThis, "fetch", async () => Response.json({
    verdict: "Suspicious", next_step: "Check the courier app.",
    reasons: [first, second], limitations: "Sender unverified.",
  }));
  const replies = await Array.fromAsync(assessText("Test"));
  assert.equal(replies[0].text, "🟡 This looks suspicious\n\n" + MENU);
});

test("a recent domain adds context to the verdict and first impression", async t => {
  const note = "This site’s domain was registered on 20 Nov 2026. It may be too new to have much of a track record.";
  const quick_check = { phrases: [], flagged_sources: [], site_age_note: note };
  assert.equal(quickRating(quick_check), "Use caution");
  t.mock.method(globalThis, "fetch", async () => Response.json({ verdict: "Unclear", quick_check }));
  const [reply] = await Array.fromAsync(assessText("example.org"));
  assert.equal(reply.text, "There isn’t enough evidence to tell\n\n" + note + "\n\n" + MENU);
});

test("split UTF-8 progress frames update the original WhatsApp receipt and skip duplicate edits", async t => {
  const dir = await mkdtemp(join(tmpdir(), "wa-progress-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const receiptFile = join(dir, "receipts.json");
  const progress = { verdict: "Suspicious", reasons: ["A suspicious link"], next_step: "Verify first", limitations: "Local check", pending: ["Cloudflare scan"] };
  const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j+U8AAAAASUVORK5CYII=", "base64");
  const preview = { image: "data:image/png;base64," + png.toString("base64"), caption: "Cloudflare captured the site homepage on 2026-11-23." };
  const scanned = { ...progress, scan_preview: preview, pending: ["Context analysis"] };
  const final = { ...progress, ai_reviews: [{ signals: [{ description: "An unexpected €50 fee" }] }], pending: [] };
  const bytes = new TextEncoder().encode([progress, progress, scanned, final].map(update => JSON.stringify(update) + "\n").join(""));
  const split = bytes.indexOf(0xe2) + 1;
  t.mock.method(globalThis, "fetch", async (_url, options) => {
    assert.equal(options.body, "  https://example.com  ");
    assert.equal(options.headers["X-Scan-Preview"], "1");
    assert.equal(options.headers["X-WhatsApp-Number"], "1234567");
    assert.equal(options.headers["X-Bridge-Token"], process.env.CHECK_BRIDGE_TOKEN || "");
    assert.equal(options.headers["X-Assessment-View"], undefined);
    return new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.slice(0, split));
        controller.enqueue(bytes.slice(split));
        controller.close();
      },
    }), { headers: { "content-type": "application/x-ndjson" } });
  });
  const key = { id: "bot-message" };
  const replies = [];
  const options = {
    receiptFile, allowedNumbers: new Set(), assess: assessText,
    send: async (_chat, content) => {
      assert.equal(JSON.parse(await readFile(receiptFile)).length, 1);
      replies.push(content);
      return key;
    },
  };
  const event = { type: "notify", messages: [{ key: { id: "incoming", remoteJid: "1234567@s.whatsapp.net" },
    message: { conversation: "  https://example.com  " } }] };
  await (await messageHandler(options))(event);
  await (await messageHandler(options))(event);
  assert.equal(replies.length, 5);
  assert.match(replies[0].text, /got it/);
  assert.match(replies[0].text, /▱▱▱▱▱/);
  assert.match(replies[1].text, /▰▰▱▱▱  Waiting for the page capture/);
  assert.equal(replies[1].edit, key);
  assert.match(replies[2].text, /▰▰▰▰▱  Reviewing/);
  assert.equal(replies[2].edit, key);
  assert.deepEqual(replies[3], { text: "🟡 This looks suspicious\n\n*AI signals*\n• An unexpected €50 fee", edit: key });
  assert.deepEqual(replies[4], { image: png, mimetype: "image/png", caption: MENU });
});

function directMessage(id, text) {
  return { key: { id, remoteJid: "1234567@s.whatsapp.net" }, message: { conversation: text } };
}

test("a short payment report reaches the checker and directs the user to the recovery menu", async t => {
  const input = incoming(directMessage("1", "I already paid"));
  assert.equal(input.text, "I already paid");
  const next_step = "Before sending any more money, please follow the steps in Already clicked or paid?";
  t.mock.method(globalThis, "fetch", async () => Response.json({
    verdict: "Suspicious", already_paid: true, next_step, ai_reviews: [{ signals: [] }],
  }));
  const [reply] = await Array.fromAsync(assessText(input.text));
  assert.equal(reply.text, "🟡 This looks suspicious\n\n*Since you’ve already paid*\n" + next_step + "\n\n" + MENU);
});

test("rescue replies deliver the selected guidance without starting a check", async t => {
  const dir = await mkdtemp(join(tmpdir(), "wa-rescue-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const replies = [];
  const handle = await messageHandler({
    receiptFile: join(dir, "receipts.json"), allowedNumbers: new Set(),
    assess: () => assert.fail("Rescue choices must not start a scan"),
    send: async (_chat, content) => replies.push(content.text),
  });
  for (const [word, expected] of [
    ["rescue", /\*COMMAND\* — I ran a command/], [" Link ", /leave it unopened/],
    ["CODE", /banking code, call your bank now/], ["I shared card details or paid", /stop or reverse it/],
    ["ACCESS", /disconnect the device/],
    ["command", /Disconnect that device from the internet now/], ["I ran the commands", /call your IT team/],
    ["ClickFix", /sign out all other sessions/],
  ]) {
    await handle({ type: "notify", messages: [directMessage(word, word)] });
    assert.match(replies.at(-1), expected);
    assert.doesNotMatch(replies.at(-1), /Disclaimer:/);
  }
});

test("sender numbers come from the direct chat, alternate address or linked-ID mapping", async t => {
  const dir = await mkdtemp(join(tmpdir(), "wa-sender-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const numbers = [];
  const handle = await messageHandler({
    receiptFile: join(dir, "receipts.json"), allowedNumbers: new Set(),
    lookupPhone: async jid => {
      if (jid === "111@lid") return "15550100002@s.whatsapp.net";
      throw new Error("Mapping unavailable");
    },
    assess: async function* (_text, number) { numbers.push(number); yield { text: "Done" }; },
    send: async () => ({ id: "reply" }),
  });
  for (const [remoteJid, remoteJidAlt] of [
    ["15550100001:5@s.whatsapp.net"], ["111@lid"], ["222@lid", "15550100003@s.whatsapp.net"], ["333@lid"],
  ]) {
    const event = directMessage("id", "Forwarded message from +15550109999");
    Object.assign(event.key, { remoteJid, remoteJidAlt });
    await handle({ type: "notify", messages: [event] });
  }
  assert.deepEqual(numbers, ["15550100001", "15550100002", "15550100003", undefined]);
});

test("greetings and short messages get instructions; short links and longer messages get checked", () => {
  for (const text of ["hi", " Hello! ", "help", "👋", "Can you help?", "a".repeat(23)]) {
    const message = incoming(directMessage("test", text));
    assert.match(message.instruction, /Forward the message/);
    assert.match(message.instruction, /send the link/);
    assert.equal(message.text, "");
  }
  for (const text of ["https://t.co/a", "www.example.com", " t.co/a ", "see x.co/x", "a".repeat(24)]) {
    const message = incoming(directMessage("test", text));
    assert.equal(message.instruction, undefined);
    assert.equal(message.text, text);
  }
});

test("greet and acknowledge queued checks while the first assessment is still running", { timeout: 3000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), "wa-queue-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const started = Promise.withResolvers();
  const finish = Promise.withResolvers();
  const secondAck = Promise.withResolvers();
  const events = [];
  const handle = await messageHandler({
    receiptFile: join(dir, "receipts.json"), allowedNumbers: new Set(),
    assess: async function* (text) {
      events.push(text);
      if (text === "first.com") {
        started.resolve();
        await finish.promise;
      }
      yield { text: "Result" };
    },
    send: async (_chat, { text }) => {
      events.push(text);
      if (events.filter(item => item.includes("got it")).length === 2) secondAck.resolve();
      return { id: "bot" };
    },
  });
  const check = (id, text) => handle({ type: "notify", messages: [directMessage(id, text)] });
  const first = check("1", "first.com");
  await started.promise;
  assert.match(events[0], /got it/);
  await check("2", "Hello!");
  assert.match(events.at(-1), /Forward the message/);
  const second = check("3", "second.com");
  try {
    await secondAck.promise;
    assert.ok(!events.includes("second.com"));
    assert.ok(!events.includes("Result"));
  } finally {
    finish.resolve();
  }
  await Promise.all([first, second]);
  assert.equal(events.filter(item => item === "Result").length, 2);
  assert.ok(!events.includes("Hello!"));
});

test("a failed screenshot upload keeps the text assessment and its final update", async t => {
  const dir = await mkdtemp(join(tmpdir(), "wa-upload-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const replies = [];
  const handle = await messageHandler({
    receiptFile: join(dir, "receipts.json"), allowedNumbers: new Set(),
    assess: async function* () {
      yield { text: "Final finding", screenshot: { image: Buffer.alloc(1), caption: MENU } };
    },
    send: async (_chat, content) => {
      if (content.image) throw new Error("Test upload failure");
      replies.push(content);
      return { id: "result" };
    },
  });
  await handle({ type: "notify", messages: [directMessage("1", "example.com")] });
  assert.deepEqual(replies[1], { text: "Final finding", edit: { id: "result" } });
  assert.equal(replies.at(-1).text, "I couldn’t attach the screenshot for this check.\n\n" + MENU);
});

test("WhatsApp lists distinct AI signals with their evidence and translations", async t => {
  const warning = "Cloudflare’s security DNS blocks the first eligible hostname as a threat.";
  const providerSignal = { code: "provider_warning", description: "A source reported a threat.", evidence: [warning] };
  const result = {
    verdict: "Likely scam", ai_enabled: true, next_step: "Verify first", recovery_steps: ["Contact your bank"],
    reasons: ["Legacy summary"], direct_findings: [warning, "Another provider found no match."],
    recovery_options: [{ reply: "CHAT" }],
    limitations: "The sender is unverified.", google_warning: "An unrelated Google warning.",
    brand_check: { status: "brand_visible", name: "Shop" },
    ai_reviews: [{ title: "URL with source reports", note: "Some signals omitted.", request_details: { action: "Pay" },
      signals: [providerSignal, providerSignal, { description: "Private payment before delivery",
        evidence: ["Pagamento in chat"], english_meaning: "Payment in chat." }] }],
  };
  t.mock.method(globalThis, "fetch", async () => Response.json(result));
  const [reply] = await Array.fromAsync(assessText("example.com"));
  assert.equal(reply.text, "🔴 This is likely a scam\n\n*AI signals*\n• A source reported a threat.\nSource report: “" + warning +
    "”\n• Private payment before delivery\nEvidence: “Pagamento in chat”\nAI translation: Payment in chat.\n\n" + MENU + "\n*CHAT* — I replied to the sender");
});

test("courier check includes all three signals and the screenshot interpretation", async t => {
  const registration = "This site’s domain was registered on 25 Nov 2026. It may be too new to have much of a track record.";
  const rows = [
    ["The message asks for sensitive personal details.", "Submitted text", "Please verify your delivery address."],
    ["Cloudflare assigned a threat-related category to the scanned site.", "Domain category", "Phishing"],
    ["A source reported a threat relevant to this link.", "Source report", "Cloudflare flagged the linked page as malicious at scan time."],
  ];
  const result = {
    verdict: "Likely scam", quick_check: { flagged_sources: ["Cloudflare URL Scanner"], site_age_note: registration },
    ai_reviews: [{ signals: rows.map(([description, evidence_source, quote]) => ({ description, evidence_source, evidence: [quote] })) }],
    brand_check: { status: "brand_visible", name: "Example Courier", cue: "wordmark", scope: "linked page", date: "2026-11-26" },
    scan_preview: { image: "data:image/png;base64,aW1hZ2U=" },
  };
  t.mock.method(globalThis, "fetch", async () => Response.json(result));
  const [reply] = await Array.fromAsync(assessText("Please verify your delivery address."));
  const findings = rows.map(([description, source, quote]) => "• " + description + "\n" + source + ": “" + quote + "”").join("\n");
  assert.equal(reply.text, "🔴 This is dangerous\n\n*AI signals*\n" + findings +
    "\n\n*What the AI sees*\nVisible branding: Example Courier. The AI identified a wordmark in the linked page capture from 2026-11-26. Affiliation is unverified.\n\n" + registration);
  assert.equal(reply.screenshot.caption, MENU);
});

test("a Google warning selected as an AI signal retains its attribution", async t => {
  const warning = "Google Safe Browsing warns that this link may expose you to malware.";
  t.mock.method(globalThis, "fetch", async () => Response.json({
    verdict: "Suspicious", google_warning: warning, direct_findings: [warning],
    ai_reviews: [{ signals: [{ code: "provider_warning", description: "Provider warning", evidence: [warning] }] }],
  }));
  const [reply] = await Array.fromAsync(assessText("example.com"));
  assert.equal(reply.text, "🟡 This looks suspicious\n\n*AI signals*\n• Provider warning\nSource report: “" + warning +
    "”\nAdvisory provided by Google: https://developers.google.com/safe-browsing/v4/advisory\n\n" + MENU);
});

test("incomplete reviews show their limitation and preserve an independent link warning", async t => {
  const result = { ai_enabled: true, verdict: "Unclear", ai_reviews: [],
    review_note: "The scan did not supply the page HTML.", quick_check: { flagged_sources: [] },
    direct_findings: ["Scanner observation"], scan_preview: { image: null, caption: "Screenshot unavailable." } };
  t.mock.method(globalThis, "fetch", async () => Response.json(result));
  const [unavailable] = await Array.fromAsync(assessText("example.com"));
  assert.equal(unavailable.text, "We couldn’t finish this check\n\n" + result.review_note + "\n\n" + MENU);
  assert.equal(unavailable.screenshot, undefined);
  result.input_type = "url";
  result.capture_failure = "connection_reset";
  result.review_note = "The connection closed while Cloudflare was loading the linked page. There’s no screenshot from this scan.";
  const [reset] = await Array.fromAsync(assessText("example.com"));
  assert.equal(reset.text, "There isn’t enough evidence to tell\n\n" + result.review_note + "\n\n" + MENU);
  result.quick_check.flagged_sources = ["Cloudflare DNS"];
  const [flagged] = await Array.fromAsync(assessText("example.com"));
  assert.equal(flagged.text, "🔴 This is dangerous\n\n" + result.review_note + "\n\n" + MENU);
  delete result.review_note;
  result.ai_reviews = [{ signals: [], note: "Too little evidence." }];
  const [reviewed] = await Array.fromAsync(assessText("example.com"));
  assert.equal(reviewed.text, "🔴 This is dangerous\n\n" + MENU);
});

test("a VirusTotal flag stays dangerous after a suspicious AI verdict", async t => {
  const warning = "In VirusTotal’s last report, 2 engines marked this URL malicious and 1 marked it suspicious.";
  const quick_check = { flagged_sources: ["VirusTotal"], phrases: [] };
  assert.equal(quickRating(quick_check), "This is dangerous");
  const signals = [{ code: "provider_warning", evidence: [warning] },
    { code: "observation", description: "Page shows a verification screen" }];
  t.mock.method(globalThis, "fetch", async () => Response.json({
    verdict: "Suspicious", quick_check, ai_reviews: [{ verdict: "Suspicious", signals }],
  }));
  const [reply] = await Array.fromAsync(assessText("example.com"));
  assert.equal(reply.text, "🔴 This is dangerous\n\n*AI signals*\n• Source report: “" + warning +
    "”\n• Page shows a verification screen\n\n" + MENU);
});

test("a shortened link still gives a useful caution when the model replies are unusable", async t => {
  const note = "The shortened link hides its destination. Verify the request independently.";
  const result = { input_type: "message", ai_enabled: true, verdict: "Unclear", ai_reviews: [],
    quick_check: { shortened: true, flagged_sources: [] }, review_note: note };
  t.mock.method(globalThis, "fetch", async () => Response.json(result));
  const [reply] = await Array.fromAsync(assessText("MUNICIPAL FINES: View details: https://in.run/example-fixture"));
  assert.equal(reply.text, "🟡 Use caution\n\n" + note + "\n\n" + MENU);
});

test("an interrupted stream ends with a short failure message", async t => {
  const frame = { pending: ["Cloudflare scan"], verdict: "Unclear", direct_findings: ["Incomplete report"] };
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify(frame) + "\n", {
    headers: { "content-type": "application/x-ndjson" },
  }));
  const [progress, failed] = await Array.fromAsync(assessText("example.com"));
  assert.equal(progress.text, "▰▰▱▱▱  Waiting for the page capture. Your result will update here automatically.");
  assert.equal(failed.text, "I couldn’t complete this check. Please try sending the message again.\n\n" + MENU);
});
