import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import makeWASocket, { DisconnectReason, useMultiFileAuthState } from "@whiskeysockets/baileys";
import pino from "pino";
import qr from "qrcode-terminal";
import { assessText, log, messageHandler } from "./messages.js";

// libsignal emits session objects through console even with the Baileys logger disabled.
for (const method of ["log", "info", "warn", "error", "debug", "trace"]) {
  console[method] = () => {};
}
process.umask(0o077);
const sessionDir = "/session";
const qrFile = "/tmp/pairing-qr";
const allowedNumbers = new Set();
for (const entry of (process.env.WHATSAPP_TESTERS || "").split(",")) {
  const number = entry.trim().replace(/^\+/, "");
  if (!entry.trim()) continue;
  if (!/^\d{7,15}$/.test(number)) throw new Error("WHATSAPP_TESTERS must contain international phone numbers.");
  allowedNumbers.add(number);
}

async function run() {
  mkdirSync(sessionDir, { recursive: true });
  const { state, saveCreds } = await useMultiFileAuthState(sessionDir + "/auth");
  let active;
  let backoff = 1000;
  const handle = await messageHandler({
    receiptFile: sessionDir + "/receipts.json",
    allowedNumbers,
    assess: assessText,
    lookupPhone: jid => active?.signalRepository.lidMapping.getPNForLID(jid),
    send: async (chat, content) => {
      if (!active) throw new Error("Disconnected");
      const sent = await active.sendMessage(chat, content);
      if (!sent?.key) throw new Error("Missing delivery key");
      return sent.key;
    },
  });

  while (true) {
    rmSync(qrFile, { force: true });
    const socket = makeWASocket({
      auth: state,
      logger: pino({ level: "silent" }),
      syncFullHistory: false,
      shouldSyncHistoryMessage: () => false,
      markOnlineOnConnect: false,
    });
    socket.ev.on("creds.update", saveCreds);
    socket.ev.on("messages.upsert", handle);
    const reason = await new Promise(resolve => {
      socket.ev.on("connection.update", update => {
        if (update.qr) {
          qr.generate(update.qr, { small: true }, rendered => {
            writeFileSync(qrFile + ".tmp", rendered + "\n", { mode: 0o600 });
            renameSync(qrFile + ".tmp", qrFile);
            log("Pairing code ready. Read /tmp/pairing-qr inside the running bridge container.");
          });
        }
        if (update.connection === "open") {
          rmSync(qrFile, { force: true });
          active = socket;
          backoff = 1000;
          log("WhatsApp connected. Listening for direct messages.");
        }
        if (update.connection === "close") {
          active = undefined;
          resolve(update.lastDisconnect?.error?.output?.statusCode);
        }
      });
    });
    socket.ev.off("messages.upsert", handle);
    socket.ev.off("creds.update", saveCreds);
    rmSync(qrFile, { force: true });
    if ([DisconnectReason.loggedOut, DisconnectReason.badSession, DisconnectReason.forbidden,
         DisconnectReason.multideviceMismatch, DisconnectReason.connectionReplaced].includes(reason)) {
      log(`WhatsApp session stopped. Check linked devices and the pairing instructions. Status: ${reason}`);
      return;
    }
    log("WhatsApp disconnected. Reconnecting.");
    await delay(backoff);
    backoff = Math.min(30_000, backoff * 2);
  }
}

run().catch(() => {
  log("Bridge startup failed. Check session volume access and configuration.");
  process.exitCode = 1;
});
