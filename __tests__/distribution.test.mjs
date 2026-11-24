import assert from "node:assert/strict";
import { pbkdf2Sync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { test } from "node:test";
import { Worker } from "node:worker_threads";

const require = createRequire(import.meta.url);

test("the widget puts the original copyright credit in the rendered control", async () => {
  const [widget, license, notice, readme] = await Promise.all(
    ["web/widget.js", "LICENSE", "NOTICE", "README.md"].map((name) =>
      readFile(new URL(`../${name}`, import.meta.url), "utf8")),
  );
  const credit = "zeroCAPTCHA © 2026 Willer Xavier Reis and SID6";
  for (const content of [widget, license, notice, readme]) assert.ok(content.includes(credit));
  assert.ok(widget.includes('creditLink("Willer Xavier Reis", "https://www.linkedin.com/in/willerxar/")'));
  assert.ok(widget.includes('creditLink("SID6", "https://sid6.com/")'));
  assert.match(widget, /this\.append\(this\.#button, this\.#status, this\.#credit\)/);
});

test("the demo and widget use the bundled hand illustration and stylesheet", async () => {
  const [widget, svg, demo, css] = await Promise.all(
    ["web/widget.js", "web/press-cue.svg", "examples/demo/index.html", "web/widget.css"].map((name) =>
      readFile(new URL(`../${name}`, import.meta.url), "utf8")),
  );
  assert.match(svg, /<svg [^>]*viewBox="0 -6 96 100"/);
  assert.match(svg, /<path d="M43 42 L43 66/);
  assert.doesNotMatch(svg, /<!DOCTYPE|<(?:script|foreignObject|image|use)\b|\b(?:href|on\w+)=/i);
  assert.match(widget, /cue\.src = new URL\("\.\/press-cue\.svg", import\.meta\.url\)/);
  assert.match(widget, /cue\.alt = ""/);
  assert.match(demo, /rel="stylesheet" href="\/widget\.css"/);
  assert.match(css, /prefers-reduced-motion: no-preference/);
});

test("the bundled worker solves its supported proof and rejects other algorithms", { timeout: 10_000 }, async (t) => {
  const worker = new Worker(`
    const { parentPort, workerData } = require("node:worker_threads");
    globalThis.self = globalThis;
    globalThis.postMessage = value => parentPort.postMessage(value);
    require(workerData);
    parentPort.on("message", data => globalThis.onmessage({ data }));
  `, { eval: true, workerData: require.resolve("../web/worker.js") });
  t.after(() => worker.terminate());

  const salt = randomBytes(16);
  // Public fixture for the worker parser. Only the Rust engine authenticates signatures.
  const challenge = {
    id: "worker-test",
    alg: "S6-PBKDF2-SHA256",
    salt: salt.toString("base64"),
    cost: 100,
    prefix: "0",
    expires_at: Math.floor(Date.now() / 1000) + 60,
    purpose: "login",
    kind: "proof_of_work",
    client_binding: "ab".repeat(32),
    sig: "cd".repeat(32),
  };

  async function solve(input) {
    return new Promise((resolve, reject) => {
      const onError = (error) => {
        worker.removeListener("message", onMessage);
        reject(error);
      };
      const onMessage = (message) => {
        worker.removeListener("error", onError);
        resolve(message);
      };
      worker.once("message", onMessage);
      worker.once("error", onError);
      worker.postMessage({ id: 1, challenge: input });
    });
  }

  const solved = await solve(challenge);
  assert.equal(solved.ok, true);
  assert.deepEqual(solved.solution.challenge, challenge);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64LE(BigInt(solved.solution.counter));
  const key = pbkdf2Sync(counter, salt, challenge.cost, 32, "sha256").toString("hex");
  assert.equal(solved.solution.key, key);
  assert.ok(key.startsWith(challenge.prefix));

  const unsupported = await solve({ ...challenge, alg: "S6-SHA256" });
  assert.equal(unsupported.ok, false);
  assert.match(unsupported.error, /unsupported/);
});
