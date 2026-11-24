import { createHmac, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";

const loopback = "127.0.0.1";
const maxBodyBytes = 16_384;
const demoPort = readPort("DEMO_PORT", 3080);
const enginePort = readPort("ZEROCAPTCHA_PORT", 3028);
const origin = `http://${loopback}:${demoPort}`;
const bindingKey = randomBytes(32);
const purpose = "login";

const assets = new Map([
  ["/", ["./index.html", "text/html; charset=utf-8"]],
  ["/demo.css", ["./demo.css", "text/css; charset=utf-8"]],
  ["/demo.js", ["./demo.js", "text/javascript; charset=utf-8"]],
  ["/widget.js", ["../../web/widget.js", "text/javascript; charset=utf-8"]],
  ["/widget.css", ["../../web/widget.css", "text/css; charset=utf-8"]],
  ["/press-cue.svg", ["../../web/press-cue.svg", "image/svg+xml"]],
  ["/worker.js", ["../../web/worker.js", "text/javascript; charset=utf-8"]],
]);

function readPort(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65_535) {
    throw new Error(`${name} must be a valid TCP port`);
  }
  return value;
}

function json(response, status, body) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

async function readObject(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > maxBodyBytes) return null;
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

async function requestEngine(path, input) {
  const response = await fetch(`http://${loopback}:${enginePort}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
    signal: AbortSignal.timeout(5_000),
    redirect: "error",
  });
  return { status: response.status, body: await response.json() };
}

const server = createServer({ requestTimeout: 10_000, headersTimeout: 5_000 }, async (request, response) => {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  const path = request.url;

  // An explicit loopback Host and Origin prevent other sites from using the demo.
  if (request.headers.host !== `${loopback}:${demoPort}`) {
    return json(response, 403, { accepted: false });
  }

  try {
    if (request.method === "GET" && path === "/favicon.ico") {
      response.writeHead(204);
      return response.end();
    }
    if (request.method === "GET" && assets.has(path)) {
      const [file, type] = assets.get(path);
      const content = await readFile(new URL(file, import.meta.url));
      response.writeHead(200, { "Content-Type": type });
      return response.end(content);
    }
    if (request.method !== "POST" || !["/captcha/challenge", "/demo/submit"].includes(path)) {
      return json(response, 404, { accepted: false });
    }
    if (request.headers.origin !== origin || request.headers["content-type"] !== "application/json") {
      return json(response, 403, { accepted: false });
    }
    const body = await readObject(request);
    if (!body) {
      response.setHeader("Connection", "close");
      return json(response, 400, { accepted: false });
    }

    // Published integrations should bind a server-owned session. On this
    // local demo, one loopback peer shares one quota and one binding.
    const clientBinding = createHmac("sha256", bindingKey).update(request.socket.remoteAddress).digest("hex");
    const common = { purpose, client_binding: clientBinding };
    if (path === "/captcha/challenge" && Object.keys(body).length === 0) {
      const issued = await requestEngine("/v1/challenge", common);
      if (issued.status === 200 && issued.body.success === true) {
        return json(response, 200, { challenge: issued.body.challenge });
      }
      return json(response, issued.status === 429 ? 429 : 502, { accepted: false });
    }
    if (path === "/demo/submit" && Object.keys(body).length === 1 && body.solution) {
      const verified = await requestEngine("/v1/verify", { ...common, solution: body.solution });
      // The protected action belongs here, after this fresh proof is consumed.
      const accepted = verified.status === 200 && verified.body.valid === true;
      return json(response, accepted ? 200 : 403, { accepted });
    }
    return json(response, 400, { accepted: false });
  } catch {
    return json(response, 502, { accepted: false });
  }
});

server.listen(demoPort, loopback, () => console.log(`zeroCAPTCHA demo at ${origin}`));
