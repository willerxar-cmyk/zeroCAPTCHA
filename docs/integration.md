# Browser and application integration

## Request flow

1. Derive a stable 64-character lowercase hexadecimal `client_binding` on
   the application server. Use HMAC-SHA-256 with an application-owned key and
   a server-owned session identifier. Give distinct deployments distinct
   keys. Avoid storing or forwarding raw IP addresses as bindings.
2. Fix the action purpose and policy on the server and send a request to
   the engine's `/v1/challenge`. Pass the returned challenge to the browser.
3. Have the browser solve the challenge in a Web Worker and submit the
   resulting solution with the protected action.
4. Recompute the same binding from the current session. Ask the engine to
   verify and consume the proof with the action's expected purpose.
5. Perform the protected action only if verification succeeds. Request a
   fresh challenge after rejection, expiry, or an action that needs a retry.

The browser can see its signed challenge, including the binding and expiry.
It has no access to the signing or binding keys. Use your application's
usual session handling, origin checks, and rate limits on both public routes.
Verification and action authorization serve separate roles. Keep all normal
authorization and validation checks on the action.

## Embed the widget

Serve the contents of `web/` from the same directory over HTTPS or loopback.
The custom element uses a native button with a hand illustration, a live status
and linked copyright credits. Its optional `messages` object configures `start`,
`pending`, `accepted`, and `retry` copy. Keep the original credit visible
and readable when styling or adapting the element.

```html
<link rel="stylesheet" href="/widget.css">
<zero-captcha id="captcha"></zero-captcha>
<script type="module" src="/captcha-ui.js"></script>
```

In your browser module, supply the request flow for your application. Have the
callback resolve to `true` only when the protected action succeeds.

```js
import "./widget.js";

const widget = document.querySelector("#captcha");
widget.run = async (solve, signal) => {
  const challenge = await issueForCurrentSession(signal);
  const solution = await solve(challenge);
  return submitProtectedAction(solution, signal);
};
```

See the complete [demo client](../examples/demo/demo.js) and
[demo server](../examples/demo/server.mjs) for the actual request and response
handling. The bundled widget solves `S6-PBKDF2-SHA256` challenges. Integrations
using other algorithms or the optional hold-and-release protocol supply their
own client implementation and retain the visible attribution.
