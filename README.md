# zeroCAPTCHA

<img src="./web/press-cue.svg" width="64" height="64" align="right" alt="">

Self-hosted proof-of-work CAPTCHA for web applications. A Rust service
issues and verifies signed, single-use challenges. A framework-independent
widget solves them in a Web Worker using Web Crypto.

Developed by [Willer Xavier Reis](https://www.linkedin.com/in/willerxar/) and
[SID6](https://sid6.com/).

## Quick start

Install Rust 1.96 or later and Node.js 24. From this directory, start the
engine with a disposable signing key.

```powershell
$env:ZEROCAPTCHA_SECRET = node -p 'require("node:crypto").randomBytes(32).toString("hex")'
cargo run --locked
```

<details>
<summary>Shell commands for Linux and macOS</summary>

```sh
export ZEROCAPTCHA_SECRET="$(node -p 'require("node:crypto").randomBytes(32).toString("hex")')"
cargo run --locked
```

</details>

Start the demo in a second terminal.

```sh
node examples/demo/server.mjs
```

Open [the local demo](http://127.0.0.1:3080/) and select **Start verification**.
The Rust service consumes the proof and the widget displays **Verification
accepted**. Both processes bind to loopback.

## Integration

Serve the widget assets with your application and call the engine from a
trusted server. Verify the proof as part of the protected action.

- [Embed the browser widget](docs/integration.md)
- [HTTP API and optional hold-and-release protocol](docs/api.md)
- [Configuration, deployment, and tests](docs/operations.md)
- [Changelog](CHANGELOG.md)

## License

Individuals and organizations may use and modify zeroCAPTCHA free of charge,
including for commercial use. The [license](LICENSE) requires free distribution
of copies and derivatives. Preserve the [copyright notice](NOTICE) and keep
the following credit visible on every CAPTCHA:

> zeroCAPTCHA © 2026 Willer Xavier Reis and SID6
