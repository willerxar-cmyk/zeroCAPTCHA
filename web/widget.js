// zeroCAPTCHA © 2026 Willer Xavier Reis and SID6. See LICENSE.

const solveTimeoutMs = 90_000;

function creditLink(name, url) {
  const link = document.createElement("a");
  link.textContent = name;
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function solveInWorker(challenge, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./worker.js", import.meta.url));
    const timeout = setTimeout(() => finish(new Error("Verification timed out")), solveTimeoutMs);
    const abort = () => finish(signal.reason);

    function finish(error, solution) {
      clearTimeout(timeout);
      signal.removeEventListener("abort", abort);
      worker.terminate();
      if (error) reject(error);
      else resolve(solution);
    }

    signal.addEventListener("abort", abort, { once: true });
    worker.onmessage = ({ data }) => {
      if (data.id !== 1) return;
      if (data.ok) finish(null, data.solution);
      else finish(new Error(data.error));
    };
    worker.onerror = () => finish(new Error("Verification worker failed"));
    worker.onmessageerror = () => finish(new Error("Invalid verification response"));
    try {
      worker.postMessage({ id: 1, challenge });
    } catch (error) {
      finish(error);
    }
  });
}

export class ZeroCaptcha extends HTMLElement {
  #attempt;
  #button = document.createElement("button");
  #label = document.createElement("span");
  #status = document.createElement("p");
  #credit = document.createElement("small");

  // Integrators supply a function that obtains a challenge, calls solve,
  // and submits the solution with the protected action.
  run;
  messages = {
    start: "Start verification",
    pending: "Verifying…",
    accepted: "Verification accepted.",
    retry: "Verification failed. Please try again.",
  };

  constructor() {
    super();
    this.#button.type = "button";
    this.#button.className = "zc-control";
    this.#button.addEventListener("click", () => void this.#verify());

    const instruction = document.createElement("span");
    instruction.className = "zc-instruction";
    const track = document.createElement("span");
    track.className = "zc-track";
    track.setAttribute("aria-hidden", "true");
    instruction.append(this.#label, track);

    const cue = document.createElement("img");
    cue.className = "zc-press-cue";
    cue.src = new URL("./press-cue.svg", import.meta.url).href;
    cue.alt = "";
    this.#button.append(instruction, cue);

    this.#status.className = "zc-status";
    this.#status.setAttribute("role", "status");
    this.#credit.className = "zc-credit";
    this.#credit.append(
      "zeroCAPTCHA © 2026 ",
      creditLink("Willer Xavier Reis", "https://www.linkedin.com/in/willerxar/"),
      " and ",
      creditLink("SID6", "https://sid6.com/"),
    );
  }

  connectedCallback() {
    this.#label.textContent = this.messages.start;
    this.#renderState("idle");
    this.append(this.#button, this.#status, this.#credit);
  }

  disconnectedCallback() {
    this.#attempt?.abort();
  }

  #renderState(state, message = "") {
    this.#button.dataset.state = state;
    this.#status.textContent = message;
  }

  async #verify() {
    if (this.#attempt || typeof this.run !== "function") return;
    const attempt = new AbortController();
    this.#attempt = attempt;
    this.#button.disabled = true;
    this.#renderState("pending", this.messages.pending);
    try {
      const solve = async (challenge) => {
        const started = performance.now();
        const solution = await solveInWorker(challenge, attempt.signal);
        // The button activation is the sole interaction collected by this widget.
        return {
          ...solution,
          evidence: {
            interactions: 1,
            focus: document.hasFocus(),
            solve_ms: Math.round(performance.now() - started),
          },
        };
      };
      const accepted = await this.run(solve, attempt.signal);
      if (accepted !== true) throw new Error("Server rejected verification");
      if (!attempt.signal.aborted) this.#renderState("accepted", this.messages.accepted);
    } catch {
      if (!attempt.signal.aborted) this.#renderState("retry", this.messages.retry);
    } finally {
      this.#attempt = undefined;
      this.#button.disabled = false;
    }
  }
}

customElements.define("zero-captcha", ZeroCaptcha);
