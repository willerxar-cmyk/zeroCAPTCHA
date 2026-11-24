import "/widget.js";

async function post(path, body, signal) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok) throw new Error("Verification request failed");
  return response.json();
}

document.querySelector("zero-captcha").run = async (solve, signal) => {
  const { challenge } = await post("/captcha/challenge", {}, signal);
  const solution = await solve(challenge);
  const { accepted } = await post("/demo/submit", { solution }, signal);
  return accepted === true;
};
