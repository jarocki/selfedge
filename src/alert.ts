/**
 * alert.ts — fire a doorbell to the configured webhook. Callers pass a SHORT,
 * content-free string (who/where/id, never message bodies). Discord/Slack/ntfy
 * all accept a simple JSON post; we send the widely-compatible {content} shape.
 */
export async function alert(env: { ALERT_WEBHOOK_URL?: string }, text: string): Promise<void> {
  if (!env.ALERT_WEBHOOK_URL) return;
  // Sanitize before it leaves: collapse newlines (prevents webhook payload
  // injection), defang @everyone/@here mentions with a zero-width space, and
  // hard-cap length. Callers may include request-derived strings.
  const clean = String(text)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/@(everyone|here)/gi, "@\u200b$1")
    .slice(0, 300);
  try {
    await fetch(env.ALERT_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: clean, text: clean }), // content=Discord/ntfy, text=Slack
    });
  } catch { /* alerting is best-effort; never break a response over it */ }
}
