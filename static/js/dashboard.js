/* Forensics Dashboard — shared JS utilities */

/**
 * Append a line to a <pre> element and auto-scroll to bottom.
 */
function appendLog(elementId, line) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent += line + "\n";
  el.scrollTop = el.scrollHeight;
}
