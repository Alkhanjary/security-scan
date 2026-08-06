/* Landing page: types the hero terminal out line by line.
 *
 * The scan log is the most characteristic thing in this tool's world, so it
 * plays rather than sitting still. Built with textContent per span — never
 * innerHTML on a template string — so the pattern here matches the rest of
 * the app and can't drift into an injection habit.
 */
(function () {
  'use strict';

  var LINES = [
    ['Scan scope: code, web, network', 'tok-dim'],
    ['[regex 12] config/settings.py', 'tok-dim'],
    ['[regex 28] api/routes.py', 'tok-dim'],
    ['[CRITICAL] possible AWS access key ID', 'sev-critical'],
    ['  config/settings.py:41', 'tok-dim'],
    ['[HIGH] subprocess call with shell=True', 'sev-high'],
    ['  api/routes.py:88', 'tok-dim'],
    ['[3/3] AI reviewing api/routes.py ...', 'tok-dim'],
    ['  verdict: true_positive  (reachable from a request handler)', 'tok-ai'],
    ['Risk summary: 2 confirmed issues to fix before deploy.', 'tok-accent']
  ];

  var host = document.getElementById('hero-code');
  if (!host) return;
  var code = host.querySelector('code');
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function addLine(text, cls) {
    var span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = text;
    code.appendChild(span);
    code.appendChild(document.createTextNode('\n'));
    return span;
  }

  if (reduced) {
    LINES.forEach(function (l) { addLine(l[0], l[1]); });
    return;
  }

  // Reserve the final height up front so the panel doesn't grow line by line
  // and shove the rest of the page down while it plays.
  code.style.minHeight = (LINES.length * 1.75) + 'em';

  var caret = document.createElement('span');
  caret.className = 'caret';
  caret.textContent = '█';

  var i = 0;
  function next() {
    if (i >= LINES.length) { caret.remove(); return; }
    var line = LINES[i++];
    var span = addLine('', line[1]);
    var text = line[0];
    var c = 0;
    span.appendChild(caret);

    (function typeChar() {
      if (c < text.length) {
        span.insertBefore(document.createTextNode(text.charAt(c++)), caret);
        // Faster through dim log noise, slower on the lines that carry meaning.
        setTimeout(typeChar, line[1] === 'tok-dim' ? 6 : 16);
      } else {
        setTimeout(next, line[1] === 'tok-dim' ? 90 : 320);
      }
    })();
  }

  // Hold a beat before starting so the page has settled.
  setTimeout(next, 450);
})();
