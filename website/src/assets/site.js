// The entire site works without JavaScript; this adds copy buttons to examples.
for (const pre of document.querySelectorAll('pre[data-copy], .prose pre')) {
  if (!navigator.clipboard) continue;
  const wrap = document.createElement('div');
  wrap.className = 'code-wrap';
  pre.before(wrap); wrap.append(pre);
  const button = document.createElement('button');
  button.className = 'copy'; button.type = 'button'; button.textContent = 'Copy';
  button.setAttribute('aria-label', 'Copy code example');
  button.setAttribute('aria-live', 'polite');
  wrap.append(button);
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pre.textContent.trim());
      button.textContent = 'Copied';
    } catch { button.textContent = 'Select to copy'; }
    setTimeout(() => { button.textContent = 'Copy'; }, 2200);
  });
}
