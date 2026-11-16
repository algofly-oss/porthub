// Scroll only the horizontal tab container; never move the page or modal.
export function revealSelectedTab(group) {
  const selected = group?.querySelector('[aria-pressed="true"]');
  if (!selected) return;
  for (let parent = group.parentElement; parent; parent = parent.parentElement) {
    if (!['auto', 'scroll'].includes(getComputedStyle(parent).overflowX)) continue;
    const viewport = parent.getBoundingClientRect();
    const tab = selected.getBoundingClientRect();
    const left = viewport.left + parent.clientLeft;
    const right = left + parent.clientWidth;
    const delta = tab.left < left ? tab.left - left : tab.right > right ? tab.right - right : 0;
    if (delta) parent.scrollLeft += delta;
    return;
  }
}
