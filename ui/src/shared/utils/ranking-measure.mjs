// ResizeObserver delivery only schedules work; writing ancestor-dependent layout
// during delivery can leave notifications undelivered even when layout settles.
export function observeRankingRows(element) {
  const contents = [...element.querySelectorAll('[data-ranking-row-content]')];
  let frame = null, disposed = false;
  const set = (target, name, value) => {
    if (target.style.getPropertyValue(name) !== value) target.style.setProperty(name, value);
  };
  const measure = () => {
    if (disposed) return;
    const height = element.clientHeight;
    const scrollbar = `${element.offsetWidth - element.clientWidth}px`;
    const minimum = Math.max(0, ...contents.map(content => content.getBoundingClientRect().height + 1));
    if (element.parentElement) set(element.parentElement, '--ranking-scrollbar', scrollbar);
    if (!height || !minimum) return;
    const count = Math.max(1, Math.min(contents.length, Math.floor(height / minimum)));
    set(element, '--ranking-row-height', `${contents.length <= count ? minimum : height / count}px`);
  };
  const schedule = () => {
    if (disposed || frame !== null) return;
    frame = requestAnimationFrame(() => { frame = null; measure(); });
  };
  const observer = new ResizeObserver(schedule);
  observer.observe(element);
  contents.forEach(content => observer.observe(content));
  measure(); // Called by the component's layout effect, outside observer delivery.
  return () => {
    disposed = true;
    observer.disconnect();
    if (frame !== null) cancelAnimationFrame(frame);
    frame = null;
  };
}
