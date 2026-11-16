/* =========================
   Gliding Hover Highlight
   ========================= */

/* The sidebar shows one highlight that glides from item to item, instead of each item lighting */
/* up on its own. Adapted from Starjot. It stays on the nearest item across the small gaps. */
const CONTAINER = ".sidebar-nav";
const ITEM = ".nav-item";

/* How far outside an item (in pixels) the pointer may be for the item to stay lit. */
const GAP = 8;

let highlight: HTMLElement | null = null;
let frame: number | null = null;

/* The highlight is added as the list's first child the first time it is needed. */
function highlightOf(container: Element) {
  if (!highlight?.isConnected) {
    highlight = document.createElement("div");
    highlight.className = "fluid-highlight";
    highlight.setAttribute("aria-hidden", "true");
    container.prepend(highlight);
  }
  return highlight;
}

/* The item the pointer is in, or the nearest one within the gap. */
function itemAt(container: Element, x: number, y: number) {
  let best: Element | null = null;
  let bestDistance = GAP;
  container.querySelectorAll(ITEM).forEach((item) => {
    const box = item.getBoundingClientRect();
    const distance = Math.hypot(Math.max(box.left - x, 0, x - box.right), Math.max(box.top - y, 0, y - box.bottom));
    if (distance <= bestDistance) {
      best = item;
      bestDistance = distance;
    }
  });
  return best as Element | null;
}

/* A highlight that was hidden appears in place and fades in, without travelling from where it was. */
function showOn(container: Element, item: Element) {
  const element = highlightOf(container);
  const outer = container.getBoundingClientRect();
  const box = item.getBoundingClientRect();
  const appearing = !element.classList.contains("is-shown");
  if (appearing) element.classList.add("is-placing");
  element.style.transform = `translate(${box.left - outer.left}px, ${box.top - outer.top}px)`;
  element.style.width = `${box.width}px`;
  element.style.height = `${box.height}px`;
  if (appearing) {
    /* Reading offsetWidth makes the browser place it before the fade starts. */
    void element.offsetWidth;
    element.classList.remove("is-placing");
    element.classList.add("is-shown");
  }
}

function hide() {
  highlight?.classList.remove("is-shown");
}

/* Follows the mouse once per frame. Touch has no hover, so it is left alone. */
export function startFluidHover() {
  document.addEventListener(
    "pointermove",
    (event) => {
      if (event.pointerType === "touch") return;
      const target = event.target instanceof Element ? event.target : null;
      const { clientX, clientY } = event;
      if (frame !== null) cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        frame = null;
        const container = target?.closest(CONTAINER);
        const item = container ? itemAt(container, clientX, clientY) : null;
        if (container && item) showOn(container, item);
        else hide();
      });
    },
    { passive: true },
  );
  document.documentElement.addEventListener("pointerleave", hide);
  window.addEventListener("blur", hide);
}
