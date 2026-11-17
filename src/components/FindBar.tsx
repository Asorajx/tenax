import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronUp, X } from "lucide-react";

/* =========================
   Find Bar
   ========================= */

/* Every match of the text on the page that is showing, as ranges. Hidden pages and the bar itself are skipped. */
function findRanges(query: string, bar: Element | null) {
  const ranges: Range[] = [];
  const needle = query.toLowerCase();
  if (!needle) return ranges;

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const element = node.parentElement;
      if (!element || element.closest("script, style") || bar?.contains(element)) return NodeFilter.FILTER_REJECT;
      return element.getClientRects().length ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    },
  });

  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = (node.textContent ?? "").toLowerCase();
    for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + needle.length)) {
      const range = new Range();
      range.setStart(node, at);
      range.setEnd(node, at + needle.length);
      ranges.push(range);
    }
  }
  return ranges;
}

/* The matches are painted with the CSS highlight feature, which marks text without changing the page. */
function paint(ranges: Range[], current: number) {
  CSS.highlights.delete("find");
  CSS.highlights.delete("find-current");
  if (!ranges.length) return;
  CSS.highlights.set("find", new Highlight(...ranges));
  CSS.highlights.set("find-current", new Highlight(ranges[current]));
  ranges[current].startContainer.parentElement?.scrollIntoView({ block: "center" });
}

/* Ctrl + F opens it below the title bar, so it never covers the window buttons. Enter and Shift + Enter */
/* move between matches, and Escape closes it. */
export default function FindBar() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [count, setCount] = useState(0);
  const [index, setIndex] = useState(0);
  const bar = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const ranges = useRef<Range[]>([]);

  /* Looks again, keeping the same match when it is still there. */
  const search = useCallback((text: string, at: number) => {
    ranges.current = findRanges(text, bar.current);
    const next = Math.min(at, Math.max(ranges.current.length - 1, 0));
    setCount(ranges.current.length);
    setIndex(next);
    paint(ranges.current, next);
  }, []);

  function close() {
    setOpen(false);
    CSS.highlights.delete("find");
    CSS.highlights.delete("find-current");
  }

  function move(step: number) {
    if (!ranges.current.length) return;
    const next = (index + step + ranges.current.length) % ranges.current.length;
    setIndex(next);
    paint(ranges.current, next);
  }

  /* Ctrl + F takes the place of the browser's own find, which cannot be moved. */
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!event.ctrlKey || event.altKey || event.key.toLowerCase() !== "f") return;
      event.preventDefault();
      setOpen(true);
      input.current?.focus();
      input.current?.select();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (open) {
      input.current?.focus();
      input.current?.select();
    }
  }, [open]);

  /* Pages change while it is open, so the matches follow what is showing. */
  useEffect(() => {
    if (!open || !query) return;
    let timer = 0;
    const observer = new MutationObserver(() => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        const found = findRanges(query, bar.current);
        if (found.length !== ranges.current.length || found[0]?.startContainer !== ranges.current[0]?.startContainer) {
          search(query, index);
        }
      }, 150);
    });
    observer.observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ["hidden"] });
    return () => {
      window.clearTimeout(timer);
      observer.disconnect();
    };
  }, [open, query, index, search]);

  if (!open) return null;

  return (
    <div className="findbar" role="search" ref={bar}>
      <input
        ref={input}
        type="text"
        value={query}
        aria-label="Find in page"
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => {
          setQuery(event.target.value);
          search(event.target.value, 0);
        }}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            move(event.shiftKey ? -1 : 1);
          } else if (event.key === "Escape") {
            close();
          }
        }}
      />
      <span className="findbar-count" aria-live="polite">
        {query ? `${count ? index + 1 : 0}/${count}` : ""}
      </span>
      <button type="button" aria-label="Previous match" onClick={() => move(-1)}>
        <ChevronUp size={16} strokeWidth={1.75} aria-hidden="true" />
      </button>
      <button type="button" aria-label="Next match" onClick={() => move(1)}>
        <ChevronDown size={16} strokeWidth={1.75} aria-hidden="true" />
      </button>
      <button type="button" aria-label="Close find" onClick={close}>
        <X size={16} strokeWidth={1.75} aria-hidden="true" />
      </button>
    </div>
  );
}
