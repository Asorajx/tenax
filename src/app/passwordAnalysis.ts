import type { MatchExtended, ZxcvbnFactory, ZxcvbnResult } from "@zxcvbn-ts/core";
import type { Finding, FindingStatus } from "../components/Finding";

/* =========================
   Password Analysis
   ========================= */

/* Runs in the interface and never leaves this device. The word lists are large, so they */
/* are loaded the first time the page opens, not at startup. */
export type Analyser = ZxcvbnFactory;

let loading: Promise<Analyser> | undefined;

export function loadAnalyser() {
  loading ??= (async () => {
    const [{ ZxcvbnFactory }, common, english] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
    ]);
    return new ZxcvbnFactory({
      translations: english.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...english.dictionary },
    });
  })();
  return loading;
}

/* The longest password analysed. Longer ones only slow the estimate down. */
export const MAX_LENGTH = 128;

/* The patterns worth showing. Random characters are not a pattern. */
const PATTERNS = ["dictionary", "spatial", "repeat", "sequence", "date", "regex", "wordSequence"];

/* What a pattern is and why it weakens the password. Only generic examples are used, so the */
/* password itself is never written out. */
function describe(match: MatchExtended) {
  switch (match.pattern) {
    case "sequence":
      return match.sequenceName === "digits"
        ? { name: "Number sequence", why: "Runs like 123 are guessed early" }
        : { name: "Letter sequence", why: "Runs like abc are guessed early" };
    case "repeat":
      return match.baseToken.length === 1
        ? { name: "Repeated character", why: "Repeating one character adds little" }
        : { name: "Repeated group", why: "Repeating a group adds little" };
    case "spatial":
      return match.graph === "keypad"
        ? { name: "Keypad pattern", why: "Number pad runs are common guesses" }
        : { name: "Keyboard pattern", why: "Key runs like qwerty are common guesses" };
    case "dictionary":
      if (match.reversed) return { name: "Reversed word", why: "Backwards words are easy to try" };
      if (match.l33t) return { name: "Word with swapped characters", why: "Swaps like @ for a are well known" };
      if (match.dictionaryName === "passwords") return { name: "Common password", why: "Found in lists of common passwords" };
      return /names/.test(match.dictionaryName)
        ? { name: "Common name", why: "Names are quick to guess" }
        : { name: "Common word", why: "Dictionary words are quick to guess" };
    case "date":
      return { name: "Date", why: "Dates have few possible values" };
    case "regex":
      return { name: "Recent year", why: "Years are among the first numbers tried" };
    default:
      return { name: "Common phrase", why: "Phrases of common words are easy to guess" };
  }
}

const STATUS_BY_SCORE: FindingStatus[] = ["risk", "risk", "warning", "ok", "ok"];

function capitalise(text: string) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/* Which kinds of character the password uses, such as "lowercase, digits". */
function characterTypes(password: string) {
  const types = [
    [/[a-z]/, "lowercase"],
    [/[A-Z]/, "uppercase"],
    [/[0-9]/, "digits"],
    [/[^a-zA-Z0-9]/, "symbols"],
  ] as const;
  return types.filter(([pattern]) => pattern.test(password)).map(([, name]) => name).join(", ");
}

/* Turns the estimator's result into findings. No score is shown, only what was found. */
function toFindings(password: string, result: ZxcvbnResult, ms: number): Finding[] {
  const times = result.crackTimes;
  const status = STATUS_BY_SCORE[result.score];
  const patterns = result.sequence.filter((match) => PATTERNS.includes(match.pattern));

  const guessing: Finding = {
    id: "guessing",
    status,
    title: "Guessing time",
    summary: `Could take ${times.offlineFastHashingXPerSecond.display} to guess`,
    checked: "I estimated how many guesses it would take to find this password.",
    why: "A password that takes few guesses can be broken quickly if stored passwords leak from a site.",
    action: result.feedback.suggestions.length
      ? result.feedback.suggestions.join(" ")
      : status === "ok"
        ? undefined
        : "Make it longer. Several unrelated words are easier to remember than symbols.",
    details: [
      { label: "Length", value: `${password.length} characters` },
      { label: "Character types", value: characterTypes(password) },
      { label: "Online, rate-limited", value: capitalise(times.onlineThrottlingXPerHour.display) },
      { label: "Offline, slow hash", value: capitalise(times.offlineSlowHashingXPerSecond.display) },
      { label: "Offline, fast hash", value: capitalise(times.offlineFastHashingXPerSecond.display) },
    ],
    steps: [
      {
        action: "Analysed the password with zxcvbn-ts",
        plain: "Estimated how long this password would take to guess, on this device only",
        method:
          "ZxcvbnFactory.check() from @zxcvbn-ts/core, with the common and English word lists. Runs in the interface, no network",
        ok: true,
        result: `${result.sequence.length} segment(s) matched`,
        ms,
      },
    ],
  };

  const found: Finding = {
    id: "patterns",
    status: result.feedback.warning ? "warning" : patterns.length ? "info" : "ok",
    title: "Patterns found",
    summary:
      result.feedback.warning ?? (patterns.length ? `${patterns.length} common ${patterns.length === 1 ? "pattern" : "patterns"} found` : "No common patterns found"),
    checked: "I looked for common words, keyboard runs, repeats, sequences and dates.",
    why: "Guessing tools try these patterns first, so each one makes the password easier to find.",
    details: patterns.map((match) => {
      const { name, why } = describe(match);
      /* Only the position is shown, so the password itself is never written out on screen. */
      const where = match.i === match.j ? `character ${match.i + 1}` : `characters ${match.i + 1} to ${match.j + 1}`;
      return { label: `${name} · ${where}`, value: why };
    }),
  };

  return [guessing, found];
}

export function analyse(analyser: Analyser, password: string) {
  const started = performance.now();
  const result = analyser.check(password);
  return toFindings(password, result, performance.now() - started);
}
