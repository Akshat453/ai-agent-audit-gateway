/** A shell command -> its meaning in a few words, for titles and lists (ADR-0043).
 *  "cd dashboard && pnpm typecheck 2>&1 | tail -15" -> "Type-check the code".
 *  Deterministic parsing only (no LLM). The exact command is always shown where the step is
 *  opened; this is just the label. */

const MAX_PARTS = 3;

/** Split on ; && || | (outside quotes) into simple commands, each as words. */
export function splitCommand(command: string): string[][] {
  const parts: string[][] = [];
  let words: string[] = [];
  let cur = "";
  let quote: string | null = null;
  const flushWord = () => { if (cur) { words.push(cur); cur = ""; } };
  const flushPart = () => { flushWord(); if (words.length) parts.push(words); words = []; };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i] as string;
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === "\\" && i + 1 < command.length) { cur += command[++i]; continue; }
    if (ch === ";" || ch === "\n") { flushPart(); continue; }
    if (ch === "&" && command[i + 1] === "&") { flushPart(); i++; continue; }
    if (ch === "|") { flushPart(); if (command[i + 1] === "|") i++; continue; }
    if (ch === " " || ch === "\t") { flushWord(); continue; }
    cur += ch;
  }
  flushPart();
  // drop redirections (2>&1, >file, <file) and leading VAR=value assignments
  return parts.map((w) => {
    const out: string[] = [];
    for (let k = 0; k < w.length; k++) {
      const x = w[k] as string;
      if (/^\d*>&\d+$/.test(x) || /^&?>>?$/.test(x) || x === "<") { if (/^&?>>?$|^<$/.test(x)) k++; continue; }
      if (/^\d*>>?\S+$/.test(x) || /^<\S+$/.test(x)) continue;
      if (!out.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(x)) continue;
      out.push(x);
    }
    return out;
  }).filter((w) => w.length);
}

const base = (p: string) => {
  const clean = p.replace(/\/+$/, "");
  return clean.includes("/") ? clean.split("/").slice(-2).join("/") : clean;
};
const args = (w: string[]) => w.slice(1).filter((a) => !a.startsWith("-"));

const SCRIPT: Record<string, string> = {
  test: "run the tests", "test:unit": "run the unit tests", "test:e2e": "run the browser tests", e2e: "run the browser tests",
  typecheck: "type-check the code", tsc: "type-check the code", "type-check": "type-check the code", lint: "check code style",
  format: "format the code", build: "build the project", dev: "start the app", start: "start the app", install: "install dependencies",
  i: "install dependencies", ci: "install dependencies", add: "add a dependency", remove: "remove a dependency",
};

const GIT: Record<string, string> = {
  status: "check the git state", "rev-parse": "check the git state", log: "look at the git history", diff: "compare changes",
  show: "look at a commit", add: "stage files", commit: "commit changes", checkout: "switch branches", switch: "switch branches",
  branch: "manage branches", fetch: "fetch updates", pull: "pull updates", push: "push to the remote", merge: "merge branches",
  rebase: "rebase the branch", reset: "reset changes", stash: "stash changes", clean: "delete untracked files",
  restore: "restore files", "ls-files": "list files", grep: "search the code", blame: "look at who changed lines", tag: "manage tags",
  remote: "change git remotes", clone: "clone a repository", "cherry-pick": "copy a commit", worktree: "manage worktrees",
};

/** Words that never carry meaning on their own (navigation, output trimming). */
const QUIET = new Set(["cd", "pushd", "popd", "tail", "head", "sort", "uniq", "wc", "tee", "true", "false", "xargs", "cut", "tr", "column", "less", "more", "time", "env", "sleep", "clear"]);

function one(w: string[]): string | null {
  const [p0 = "", ...rest] = w;
  const prog = p0.split("/").pop() ?? p0;
  const a = args(w);
  switch (prog) {
    case "git": {
      let i = 0;
      while (i < rest.length && (rest[i]?.startsWith("-") || rest[i - 1] === "-c" || rest[i - 1] === "-C")) i++;
      const sub = rest[i] ?? "";
      return GIT[sub] ?? (sub ? `run git ${sub}` : "run git");
    }
    case "pnpm": case "npm": case "yarn": case "bun": {
      let sub = a[0] ?? "";
      if (sub === "run" || sub === "exec" || sub === "x" || sub === "dlx") {
        const tool = a[1] ?? "";
        if (sub === "run") return SCRIPT[tool] ?? `run the "${tool}" script`;
        return one([tool, ...a.slice(2)]) ?? `run ${tool}`;
      }
      if (sub === "-C" || sub === "--filter") sub = a[2] ?? "";
      return SCRIPT[sub] ?? (sub ? `run the "${sub}" script` : `run ${prog}`);
    }
    case "npx": return one(a) ?? "run a package";
    case "playwright": return a[0] === "test" ? "run the browser tests" : "run Playwright";
    case "vitest": case "jest": case "pytest": case "mocha": return "run the tests";
    case "tsc": return "type-check the code";
    case "eslint": case "prettier": case "biome": case "ruff": return "check code style";
    case "make": return a[0] ? `run make ${a[0]}` : "run make";
    case "cat": case "bat": case "nl": return a.length ? `read ${a.slice(0, 2).map(base).join(", ")}` : null;
    case "head": case "tail": return a.length && !/^\d+$/.test(a[0] ?? "") ? `read ${base(a[a.length - 1] ?? "")}` : null;
    case "grep": case "rg": case "ag": case "ack": return "search the code";
    case "find": case "fd": return "find files";
    case "ls": case "tree": return "list files";
    case "sed": return w.includes("-i") ? "edit a file" : "filter text";
    case "awk": return "filter text";
    case "echo": case "printf": return "print a message";
    case "curl": case "wget": case "http": {
      const url = a.find((x) => /^https?:\/\//.test(x)) ?? "";
      const host = url ? url.replace(/^https?:\/\//, "").split(/[/:?]/)[0] : "";
      return host ? `call ${host}` : "call a web address";
    }
    case "node": case "python": case "python3": case "ruby": case "deno": case "tsx": case "ts-node":
      return w.includes("-c") || w.includes("-e") ? "run inline code" : a[0] ? `run ${base(a[0])}` : `start ${prog}`;
    case "docker": case "podman": return a[0] === "compose" ? "manage Docker services" : "use Docker";
    case "rm": return "delete files";
    case "mkdir": return "create a folder";
    case "mv": return "move files";
    case "cp": return "copy files";
    case "touch": return "create a file";
    case "chmod": case "chown": return "change file permissions";
    case "psql": case "mysql": case "sqlite3": return "query the database";
    case "ssh": case "scp": case "rsync": return "connect to another computer";
    case "sudo": return "run as administrator";
    case "kill": case "pkill": return "stop a process";
    case "ps": case "lsof": return "list running processes";
    case "which": case "type": return "look up a program";
    default: return QUIET.has(prog) ? null : `run ${prog}`;
  }
}

/** The meaning of a whole command line, at most three parts: "Read x.ts and search the code". */
export function commandSummary(command: string): string {
  const phrases: string[] = [];
  for (const w of splitCommand(command)) {
    const p = one(w);
    if (p && !phrases.includes(p)) phrases.push(p);
  }
  if (!phrases.length) return "Run a command";
  const shown = phrases.slice(0, MAX_PARTS);
  const extra = phrases.length - shown.length;
  const text = shown.length === 1 ? shown[0] as string : `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
  const out = text.charAt(0).toUpperCase() + text.slice(1);
  return extra > 0 ? `${out} (+${extra} more step${extra === 1 ? "" : "s"})` : out;
}
