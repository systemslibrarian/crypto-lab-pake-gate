// Tiny DOM helpers — no framework. Every UI module builds real elements through
// these so styling and accessibility stay consistent.

export type Attrs = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: Attrs,
  children?: (Node | string | undefined | null)[],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === false) continue;
      if (k === "class") {
        node.className = String(v);
      } else if (k === "text") {
        node.textContent = String(v);
      } else if (k === "html") {
        node.innerHTML = String(v);
      } else if (v === true) {
        node.setAttribute(k, "");
      } else {
        node.setAttribute(k, String(v));
      }
    }
  }
  if (children) {
    for (const c of children) {
      if (c === undefined || c === null) continue;
      node.append(typeof c === "string" ? document.createTextNode(c) : c);
    }
  }
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** A horizontally-scrollable hex box with a copy button. Never wraps. */
export function hexBox(value: string, opts?: { highlight?: boolean; label?: string }): HTMLElement {
  const box = el("div", { class: "hexbox" + (opts?.highlight ? " hexbox--hot" : "") });
  const code = el("code", { class: "hexbox__value", text: value });
  const copy = el(
    "button",
    {
      type: "button",
      class: "hexbox__copy",
      title: "Copy to clipboard",
      "aria-label": `Copy ${opts?.label ?? "value"}`,
    },
    ["copy"],
  );
  copy.addEventListener("click", () => {
    void copyText(value).then((ok) => {
      copy.textContent = ok ? "copied" : "failed";
      window.setTimeout(() => {
        copy.textContent = "copy";
      }, 900);
    });
  });
  box.append(code, copy);
  return box;
}

async function copyText(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    /* fall through to legacy path */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

export function button(
  label: string,
  onClick: () => void,
  opts?: { class?: string; title?: string; disabled?: boolean },
): HTMLButtonElement {
  const b = el("button", {
    type: "button",
    class: "btn" + (opts?.class ? " " + opts.class : ""),
    title: opts?.title,
    disabled: opts?.disabled,
  }, [label]);
  b.addEventListener("click", onClick);
  return b;
}

export function labeledInput(
  labelText: string,
  attrs: Attrs & { id: string },
): { wrap: HTMLElement; input: HTMLInputElement } {
  const input = el("input", { class: "field__input", ...attrs }) as HTMLInputElement;
  const label = el("label", { class: "field__label", for: attrs.id }, [labelText]);
  const wrap = el("div", { class: "field" }, [label, input]);
  return { wrap, input };
}
