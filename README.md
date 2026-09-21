# Foxhound for Chromium

**Dynamic taint tracking for the Chromium web platform (Blink + V8), ported from Project "Foxhound".**

This source tree is a **Chromium 152** checkout extended with byte-precise, browser-wide **taint tracking** — the technique that made [Project "Foxhound"](https://github.com/SAP/project-foxhound) the state of the art for detecting client-side Cross-Site-Scripting (DOM-XSS). Foxhound implements taint tracking in **Firefox / SpiderMonkey**; this project re-implements the same capability in **Chromium / Blink / V8**.

Taint tracking marks attacker-controllable strings (e.g. `location.hash`, `document.URL`, `postMessage` data) as *tainted*, follows them byte-by-byte as they flow through string operations across the whole engine, and raises a report the moment tainted data reaches a dangerous **sink** (e.g. `eval()`, `.innerHTML`, `document.write()`, `script.src`, …). This makes it possible to automatically discover client-side injection flaws in real websites.

---

## Where this project comes from

This is **not** a from-scratch implementation. It is a **port** of an existing, peer-reviewed system:

* **Upstream: [SAP/project-foxhound](https://github.com/SAP/project-foxhound)** — a Firefox fork that adds taint tracking to Gecko and SpiderMonkey. It was independently rated the **best tool** for dynamic security analysis of JavaScript, outperforming 17 other tools on compatibility, transparency, coverage and performance (Calzavara et al., *WWW '25*). Foxhound is licensed under **GPL-3.0**.
* **This project** takes Foxhound's taint model — its data structures, sources, propagation rules and sinks — and re-implements the same semantics on the **Chromium** engine stack instead of the Firefox one:
  * **SpiderMonkey → V8** for the JavaScript engine (string representation, string builtins, the parser/scanner character streams, the JIT tiers).
  * **Gecko → Blink** for the rest of the browser (DOM strings, `ParkableString`, script streaming, the network stack).

The goal is to make Foxhound-grade taint analysis available to the very large share of the web that is tested against Chromium, and to the tooling ecosystem built around it.

### What was actually ported

| Layer | Firefox / Foxhound | This project (Chromium) |
| --- | --- | --- |
| Taint core data structures | `taint/Taint.*` (shared by Gecko + SpiderMonkey) | [`taint/`](taint) `Taint.*`, reused and adapted for Blink + V8 |
| String taint storage | `JSString` carries `StringTaint` | V8 `String` and Blink `WTF::String` / `ParkableString` carry `StringTaint` |
| Sources / propagation / sinks | SpiderMonkey + Gecko instrumentation | V8 string builtins & factory, Blink bindings |
| Cross-document taint transport | internal | serialized over the **`X-Taint`** HTTP response header and carried across the Mojo IPC boundary |
| Sink reporting | `JS_ReportTaintSink` → console + `__taintreport` event | same developer-facing contract: console warning + `__taintreport` event |

Because V8 lives in a **separate third-party repository** (`v8/`, managed by `gclient`/DEPS), the V8 side of the port is shipped as a patch rather than as committed files — see [Building](#building).

---

## Usage

### Detecting flows at runtime

When the browser discovers an insecure data flow, it logs a warning to the JavaScript console and dispatches a `__taintreport` event on `window`. Listen for it to inspect the flow:

```javascript
window.addEventListener("__taintreport", function (report) {
  const { str, sink, loc } = report.detail;
  // str  — the tainted string; str.taint holds its byte ranges and their flow
  // sink — the sink the tainted data reached
  // loc  — location.href of the document where the flow was detected
  console.log(sink, loc, str.taint);
});
```

The event `detail` carries `{ str, sink, loc }`.

### Inspecting taint from JavaScript

Every string exposes its taint through the `.taint` property, and `String.tainted()` creates a tainted source string:

```javascript
var a = String.tainted("abc");   // optional 2nd argument: a source name
var b = "def";
var c = a.toUpperCase() + b;
console.log(JSON.stringify(c.taint));
// [{begin:0, end:3, flow:[{operation:"toUpperCase", arguments:[]},
//                          {operation:"Manual taint source", arguments:["abc"]}]}]
```

The taint is a list of ranges; each range carries the full `flow` of operations that produced it, from the original source to the current value.

The set of instrumented **sources** and **sinks** mirrors upstream Foxhound; see [`taint/`](taint) for the core classes and [`taint/Taint.h`](taint/Taint.h) for the data-structure documentation.

---

## Building

This is a normal Chromium build. You need `depot_tools` on your `PATH` and this **Chromium 152** tree checked out via `gclient`/`fetch` (do **not** `git clone`; follow the [get-the-code](docs/get_the_code.md) instructions).

> The port has been developed and tested on **Windows**. The steps below are platform-neutral; adjust the toolchain notes in `args.gn` for your OS.

### 1. Apply the V8 taint patch

The main-tree changes (taint core in [`taint/`](taint), Blink integration) are already part of this tree. The **V8** changes are provided as a patch, because `gclient sync` resets `v8/` to the DEPS-pinned revision:

```bash
cd v8
# V8 must be at the pinned base revision:
#   d0c53053ee8  "Version 15.2.114"   (see ../patches/v8-base.txt)
git apply ../patches/v8-foxhound-taint.patch
cd ..
```

Re-apply this patch whenever `gclient sync` rolls or resets V8.
### 2. Follow Chromium to build and run 
---

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**, the same license as upstream Foxhound. Inherited code keeps its original license: **Chromium** and **V8** remain **BSD-3-Clause**, and any **Firefox**-derived files remain **MPL-2.0** — both are GPL-3.0-compatible.
