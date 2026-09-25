# go-csp-engine 

Content Security Policy engine for Go/Golang. Unit test your CSP rules!

This allows you to check HTML and CSS for preflight CSP violations.

## Issue tracking (Beads) — read this first

All known issues, bugs and planned work for this repository live in **Beads** (`.beads/`, issue
prefix `csp-validator`). Beads is the source of truth for open work; markdown TODO files and chat-only
notes are not.

Anyone working on this repo (human or AI agent) must:

1. **Consult open issues before starting** — check what is already filed, in progress or blocked, so
   work is not duplicated and blockers are respected.
2. **File every bug, observation and follow-up with `bd create`** as soon as it is discovered — do not
   fix things that are not tracked, and do not track things outside Beads.
3. **Close with `bd close <id>` only when the work is actually complete and verified** (build, tests).

### The 5 commands that matter

| Command | What it is for |
| --- | --- |
| `bd ready` | List issues that are actionable right now (nothing open blocks them). Also useful: `bd list --status=open`, `bd blocked`. |
| `bd show <id>` | Read one issue in full: description, file references, labels, dependencies. Inspect before you edit. |
| `bd create "title" -d "description" -p <0-4> -t bug\|task\|feature -l label` | File a new issue (`--deps <id>` links a blocker, `--acceptance` adds criteria). |
| `bd close <id> --reason="what was done and how it was verified"` | Close an issue once verified. |
| `bd remember "project insight or decision"` | Store a persistent memory that survives sessions — conventions, gotchas, decisions future agents must know. |

Adding new context at any time is always correct: if you learned something durable about the project,
`bd remember` it; if you find work to do, `bd create` it.

Features:

* Checks script, img, audio, video, track, iframe, object, embed, applet, style,
  base tags.
* Checks `link` tags for stylesheet, prefetch, prerender, icon, and manifest types.
* Checks unsafe inline style and script tags for nonce & hash.
* Check stylesheet @import and @font-face external URLs.

Known limitations:

* Doesn't fetch imported/referenced URLs to check for post flight violations.
  Thus, it doesn't check that the imported external resources have valid hashes.
* Doesn't check stylesheet declarations that access resources like
  `background-image`.
* Doesn't check any network requests made by javascript.

## Example

```go
package main

import (
	"net/url"
	"strings"
  "log"

	csp "github.com/secinto/go-csp-engine"
)

func main() {
  policy, err := csp.ParsePolicy("default-src: 'self'; script-src: 'nonce-foo'; img-src https://cdn")
  if err != nil {
    log.Fatal(err)
  }
  page, err := url.Parse('http://example.com/bar/')
  if err != nil {
    log.Fatal(err)
  }
  valid, reports, err := csp.ValidatePage(policy, *page, strings.NewReader(`
    <link rel="stylesheet" href="./foo.css">
    <script nonce="foo">alert('boo yeah!')</script>
    <img src="https://cdn/blah">
  `))
  if err != nil {
    log.Fatal(err)
  }
  log.Println(valid, reports)
}
```

## License

go-csp-engine is licensed under the MIT license. See LICENSE file for more
information.
