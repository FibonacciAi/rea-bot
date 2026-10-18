# Attribution

Lostwax (code id `rea-bot`) is an independent integration. It is not an official REA, xAI, Cursor or OpenAI product.

- Engine: REA, `rea-agents@6.5.0`, MIT, Copyright (c) 2026 morluto. Source https://github.com/morluto/rea, commit `3b79af28e80785afce9f5998d8f03289402a1847`, tag `rea-agents-6.5.0`.
- This repository does not redistribute the engine. `rea-bot engine setup` downloads the published npm tarball, verifies the SHA-512 recorded in `engine/UPSTREAM.json`, adds the matching source release `package-lock.json` (`engine/package-lock.json`, from upstream) and verifies all 1,651 files against `engine/vendor-integrity.json`. Upstream licenses and third-party notices travel inside that tarball and remain in force.
- The workbench logic is derived from REA Native 0.1.7 (MIT, Copyright (c) 2026 REA Native contributors). The owned search fixture and its Python reconstruction come from the same project under MIT.
- Commercial engines (Hopper, IDA, JEB and similar) are not included or licensed. Analyzing a target does not grant rights in it.
