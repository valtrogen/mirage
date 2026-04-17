# Third-Party Notices

The mirage source tree contains code derived from the following
third-party projects. Each entry lists the upstream project, the
license under which mirage redistributes the derived code, and the
mirage subdirectories affected.

This file accompanies the project's `LICENSE` (MIT). Inclusion of a
project here does not relicense any mirage-original code.

## cloudflare/quiche — BBRv2 algorithm

- Upstream: https://github.com/cloudflare/quiche
- Upstream license: BSD 2-Clause "Simplified" License
- License compatibility: BSD-2-Clause is permissive and compatible
  with the MIT license that governs mirage.
- Affected paths: `congestion/bbr2/`

The BBRv2 implementation in `congestion/bbr2/` is a Go port of the
Rust BBRv2 implementation in `cloudflare/quiche`
(`quiche/src/recovery/gcongestion/bbr2*`). Algorithm parameters,
state-machine layout, bandwidth sampler, network model, pacer, and
windowed-filter logic all derive from the cloudflare/quiche
reference. Per-file `// src from:` headers point back to the exact
upstream file each port is based on.

```
Copyright (C) 2018-2019, Cloudflare, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
```

### Reference port

The Go translation in `congestion/bbr2/` cross-references the existing
Go BBRv2 implementation in `sing-quic`
(`sagernet/sing-quic/internal/sing-quic/congestion_bbr2/`) for shape
and idiom. The reference is consulted only as documentation; mirage
contains no copied `sing-quic` source. `sing-quic` itself is licensed
GPLv3, which is incompatible with mirage's MIT license, and so was
deliberately not redistributed.
