# Changelog

## [0.3.0](https://github.com/takehaya/goisis/compare/v0.2.0...v0.3.0) (2026-09-22)


### Compatibility notes for Go embedders

* `fib.SIDBehavior` values were renumbered when `BehaviorEndX` was inserted:
  `BehaviorEndDT4`, `BehaviorEndDT6` and `BehaviorEndDT46` each shifted by one.
  The named constants are the contract; anything that persisted or logged the
  numeric value must be re-read against this release.
* The `server.Metrics` interface gained six methods (`PDURx`, `PDUDrop`,
  `AdjacencyCount`, `RouteCount`, `FIBError`, `EventQueueDepth`). Embed
  `server.NoopMetrics` in a custom implementation so later additions stay
  source-compatible.


### Features

* **api:** add, delete prefixes, set overload and clear adjacencies at runtime ([dc2600f](https://github.com/takehaya/goisis/commit/dc2600f19550ec9298e2c79d886a6cb6168f6b99))
* **auth:** accept additional keys on receive for key rotation ([e8c68b3](https://github.com/takehaya/goisis/commit/e8c68b33599447e778783b7898b912ddaefc0f59))
* **cli:** JSON output, database --detail, and hostname resolution ([c2bd181](https://github.com/takehaya/goisis/commit/c2bd1810bd07b6ec080a01591408fa1a447687ee))
* **config:** expose hello timers, padding, prefix metrics and the FIB table ([2336488](https://github.com/takehaya/goisis/commit/23364882f88fd212721cf6bc1c7f786bd29fca35))
* **config:** follow interface address and link events at runtime ([4b48bcc](https://github.com/takehaya/goisis/commit/4b48bccf6d91477bdc30729e832e68edeb882360))
* **goisisd:** serve the management API on a unix socket ([7f7cff4](https://github.com/takehaya/goisis/commit/7f7cff4b3963d61d788d19b590536ff028a85691))
* **metrics:** count drops and receives, expose adjacency, route and queue gauges ([6f277c3](https://github.com/takehaya/goisis/commit/6f277c3976eaa96008b79b8b95f5bc69190fd70a))
* **origination:** coalesce event-driven LSP regeneration and jitter refresh ([d339dcb](https://github.com/takehaya/goisis/commit/d339dcb7c1d915adadc0cdd7dc416bb9f1cd1e73))
* **origination:** propagate Level-1 reachability into the Level-2 LSP ([b6f4bcc](https://github.com/takehaya/goisis/commit/b6f4bcc99cc8b7b6850a36a8fc865ac6aaca5588))
* **origination:** size own LSPs to the smallest circuit MTU ([b54be75](https://github.com/takehaya/goisis/commit/b54be75deb7e2575267e9fa4ca99b51d0f6d3f6c))
* **spf:** hold and coalesce SPF runs after a recompute (RFC 8405-lite) ([86beecc](https://github.com/takehaya/goisis/commit/86beecc6e8cefc1e2bb3b41c4adb5605c9450264))
* **spf:** install a default route from the ATT bit on Level-1-only nodes ([13a9b11](https://github.com/takehaya/goisis/commit/13a9b11c041c08f58d96d2c21bf2569bb40354f0))
* **srv6:** advertise and program End.X SIDs per adjacency ([ab5adab](https://github.com/takehaya/goisis/commit/ab5adab38d272e0adb985596b6e54b4ae783980d))
* **watch:** start a subscription with a gap-free snapshot of current state ([9cc22ae](https://github.com/takehaya/goisis/commit/9cc22aed57a155ab014f7eaa5e5fc71141cfb067))


### Bug Fixes

* **datalink:** retry transient receive errors instead of killing the reader ([c59e341](https://github.com/takehaya/goisis/commit/c59e3411a034798adc0c3b7586a5f62a5174f5d3))
* **flooding:** accept LSPs and SNPs only from Up adjacencies ([04b4fe9](https://github.com/takehaya/goisis/commit/04b4fe9202336d4fa605afa1a756f212b668c25a))
* **flooding:** acknowledge purges for unknown LSPs without storing them ([61c89f1](https://github.com/takehaya/goisis/commit/61c89f1745d10d0074c8d87f814886f5b8b7cea6))
* **flooding:** only the DIS answers PSNP requests on a LAN ([187bd7d](https://github.com/takehaya/goisis/commit/187bd7d2e816b68bea8b36415497ce22f7babfeb))
* **flooding:** purge LSPs that carry our System ID but that we do not own ([f4c3d77](https://github.com/takehaya/goisis/commit/f4c3d7742bdfb034cfa061b3e305b90b77d1a584))
* **flooding:** split CSNPs into per-PDU LSP-ID ranges ([7038371](https://github.com/takehaya/goisis/commit/7038371b0dd3297e5318fc62edfbf20d56382e60))
* **flooding:** stop flooding into p2p circuits without an adjacency ([6000846](https://github.com/takehaya/goisis/commit/6000846e9408ff8137106c37d101ffc7b9695d40))
* **flooding:** synchronize the whole database when a p2p adjacency comes Up ([48b6f1d](https://github.com/takehaya/goisis/commit/48b6f1d3247589c2861de0e3176e08bf3b3b2b4d))
* **hello:** tear down a p2p adjacency on a mismatched echo, drop own-ID hellos ([757aa4b](https://github.com/takehaya/goisis/commit/757aa4bdc1314861a5e2e53180faa758c2276950))
* **rib:** pick an on-link next hop and honor the neighbor's NLPIDs ([657d342](https://github.com/takehaya/goisis/commit/657d342e2c92ebd36b86b8bc989eaebd58b3c72f))

## [0.2.0](https://github.com/takehaya/goisis/compare/v0.1.0...v0.2.0) (2026-07-04)


### ⚠ BREAKING CHANGES

* **goisisd:** goisisd exits at startup when -api-listen is bound beyond loopback and -api-allow-remote is not given; previously it started with a warning.

### Features

* **goisisd:** require -api-allow-remote for non-loopback API binds ([6e64af8](https://github.com/takehaya/goisis/commit/6e64af8748fc2bec70470171d5e155bd1f06e1b9))


### Bug Fixes

* **fib:** match wrapped errnos and reject End.DT46 explicitly ([a0c8241](https://github.com/takehaya/goisis/commit/a0c8241daea7f0fb07cf7eb768d44cdb3dc038e6))
* **packet:** preserve unknown SRv6 sub-TLVs and reject duplicate auth TLVs ([36de646](https://github.com/takehaya/goisis/commit/36de6468d9c2ede0b32b4d8724daace74c5b1fd6))
* **server:** header-only expiry purges, LSDB entry cap, fragment guards ([eccd5ba](https://github.com/takehaya/goisis/commit/eccd5baeccf44c65f0839677a3103fcf8644c128))

## 0.1.0 (2026-06-19)


### ⚠ BREAKING CHANGES

* **api:** the RPC package is goisis.v1; clients built against goisis.v1alpha1 must regenerate.

### Features

* **api:** Add/Delete locator and Flex-Algo RPCs and CLI subcommands ([cd1509e](https://github.com/takehaya/goisis/commit/cd1509eeda3cf0d6f5bc37c842b43f87a3aaec0d))
* **api:** promote the management API to v1 ([97bd007](https://github.com/takehaya/goisis/commit/97bd0070ed550cc05d7775b18e30fbd061d7d333))
* **config:** declarative prefix-list route policy ([0a82d81](https://github.com/takehaya/goisis/commit/0a82d8150e25ac50c82d8c9900cd116c14d3892a))
* Connect RPC read API, WatchEvent streaming, and the goisis CLI ([434e082](https://github.com/takehaya/goisis/commit/434e082f7e45964aff0130db2327c8c7855fa54e))
* expose SRv6 locators and Flex-Algo over the Connect API and CLI ([0e92e7a](https://github.com/takehaya/goisis/commit/0e92e7a5fd1d34c59f07dab846899b2496f33c94))
* Flex-Algo definition, election, and per-algorithm SPF (RFC 9350) ([e90c66a](https://github.com/takehaya/goisis/commit/e90c66a0924b3e1241f30d28c6a6db5f9655cf33))
* HMAC-MD5 hello authentication (RFC 5304), wire-compatible with FRR ([018062c](https://github.com/takehaya/goisis/commit/018062c6111bfd5da5f72f6225b2f08e866b5418))
* HMAC-MD5 LSP/SNP authentication (RFC 5304 area/domain password) ([34820ce](https://github.com/takehaya/goisis/commit/34820ce9a4d240df2bb8dd164fd17a2f5561d4a3))
* HMAC-SHA authentication (RFC 5310 generic cryptographic auth) ([2f6da1e](https://github.com/takehaya/goisis/commit/2f6da1e6706a92c50125d9528a9e29ed6735e510))
* **packet:** IS-IS PDU and TLV codec with FRR golden tests ([a1c1e2e](https://github.com/takehaya/goisis/commit/a1c1e2eea965cf4b9df259946deb5d254aa9426b))
* Prometheus metrics for adjacencies, SPF, LSDB, and flooding ([8db6ec1](https://github.com/takehaya/goisis/commit/8db6ec1b264883a4d305a1af8b58c6cd4e75dd37))
* scaffold daemon, CLI, library API, and release automation ([a87f4dd](https://github.com/takehaya/goisis/commit/a87f4dd307fd2db133cb371138a0953b78483dc2))
* **server:** data-link layer, adjacency FSM, and DIS election ([9575d80](https://github.com/takehaya/goisis/commit/9575d80b0fb08989e9881952e339490100419405))
* **server:** export and FIB route-policy filters ([7f28ed3](https://github.com/takehaya/goisis/commit/7f28ed3d0b8855737b08c92914637b751f3cd6a2))
* **server:** LSP fragmentation across fragment numbers 1..255 ([2f9c1a6](https://github.com/takehaya/goisis/commit/2f9c1a648ad62fc2307d42141fbd0f1df125f7d9))
* **server:** LSP origination, flooding, CSNP/PSNP sync, and lifetime ([99a02db](https://github.com/takehaya/goisis/commit/99a02db9407f65cd27b05cf5ceb07e3723873f08))
* **server:** overload-on-startup and clean-shutdown LSP purge ([7bb77f4](https://github.com/takehaya/goisis/commit/7bb77f400d5a52e12beca0c50e0bf5bd80ec1c39))
* **server:** runtime mutators for SRv6 locators and Flex-Algos ([d4a3969](https://github.com/takehaya/goisis/commit/d4a396907adf5b220207836daa461a61f5d37a33))
* **server:** SPF, RIB, prefix origination, and netlink FIB ([4d0ac1f](https://github.com/takehaya/goisis/commit/4d0ac1f17f0556b0df4d0a15c75c21a4ec5d958b))
* SRv6 locator advertisement, learning, and End SID programming ([9b6eac8](https://github.com/takehaya/goisis/commit/9b6eac83cc6f88cb09b39908fe835e2478653184))


### Bug Fixes

* address whole-codebase review findings (adjacency, flooding, RIB, lifecycle) ([2dcbceb](https://github.com/takehaya/goisis/commit/2dcbceb610901d1df05641b819bacfe55e1223b4))
* authenticate over the declared PDU length, not the padded frame ([00b8620](https://github.com/takehaya/goisis/commit/00b8620b24956975ef6a9a182dfa32bc35a18a6a))
* **flooding:** validate received-LSP checksum over wire bytes, not a re-serialization ([b19e9d0](https://github.com/takehaya/goisis/commit/b19e9d0c2d2c6846a421c6c9c2ebefbcaa2f52a6))
* **origination:** split oversize reachability across multiple TLVs ([ae9aead](https://github.com/takehaya/goisis/commit/ae9aead7485d55e79fe08e35dd787c191c80bcbc))
* **packet:** rename misleading up/down reach bit; reject trailing octet in SRv6 walks ([82c1910](https://github.com/takehaya/goisis/commit/82c191048edc33238176507f259d1b6e06e4f0d7))
* **release:** build goisisd Linux-only and re-cut 0.1.0 ([a521832](https://github.com/takehaya/goisis/commit/a521832755867017ebae0ad5e51ad15c2b739290))
* **release:** goisisd Linux-only build; reset manifest to re-cut 0.1.0 ([744eeb4](https://github.com/takehaya/goisis/commit/744eeb4af28e0c275a9294aaf52c8fed6a53fc5e))
* **release:** split archives per binary; re-cut 0.1.0 ([4ad8f5c](https://github.com/takehaya/goisis/commit/4ad8f5cbe5a8d58042a94d0a34889af4a7befa6f))


### Miscellaneous Chores

* cut the first release as 0.1.0 ([37e2feb](https://github.com/takehaya/goisis/commit/37e2febaf95ee6bead3424895dec394e92e52f16))
