# Changelog

## [0.6.1](https://github.com/takehaya/goisis/compare/v0.6.0...v0.6.1) (2026-09-24)


### Bug Fixes

* **config:** stop a refused reload rebuilding a circuit that already matches ([cccdb2a](https://github.com/takehaya/goisis/commit/cccdb2a8e4eab53e8bb8d712b67e512bbb29d419))
* **config:** validate a circuit the way a restart validates it ([7d4da4a](https://github.com/takehaya/goisis/commit/7d4da4a4677cb41d2ca578abed46ee38c5979f4a))
* **server:** compare a circuit, and own the transport on every path ([2bbb541](https://github.com/takehaya/goisis/commit/2bbb541f157a688f443aa8b620096f3eb2e3dad0))
* **server:** flush a deleted circuit's purge where it can still be sent ([d179155](https://github.com/takehaya/goisis/commit/d179155307661cba9ffb2228e0f9d2440659c577))
* **server:** refuse a duplicate circuit name at startup, and say what a ([e436bf4](https://github.com/takehaya/goisis/commit/e436bf431754243b664fc52a6af2bd979c6d0a8f))

## [0.6.0](https://github.com/takehaya/goisis/compare/v0.5.0...v0.6.0) (2026-09-24)

### Upgrade notes for operators

* Startup now refuses a `prefixes:` entry that no unicast forwarding entry can
  serve — multicast, unspecified, link-local, IPv4-mapped — or one whose metric
  is at the RFC 5305 reachability ceiling. Through 0.5.0 only `goisis prefix
  add` refused these, so a file carrying one started and then could not be
  reloaded. Remove the entry or give it a usable metric.
* A configuration file holds one YAML document. Anything past a `---` separator
  was being dropped in silence, including a correctly spelled `area-password`,
  so it is now a load error. A leading separator is still one document.
* A circuit can be added or removed with `SIGHUP`. A circuit whose settings
  change is rebuilt rather than mutated, so **its adjacency drops and re-forms**;
  the reload warns by name before it happens.
* `goisis route` prints a `PREF` column, between `ALGO` and `METRIC`, naming
  the preference class the route was selected on. Everything from `METRIC`
  rightwards moves one column, so a script reading the table by position reads
  the wrong field. `-o json` is the form that does not move.
* `goisis flex-algo` prints a `CONSTRAINTS` column, before `PARTICIPANTS`,
  carrying the elected definition's constraint sub-TLVs. `PARTICIPANTS` moves
  one column for the same reason, and `-o json` is again the form that does not.

### Compatibility notes for Go embedders

* The `server.Metrics` interface gained `ConfigReloadUnapplied` and
  `ForgetCircuit`. An implementation that embeds `server.NoopMetrics` is
  unaffected; one that does not needs both methods.
* `config.WatchInterfaces` no longer takes a `*Config`. It reads the circuit set
  from the server, because a startup snapshot stops being correct once circuits
  change at runtime.


### Features

* **cli:** show the preference class a route was selected on ([4bd0927](https://github.com/takehaya/goisis/commit/4bd092752c68dd53492509008213e746b2a90743))
* **config:** add and remove circuits on SIGHUP ([25e7f31](https://github.com/takehaya/goisis/commit/25e7f31d4c499ebdf0ea62f04ba6a33455869c33))
* **metrics:** count the differences a reload left for the next restart ([1d3b37c](https://github.com/takehaya/goisis/commit/1d3b37c63218697008aa24f9898e6118b49e7e0e))
* **server:** add a circuit at runtime ([0dc8d2f](https://github.com/takehaya/goisis/commit/0dc8d2f7a978e6eae1e693f4a23a9aca6ebbe1b9))
* **server:** remove a circuit at runtime ([f315b21](https://github.com/takehaya/goisis/commit/f315b21ffdd83baddc1f0141d07b2630b02fa051))


### Bug Fixes

* **config:** bound the reload's outcome report separately from its apply ([81c7d7d](https://github.com/takehaya/goisis/commit/81c7d7d9dce4f2eff2a43b785a85201785d43387))
* **config:** build the parse error from parts instead of redacting one ([6e8fec9](https://github.com/takehaya/goisis/commit/6e8fec951246c6eecaf702d6f547300bbdb83adc))
* **config:** let a refused reload be repaired by the next signal ([f92e5e4](https://github.com/takehaya/goisis/commit/f92e5e4264b5471f7e9f333084d8fcec7f96ad40))
* **config:** validate a reload the way a restart validates ([b485c75](https://github.com/takehaya/goisis/commit/b485c758fd4d1868e4031f88728e04bf008b84a4))
* **flexalgo:** report the elected definition's constraints ([abd37d0](https://github.com/takehaya/goisis/commit/abd37d05632df94552a79fcf1f2f08104979a435))
* **rib:** ignore the up/down bit in a Level-2 advertisement ([04a101b](https://github.com/takehaya/goisis/commit/04a101b722e1896af21ffff46c8ed7a6b3ee512c))
* **spf:** rank the ATT-derived default below any advertised default ([699f680](https://github.com/takehaya/goisis/commit/699f68040e182b0a79a1d79a76b8d20b869e0f11))

## [0.5.0](https://github.com/takehaya/goisis/compare/v0.4.0...v0.5.0) (2026-09-24)


### Upgrade notes for operators

* A key the configuration schema does not define is now a load error, so a file
  that started under 0.4.0 can stop `goisisd` from starting, and `SIGHUP`
  refuses it rather than applying part of it. The silence this replaces is what
  it was for: a transposed `area-pasword` left the node unauthenticated with
  nothing to report it. It also ends YAML anchors as an idiom, since an anchor
  block is an undefined key. Comment the key out or delete it.


### Features

* **goisisd:** apply the runtime-capable part of a config change on SIGHUP ([099f7de](https://github.com/takehaya/goisis/commit/099f7de030dc247770ae54a4b4eaf54d62a50b11))
* **metrics:** count reload outcomes, floored lifetimes and inter-level prefixes ([dd0fb51](https://github.com/takehaya/goisis/commit/dd0fb5176ca10a03cee58bab6d14280dcdb939fb))
* **origination:** leak Level-2 prefixes into Level-1 behind a policy ([c6e96bd](https://github.com/takehaya/goisis/commit/c6e96bd3a794567ba1eafadb2ada0f2fc9ab138b))


### Bug Fixes

* **config:** validate a reload before it mutates, and keep the baseline when one is refused ([e3595de](https://github.com/takehaya/goisis/commit/e3595def04a7221d49021e4bea3dc0e0bca39e89))
* **lsdb:** hold a received LSP's lifetime at MaxAge (RFC 7987) ([96d1a86](https://github.com/takehaya/goisis/commit/96d1a862d76e7584b0a253d1ba5186a59d1ea67b))
* **rib:** rank a leaked Level-1 route below a Level-2 route (RFC 5302 3.2) ([7c56add](https://github.com/takehaya/goisis/commit/7c56addf1669134007eebf72ef451f6ce6cbc6e5))
* **server:** clamp the leaked metric where it reaches the wire, and bound a reload ([325c821](https://github.com/takehaya/goisis/commit/325c82103464f9953a6567bd0a575f6f325a3dce))
* **spf:** keep the winning advertisement's up/down bit instead of a sticky merge ([5996f4a](https://github.com/takehaya/goisis/commit/5996f4a49bd0b7b9058c9a3cf09f454683438525))

## [0.4.0](https://github.com/takehaya/goisis/compare/v0.3.0...v0.4.0) (2026-09-23)


### Features

* **metrics:** count the receive, transmit and hello paths that failed silently ([656f63b](https://github.com/takehaya/goisis/commit/656f63b78b8be0d57defe8827b8c95ef3f5b417a))
* **origination:** advertise our global IPv6 addresses in the node LSP ([345c16b](https://github.com/takehaya/goisis/commit/345c16b3e51bc3277e8c6c4fae9f5be32eab3a6a))
* **server:** cap adjacencies per circuit and slow the local SID re-assert ([3dbccd7](https://github.com/takehaya/goisis/commit/3dbccd73da8f65480d4faf02d1c652e7104be50d))


### Bug Fixes

* **auth:** reject accept-password lists configured without a primary password ([31e2499](https://github.com/takehaya/goisis/commit/31e24990ce51db5d22ad652f4066f6ea190c657c))
* **config:** stop the interface watcher from panicking or spinning when netlink closes ([b8082c3](https://github.com/takehaya/goisis/commit/b8082c391ccef319b84f9eca681de4479cda5e49))
* **fib:** give IS-IS routes a non-zero metric so they cannot replace connected routes ([590f4f7](https://github.com/takehaya/goisis/commit/590f4f71fd14e169af31362d5a14b227f1612b4f))
* **fib:** install local SIDs on a dummy device instead of the loopback ([21c0d3a](https://github.com/takehaya/goisis/commit/21c0d3ac024d6f8fd3bed5272347ac7f1762b45d))
* **flooding:** count LSPs dropped for exceeding a circuit MTU and re-arm the warning ([32bf592](https://github.com/takehaya/goisis/commit/32bf592c21c1126edeafad158f06d96a078761eb))
* **flooding:** pace the whole-database sync and hold down a flapping peer ([6dbbdee](https://github.com/takehaya/goisis/commit/6dbbdee7120625151ae7209d0c183725be45aff4))
* **flooding:** purge forged LSPs naming us and handle sequence-number exhaustion ([a3de360](https://github.com/takehaya/goisis/commit/a3de360b36915f5c195d03663b5bcd24ee17e66f))
* **goisisd:** close the API listen gate and validate runtime prefixes ([abf6e4e](https://github.com/takehaya/goisis/commit/abf6e4e7b334b12719940acf97e2d9d8deb77b9a))
* **hello:** split the IS Neighbors TLV so a LAN with 43 stations keeps sending hellos ([70c853d](https://github.com/takehaya/goisis/commit/70c853d0461dccbc670c446c3f86f67b9190a77f))
* **origination:** apply the advertise policy to Level-1 prefixes exported into Level-2 ([b472d0c](https://github.com/takehaya/goisis/commit/b472d0c7990f7b25d18be1b36840074f48b00631))
* **server:** compare circuit addresses as sets when deciding a no-op ([4cfe0a1](https://github.com/takehaya/goisis/commit/4cfe0a1bcb29528d89acd6ec45d0c0dd65459bf2))
* **server:** give originated prefixes a single owner ([c9ed9d7](https://github.com/takehaya/goisis/commit/c9ed9d7850563fcea46ca3cc7c4331b509ee6590))
* **server:** retry failed FIB writes on the tick and re-read interfaces periodically ([a78c207](https://github.com/takehaya/goisis/commit/a78c207b6fd0e7a582ad5799365780775c4f30f6))
* **server:** sanitize peer hostnames before they reach the management API ([d24dc7d](https://github.com/takehaya/goisis/commit/d24dc7d8821d4ca8bc98c36b753ec352d8bda27d))
* **spf:** compute our own paths from live adjacencies, not from the stored LSP ([32a6f42](https://github.com/takehaya/goisis/commit/32a6f42d3c43e4b0ba354bbdc5f886b97558feb7))
* **srv6:** allocate Flex-Algo End.X SIDs only toward participating neighbors ([6c38263](https://github.com/takehaya/goisis/commit/6c38263003175ce534c996f6b3f690489124b977))
* **srv6:** count End.X FIB failures and retry the writes that failed ([ee0b93a](https://github.com/takehaya/goisis/commit/ee0b93a676c09a817fc03cd0f0028f8472662816))
* **srv6:** forward End.X SIDs to an on-link global address, or do not advertise them ([275de6d](https://github.com/takehaya/goisis/commit/275de6dc8d8839360f298996ee2e5a8079cf6b1a))
* **watch:** resolve hostnames in a subscription's initial snapshot ([d2f7cd0](https://github.com/takehaya/goisis/commit/d2f7cd0bee60090206d4fd412b89f27d79babea8))


### Performance Improvements

* **server:** copy state on the management loop and render off it ([80c545b](https://github.com/takehaya/goisis/commit/80c545b3636bfb1ccb7bb928c8f235930ed91d69))

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
