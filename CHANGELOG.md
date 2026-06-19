# Changelog

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


### Miscellaneous Chores

* cut the first release as 0.1.0 ([37e2feb](https://github.com/takehaya/goisis/commit/37e2febaf95ee6bead3424895dec394e92e52f16))
