The offline machine has no image of its own.

It runs the `ca-tools` image with `--network none` and only two directories mounted:
`state/offline` (which holds the root private key) and `state/transfer` (the sneakernet). The
`offline()` helper in `scripts/lib/common.sh` is what starts it.

A separate image would suggest the isolation comes from the image. It does not; it comes from
`--network none` and from mounting that key nowhere else.
