#!/usr/bin/env bash
# Record the demonstration.
#
#   record/record.sh setup      the build: PKI, DIDs, credentials
#   record/record.sh part1      the happy path, online
#   record/record.sh part2      the happy path, offline
#   record/record.sh part3      revocation, online
#   record/record.sh part4      revocation, offline
#   record/record.sh all        every part, in order
#
# Recording runs inside a container, so the host needs neither asciinema nor ffmpeg. The
# Docker socket is mounted in, because what is being recorded is a sequence of docker
# commands. Each part produces a .cast (exact, tiny, replayable), a .gif, and an .mp4.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/recordings"
IMAGE="${RECORDER_IMAGE:-pki-in-did/recorder}"
COLS="${COLS:-104}"
ROWS="${ROWS:-34}"

mkdir -p "$OUT"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building the recorder image"
  docker build -t "$IMAGE" -f "$REPO/images/recorder/Dockerfile" "$REPO"
fi

# The recorder needs to run docker, so it joins the host's docker group.
docker_gid="$(stat -c %g /var/run/docker.sock)"

record_one() {
  local name="$1" command="$2" title="$3"
  local cast="$OUT/$name.cast"

  echo
  echo "recording $name -> $cast"
  rm -f "$cast"

  # asciinema needs a pseudo-terminal to record. stdin is only attached when this script
  # itself has one, so recording works from a non-interactive shell too.
  local tty_flags=(-t)
  [[ -t 0 ]] && tty_flags=(-i -t)

  docker run --rm "${tty_flags[@]}" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$REPO:$REPO" -w "$REPO" \
    -u "$(id -u):$(id -g)" --group-add "$docker_gid" \
    -e COLUMNS="$COLS" -e LINES="$ROWS" \
    -e TERM=xterm-256color -e HOME=/tmp \
    "$IMAGE" -lc "asciinema rec --overwrite --cols $COLS --rows $ROWS \
        --title '$title' --command '$command' '$REPO/recordings/$name.cast'"

  echo "rendering $name.gif"
  docker run --rm -v "$REPO:$REPO" -w "$REPO" -u "$(id -u):$(id -g)" \
    --entrypoint agg "$IMAGE" \
    --font-size 15 --theme asciinema --speed 1 \
    "$REPO/recordings/$name.cast" "$REPO/recordings/$name.gif"

  echo "rendering $name.mp4"
  docker run --rm -v "$REPO:$REPO" -w "$REPO" -u "$(id -u):$(id -g)" \
    --entrypoint ffmpeg "$IMAGE" \
    -y -loglevel error -i "$REPO/recordings/$name.gif" \
    -movflags faststart -pix_fmt yuv420p \
    -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
    "$REPO/recordings/$name.mp4"

  ls -lh "$OUT/$name".{cast,gif,mp4} | awk '{printf "  %-10s %s\n", $5, $9}'
}

part="${1:-all}"

case "$part" in
  setup)
    # demo/part0-setup.sh, not 00-reset.sh directly: the reset deliberately keeps the root,
    # so on its own it would never show the offline machine that holds the root key.
    record_one part0-setup "PAUSE=0 demo/part0-setup.sh" \
      "PKI in DIDs - part 0, building the PKI, the DID documents and the credentials"
    ;;
  part1)
    record_one part1-happy-online "PAUSE=0 demo/part1-happy-online.sh" \
      "PKI in DIDs - part 1, the happy path online"
    ;;
  part2)
    record_one part2-happy-offline "PAUSE=0 demo/part2-happy-offline.sh" \
      "PKI in DIDs - part 2, the happy path with no network"
    ;;
  part3)
    record_one part3-revocation-online "PAUSE=0 demo/part3-revocation-online.sh" \
      "PKI in DIDs - part 3, revocation online"
    ;;
  part4)
    record_one part4-revocation-offline "PAUSE=0 demo/part4-revocation-offline.sh" \
      "PKI in DIDs - part 4, revocation offline"
    ;;
  part5)
    record_one part5-the-gap "PAUSE=0 demo/part5-the-gap.sh" \
      "PKI in DIDs - part 5, what a conformant verifier does not check"
    ;;
  all)
    "$0" setup
    "$0" part1
    "$0" part2
    "$0" part3
    "$0" part4
    "$0" part5
    echo
    echo "all recordings in $OUT"
    ;;
  *)
    echo "usage: record/record.sh <setup|part1|part2|part3|part4|part5|all>" >&2
    exit 2
    ;;
esac
