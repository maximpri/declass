# Recorded billing demo, October 4, 2026

The README's demo GIF until the [October 6 recording](../recorder-billing-2026-10-06/README.md) replaced it. Recorded with [`tools/declass-recorder`](../../../tools/declass-recorder/README.md)
from [`scenes/billing.json`](../../../tools/declass-recorder/scenes/billing.json): the real `duet`
binary ran in a pseudo-terminal on a fresh copy of the [synthetic billing fixture](../../launch/billing-demo/README.md),
with `glm-5.3-flash` as the frontier model and `omlx-coding` as the local model.

| Check | Result |
| --- | --- |
| Tests before the session | 1 of 4 failing ([output](check-before.txt)) |
| Tests after the session | 4 of 4 passing ([output](check-after.txt)) |
| Code change | One line in `billing.py` ([patch](change.patch)) |
| Planted values in recorded frontier requests | **0 matches** for 13 complete values in 5 requests |
| Session cost shown by Duet | $0.0016 (frontier tokens at catalog rates; local model at zero) |

The recorder saved the terminal bytes, typed input and scene markers (asciicast v2) and a manifest
with the Duet version (0.1.0) and binary hash, the recorder commit
(`89213d4c1e421fea99c5c90c64135bcdb3e281e9`), the scene and cast hashes and the playback timing
(411 frames, 34.25 seconds at 12 fps, speeds 1× and 6×); neither file is published. The raw recordings (audit logs, transcripts, terminal casts) were removed before publication because they contained session identifiers and local paths.

Its GIF and MP4 replayed those bytes in xterm.js; the [October 6 recording](../recorder-billing-2026-10-06/README.md)
replaced them in `docs/assets/demo`, and they are not published. No screen text was generated or
edited. While the agent works, playback runs at 6× speed, and the window says so. Pauses longer
than 1.5 seconds outside scene holds are shortened. Playback length is not task duration.

The fixture's names, emails, amounts and database password are fictional. The planted-value check
looks for complete values in literal, base64, hex and URL-encoded forms in the recorded request
bodies. It does not detect fragments, paraphrase or inference, and it does not observe the network.
The local model runs on the maintainer's development LAN host. For the recording, the recorder
relayed it through a loopback port and gave Duet a throwaway config pointing there, so the
screen shows `127.0.0.1` rather than the development network. The relay forwards bytes
unchanged: the hop from this machine to that host was still plain HTTP on the LAN
(the manifest recorded this relay).

To make a recording of your own, run the recorder as described in its
[README](../../../tools/declass-recorder/README.md).
