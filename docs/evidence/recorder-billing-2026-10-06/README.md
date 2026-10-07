# Recorded billing demo, October 6, 2026

The README's demo GIF. Recorded with [`tools/declass-recorder`](../../../tools/declass-recorder/README.md)
from [`scenes/billing.json`](../../../tools/declass-recorder/scenes/billing.json): the real `declass`
binary ran in a pseudo-terminal on a fresh copy of the [synthetic billing fixture](../../launch/billing-demo/README.md),
with `gpt-6.1-sol` (reasoning effort `medium`) as the frontier model, paid for by a ChatGPT plan
through Sign in with ChatGPT, and `omlx-coding` as the local model.

| Check | Result |
| --- | --- |
| Tests before the session | 1 of 4 failing ([output](check-before.txt)) |
| Tests after the session | 4 of 4 passing ([output](check-after.txt)) |
| Code change | One line in `billing.py` ([patch](change.patch)) |
| Planted values in recorded frontier requests | **0 matches** for 13 complete values in 5 requests |
| Frontier requests | 5, all to `https://api.openai.com/v1` with model `gpt-6.1-sol` |

The recorder saved the terminal bytes, typed input and scene markers (asciicast v2) and a manifest
with the Declass version (0.1.1) and binary hash, the recorder commit
(`22a3d647e916fbae49c460f71d74e378532b418a`), the scene and cast hashes and the playback timing
(369 frames, 30.75 seconds at 12 fps, speeds 1× and 6×); neither file is published. The raw recordings (audit logs, transcripts, terminal casts) were removed before publication because they contained session identifiers and local paths.

The [GIF and MP4](../../assets/demo/) replay those bytes in xterm.js. The published GIF and MP4 were
re-rendered from the original recording with the session ID hidden behind a block of the same
width; the frames are otherwise the same. No other screen text was generated or edited. While the agent works, playback runs at 6× speed, and the window says so. Pauses longer
than 1.5 seconds outside scene holds are shortened. Playback length is not task duration.

The fixture's names, emails, amounts and database password are fictional. The planted-value check
looks for complete values in literal, base64, hex and URL-encoded forms in the recorded request
bodies. It does not detect fragments, paraphrase or inference, and it does not observe the network.

The frontier requests carried the ChatGPT sign-in's access token, which the recording never shows:
the session's terminal output, the cast and the evidence files held no token, email or client id.
The recorder links the owner's sign-in into the recording's throwaway configuration rather than
copying it (a refresh token rotates). At the time of the recording the plan's model list did not
include `gpt-6.1-sol`, but the plan accepted and answered every request for it.

The local model runs on the maintainer's development LAN host. For the recording, the recorder
relayed it through a loopback port and gave Declass a throwaway config pointing there, so the
screen shows `127.0.0.1` rather than the development network. The relay forwards bytes
unchanged: the hop from this machine to that host was still plain HTTP on the LAN
(the manifest recorded this relay).

To make a recording of your own, run the recorder as described in its
[README](../../../tools/declass-recorder/README.md).

The [October 4 recording](../recorder-billing-2026-10-04/README.md) (GLM-5.3 Flash through Z.ai) is kept
as an earlier record.
