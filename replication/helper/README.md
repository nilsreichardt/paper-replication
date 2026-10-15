# Recovered memory helper

`memdump.py` was recovered from a controller log that recorded a successful
download followed by `head -n 50 memdump.py` on 20 May 2026. The output contains
45 lines. Its final 36 lines exactly match the complete upstream helper cited
in the source, ignoring trailing newlines. This establishes that the logged
output contains that complete upstream body plus the nine-line act preamble;
it does not establish which helper revision every historical worker fetched.

The preamble exits successfully without output when `IS_RUNNING_IN_ACT=true`.
Otherwise the Linux helper finds a Runner.Worker process and writes readable
process memory to stdout. The upstream MIT license and credit are preserved.
This is generic harness source, not a generated repository-specific exploit.

The replication tests exercise only the act short-circuit. No memory dumping
is performed on the reviewer's machine. For a full owned-fork verification,
serve this exact file at a reviewer-controlled URL and set
`PWNHUNTER_MEMDUMP_URL`. Configure a reviewer-controlled collector through
`PWNHUNTER_HOOKBIN_URL`; the runner must be able to reach both addresses.
