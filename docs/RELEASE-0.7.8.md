# DNS Manager v0.7.8 — release notes

Fixes the firewall Apply timeout ("privileged helper unavailable: timed
out") and the overlapping-rollback hazard it could cause. Verified end to end
against real systemd and real UFW in an isolated container, in addition to the
full automated suite.

## What was wrong

Applying a firewall policy talks to the privileged helper over a Unix socket.
That call used the same short 10-second timeout as quick status checks, so a
policy apply that legitimately took longer than 10s returned a 502 while the
helper kept applying rules. The emergency rollback unit was already armed, so
it later restored the previous rules with no one watching. Clicking Apply again
started a second apply and a second rollback on top of the first, so rollbacks
could overlap and snapshot mid-apply state.

Separately, confirming an apply stopped the sleeping rollback unit with SIGTERM,
which systemd recorded as a "failed" oneshot — so every confirmed apply left
another failed unit instance behind.

## Fixes

- Firewall Apply now uses a 45s helper timeout (status calls stay at 10s). If
  it still times out, the error says the outcome is unknown and to check
  firewall and rollback status instead of retrying blindly.
- The rollback unit is scheduled and verified **before** any rule is changed,
  and a schedule failure aborts the apply with the firewall untouched.
- A second Apply is rejected while an earlier one is still awaiting
  confirmation, so two rollbacks can never be armed at once.
- The reported rollback countdown reflects the time already spent applying, so
  a slow apply no longer advertises a fresh full 120s window.
- The rollback unit treats SIGTERM as a clean exit (`SuccessExitStatus=SIGTERM`),
  so confirming an apply no longer accumulates "failed" unit instances.

## Verification

- Real systemd + real UFW end-to-end in an isolated container: apply arms a
  live rollback unit, a concurrent second apply is rejected, confirm stops the
  unit cleanly without failing it, and an unconfirmed apply is genuinely rolled
  back after the window with rules restored.
- Linux container suite: 479 passed, 1 skipped. Browser suite: 18 passed.
- No database migration. Firewall policy behavior, routes, and fields are
  unchanged; only safety and timeout handling changed.

Upgrade with the existing `DNS_MANAGER_INTERNAL_PROXY_IP` and hard-reload the
browser. After upgrading, run `systemctl daemon-reload` so the updated rollback
unit file is picked up before the next firewall apply.
