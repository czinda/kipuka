# EDA eviction demo — "the day it works," recorded

Records the talk's payoff sequence: a compromised Windows domain
controller is detected, its certificate is revoked by the CA, and the
host is isolated by Event-Driven Ansible. Target length: 3 minutes.

## What runs in the recording

1. The DC holds a certificate issued by the kipuka demo CA (KDC
   Authentication EKU, DC FQDN plus domain DNS name in the SAN).
2. A detection alert fires (webhook) into the ansible-rulebook.
3. The rulebook runs `playbooks/evict_dc.yml`, which:
   - looks up the certificate serial for the DC subject,
   - revokes it via `POST /admin/certs/{serial}/revoke`,
   - fetches the regenerated CRL and shows the serial on it,
   - isolates the host (lab-safe: `win_firewall_rule` on the DC blocking
     all inbound except the management path; swap in switch-port or
     ACL automation where real network gear exists),
   - verifies the result: certificate status revoked, LDAPS refused.
4. The timeline on screen matches the talk's slide: detect, revoke,
   isolate, refuse — with real timestamps.

## Prerequisites

- A Windows Server VM acting as a domain controller (lab). `dc/dc.inf`
  is the certreq INF for its certificate under the demo CA.
- The kipuka demo server running (`../run.sh --keep`), plus a CA profile
  that carries the KDC EKU and the domain SAN (see `dc/README`).
- `ansible-rulebook`, `ansible`, and the `ansible.windows` collection on
  the control node.
- A screen recorder. Record at 2026-11 timestamps; the talk shows
  02:14-02:19, the recording shows the real clock.

## Run

```bash
# terminal 1: the CA (from demo/)
./run.sh --keep

# terminal 2: the rulebook (from demo/eda/)
ansible-rulebook --rulebook rulebook.yml --inventory inventory.yml

# terminal 3: play the compromised DC
curl -X POST http://localhost:5000/events -H 'Content-Type: application/json' \
  -d '{"alert": "compromise-indicators", "host": "dc01.demo.kipuka"}'
```

## Honesty rules for the recording

- Show the approval gate, not just auto-action: narrate that
  production-critical eviction is staged behind a human decision, and
  say what is automated here (revocation, status flip) versus staged.
- Show the signing-cycle interval honestly if status checking appears.
- No cuts that hide a failure. If a beat fails, fix it and re-record
  the whole sequence; the credibility of this demo is that it is real.

## Fallback

If this is not recorded by Nov 24, the abstract's demo sentence swaps to
the STAR-loop recording (one command: `../run.sh --no-pause`) before
submission. The abstract must not promise an unrecorded demo.
