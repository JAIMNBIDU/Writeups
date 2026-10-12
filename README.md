# Security Writeups

Offensive security labs, documented with the defensive half attached.

Most writeups stop at the screenshot of domain admin. These don't. Every attack here is mapped to what it leaves behind: the Windows Event IDs, the service and registry artifacts, the network signals a defender would actually use to catch it. The dead ends and tooling errors stay in, because the clean version is a lie and the mistakes are the part worth keeping.

I work toward detection engineering and red teaming. This is where the two meet.

## Index

| Writeup | Environment | Chain | Detection focus |
|---|---|---|---|
| [MARVEL.local — Full AD Compromise](./marvel-ad-compromise) | 4-machine Active Directory (TCM / PNPT) | LLMNR poisoning → NTLM relay → pass-the-hash → Kerberoast → PsExec → token theft → DCSync | Event IDs and SOC signals per step |

More labs documented the same way are on the way.

## How these are written

- **Backwards from detection.** The attack is the easy half. Each step is paired with the signal that exposes it, so the writeup is useful to both sides of the wire.
- **Errors left in.** Wrong guesses, broken tooling, a payload fired at my own box. Deleting mistakes from a writeup is just how you guarantee you relearn them later.
- **Observed vs inferred vs confirmed, stated plainly.** No dressing up a dead branch as the path that worked.

## Note

Every environment here is an intentionally vulnerable training lab. All credentials, hashes and keys shown belong to throwaway lab machines and are worthless outside them. Nothing in this repository comes from a real engagement.
