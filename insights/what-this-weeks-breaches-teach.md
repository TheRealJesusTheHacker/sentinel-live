---
slug: what-this-weeks-breaches-teach
date: 2026-10-26
weight: 50
title: What this week's breaches teach a small business
dek: "Four items from this week's security reporting, none of them about a business your size — and every one of them carrying a lesson that scales down: a token is a key, patching is not the same as cleaning up, and the patch clock runs in days."
---

## This week's reporting

### A door left open inside the fence

Researchers at Cyberdione Labs, in findings reported by
ThaiCERT, described a flaw they call Tailworm in
Tailscale, a popular tool that links a company's machines
into one private network. As reported, an attacker who
compromises a single device inside that network can use
its SSH forwarding feature to reach root — full control —
on other machines in the same network. The reporting names
current builds as affected (Tailscale 1.104.2 and
Headscale 0.29.5) and notes that no patch was available
yet at the time of the report.

The lesson is not about one product. It is about features
that move access around. SSH forwarding is a convenience —
leave it off unless you actually use it, on any tool that
connects your machines to each other. A private network is
a trust network: its weakest device is a door to all the
rest.

### Stolen keys, quietly used

Wiz reports a campaign its researchers call Gheist:
attackers holding stolen GitHub access tokens used them
to push malicious workflows through GitHub Actions inside
private repositories — then deleted the tracks, so the
break-ins hid in the one place nobody thought to look.

The lesson: a token is a key to the kingdom. It does not
knock or pick the lock; it walks in as you. Keys like
these should be scoped to the least they need, rotated on
a schedule, and retired the moment nobody can say what
they are for — and someone should be reading the audit
logs, because deleted tracks are themselves a tell.
Private does not mean safe when the key is already out.
The same goes for API keys and app passwords in any tool
you run: the forgotten ones are the ones that get used.

### Already inside before the patch existed

The Hacker News reports that attackers planted web
shells — hidden doors of their own — on servers running
Nextcloud with its Collabora office integration *before*
the underlying flaw was public. When the emergency patch
arrived, the systems that took it closed the door
correctly. The intruder was already in the house.

The lesson is the hardest one on this page: **patching is
not remediation.** After an emergency patch on anything
internet-facing, the work is only half done. Hunt — look
for accounts, files, and changes you do not recognize —
and rotate the credentials that system held. If you cannot
hunt it yourself, that is the moment to get help, not the
moment to relax.

### The clock

This week CISA added more flaws — including flaws in Plex
software and in Siemens' Software Center — to its Known
Exploited Vulnerabilities catalog, the federal must-patch
list. A place on that list means the flaw is not
theoretical: it is being exploited, and federal agencies
work to deadlines measured in days.

The lesson is the one from [Patch day is today
now](/insights/patch-day-is-today), unchanged: attackers
automate the hunt for unpatched systems the moment a flaw
is public, and a small business is found by the same
machines. Your patch clock is the same clock.

## What to do

- **Turn off connection features you do not use.** SSH
  forwarding is this week's example; every tool that links
  your machines has two or three like it.
- **Inventory your keys.** Access tokens, API keys, app
  passwords — scope them down, rotate them, delete the
  forgotten ones, and glance at the audit logs after.
- **After an emergency patch, hunt and rotate.** Patched
  is step one. Clean is a separate claim, and it takes
  evidence.
- **Keep automatic updates on, and restart.** The
  must-patch clock runs in days now, and an update that
  never got its restart has not happened yet.

**This week's version:** pick the one that fits your
house — the forwarding feature, the forgotten token, the
server that has been "about to restart" since September —
and close it today. If any of it wants a second set of
eyes, [the contact page](/contact) is where that starts.
