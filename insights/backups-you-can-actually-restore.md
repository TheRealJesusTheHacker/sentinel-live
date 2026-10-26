---
slug: backups-you-can-actually-restore
date: 2026-10-26
weight: 10
title: Having backups is not the same as having a restore
dek: "An earlier note in this notebook made the general case: a backup you have never restored is a hope, not a backup. This one is narrower — it is how Sentinel runs its own backups, because we hold our own house to the standard we hand everyone else."
---

## How we run our own

Everything Sentinel operates — this website, the
operations platform behind it, and our mail system — runs
on infrastructure we operate ourselves. Every night, each
of the three is backed up on its own schedule, without
anybody having to remember. That is the easy part, and it
is the part most backups stop at. The rest of the system
exists because "the job ran" is not the same as "the data
is safe":

- **Every archive carries a fingerprint of itself.** Each
  backup is built with a manifest — a list of every file
  inside it, with a SHA-256 fingerprint for each one. The
  archive can be checked against its own manifest at any
  time, so integrity is something we verify, not something
  we assume.
- **The check runs itself, monthly.** An automated check
  opens the newest archive in each chain, verifies it
  against its manifest, and writes down the verdict where
  we will see it. A failed check would surface in the same
  daily summary as everything else about the platform's
  health.
- **A copy leaves the box every night.** Each night's
  backup is pulled to a separate machine. A backup that
  only exists on the machine it protects is one incident
  away from being a second copy of the problem.
- **The archives are sealed.** Backups are encrypted as
  they are created. The server holds only the public half
  of the key; the half that opens them is held by the
  owner, off the server entirely — so a stolen archive is
  a sealed envelope, not a filing cabinet.
- **The restore is a drill, on a calendar.** Every
  quarter, the latest backups are restored to scratch
  space and verified, and the results are logged. Before
  encryption was switched on, the full restore path was
  proven with the owner's key on a test archive — and the
  first real archives were opened and checked
  fingerprint-for-fingerprint the same way.

One honest wrinkle, stated plainly because a check that
claims more than it does is worse than a gap: because the
archives are sealed, the monthly check verifies the
envelope — that the ciphertext is intact and matches its
recorded fingerprints. Opening an archive and verifying
its contents is part of the quarterly drill, with the
owner's key. Between the two, nothing about our backups
rests on faith.

## The standard, in one line

A backup system is not the copies. It is the proof —
fingerprinted, sealed, off the box, and restored on a
schedule. That is the standard from [the earlier
note](/insights/backups-you-have-tested), running in our
own house, watched on our own [availability
page](/availability).

**This month's version:** steal the shape, at whatever
scale fits — backups that run on their own, one copy
somewhere else, and one restore you have actually done,
on the calendar to repeat. If you want your own backup
situation audited to this standard, [the contact
page](/contact) is where that starts.
