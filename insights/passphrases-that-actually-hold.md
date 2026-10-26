---
slug: passphrases-that-actually-hold
date: 2026-10-26
weight: 20
title: Passphrases that actually hold
dek: Short and complicated feels strong and usually is not — people forced into complexity rules write patterns, and patterns are what attackers model. Length is what actually holds, and the math is not close.
---

## The complexity theater problem

The rules most sites enforce — a capital letter, a number,
a symbol, eight characters — push everyone toward the
same shape: a word, capitalized, with a digit and a symbol
tacked on the end. Attackers know the shape. Their cracking
tools know it too, and they try the patterns first. The
password feels armored and behaves like a screen door,
while the person carrying it cannot remember it — so it
gets reused across accounts, or written down where it can
be found. A password's real strength is not how it looks.
It is how many guesses stand between an attacker and the
right one, and that is mostly a question of length.

## The math, honestly

The [passphrase generator](/tools) on this site draws from
a list of 1,306 words, picking each word uniformly at
random — the same kind of randomness your computer uses
for encryption keys, sampled so every word is exactly as
likely as every other. Each word therefore adds about ten
bits of strength, and the words add up fast:

- **Four words** — roughly 41 bits
- **Five words** — roughly 52 bits
- **Six words** — roughly 62 bits
- **Seven words** — roughly 72 bits

For comparison, an eight-character password drawn truly at
random from every symbol on the keyboard lands near 52
bits too — the five-word line. Same strength, except
nobody can remember the eight characters, and nobody's
hand-picked version of them is truly random. A passphrase
you can say, type, and remember carries its strength
honestly. The generator runs entirely in your browser —
nothing is sent anywhere — and if you add a digit or a
symbol with its toggles, fine; but spend length first. One
more word is worth about ten bits. A symbol is worth a
fraction of that.

One honesty note the tools page states about its own
strength checker, worth repeating here: a checker can only
measure length against the pool of characters used, so
treat any score it gives as the best case. It cannot see
that a phrase is a song lyric or a birthday. That is
exactly why generating beats inventing — a machine drawing
at random does not have favorite words.

## What to do

- **Generate, do not invent.** Use the [generator](/tools)
  or your password manager's, and take six words as the
  working default for anything that matters.
- **One passphrase per account, kept in a password
  manager.** Length only protects you if a breach at one
  site does not hand over the keys to the rest.
- **Put a second step behind it.** Multi-factor
  authentication means a stolen passphrase is a bad day
  instead of a lost account.

**The ten-minute version:** generate a six-word passphrase
for your email account — the one everything else resets
through — put it in a password manager, and turn on the
second step. Then work down the list of accounts that
matter. If you want the whole password situation cleaned
up properly, [the contact page](/contact) is where that
starts.
