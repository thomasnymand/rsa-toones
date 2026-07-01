```
 ____  ____    _         _____ ___   ___  _   _ _____ ____
|  _ \/ ___|  / \       |_   _/ _ \ / _ \| \ | | ____/ ___|
| |_) \___ \ / _ \        | || | | | | | |  \| |  _| \___ \
|  _ < ___) / ___ \       | || |_| | |_| | |\  | |___ ___) |
|_| \_\____/_/   \_\      |_| \___/ \___/|_| \_|_____|____/

        turn your keypair into a chiptune  •  LOAD"*",8,1
```

# RSA-TOONES

> *"Every key is already a song. Most of them are just badly produced."*

`rsa_music.py` takes an RSA keypair — a PEM, or a whole PKCS#12 identity — and
renders it as **music**: a Standard MIDI File and, if you want, a 16-bit WAV
synthesized from scratch. No `mido`, no `pycryptodome`, no `numpy`, no
soundfont. Pure Python stdlib. The way SID intended.

It sounds like a Commodore 64 having an existential moment about number theory,
because that is exactly what it is.

---

## Why

Because a 2048-bit modulus is 256 bytes of high-entropy sadness sitting in a
`.pem` file that nobody will ever *feel*. RSA is beautiful — two primes go in, a
one-way street comes out — and yet we render it as base64. Base64! The nerve.

So this maps the actual guts of the key onto a scale and lets you hear it:

| Voice        | Derived from                | Vibe                              |
|--------------|-----------------------------|-----------------------------------|
| **Melody**   | modulus `n`                 | the public face of your identity  |
| **Bass**     | primes `p XOR q`            | the secret foundation             |
| **Harmony**  | private exponent `d`        | pad or arpeggio                   |
| **Drums**    | `SHA-256(n)` prefix         | a groove unique to the key        |

### The "Keypair Duet" conceit

The melody comes from `n`, which is *public* — so anyone with your public key
can play the tune. But the bass and harmony come from `p`, `q`, and `d`, which
are *private*. Only the holder of the secret key can render the full
arrangement underneath the melody. It's a zero-knowledge jam session: the world
hums your hook, but only you know the changes.

(And because `n` is shared between the public and private key, the melody line
is byte-identical whether you feed it `pub.pem` or `priv.pem`. Consistency! In
*this* economy!)

> ⚠️ **Cryptographer's disclaimer, delivered through gritted teeth:** this is a
> toy. It is deterministic, which is the *only* nice thing you can say about it
> security-wise. It is **not** a KDF, **not** a commitment scheme, **not**
> steganography you should trust, and rendering your production signing key as a
> catchy 8-bit banger is an *exfiltration primitive*, not a party trick. The
> modulus is public anyway; the melody leaks nothing new. The bass, however,
> is literally `p XOR q` mapped to a pentatonic scale — recovering the primes
> from the audio is left as an exercise for a bored adversary with a tuner.
> **Don't toonify keys you actually care about.** Generate a throwaway.

---

## Install

There is no install. This is 1987. You have Python 3 and, for `.p12` bundles,
`openssl` on your `PATH`. That's the whole bill of materials.

```sh
git clone git@github.com:thomasnymand/rsa-toones.git
cd rsa-toones
```

PEM parsing (PKCS#1, SPKI, PKCS#8) is done by hand with a ~40-line DER walker,
because pulling in a dependency to read four integers is how you end up with a
`node_modules` the size of the C64's entire addressable memory, times a million.

---

## Quick start

Make a throwaway keypair (say it with me: **throwaway**):

```sh
openssl genrsa -out priv.pem 2048
openssl rsa -in priv.pem -pubout -out pub.pem
```

Hear the public melody:

```sh
python3 rsa_music.py --public pub.pem --wav theme.wav
```

Hear the full duet (needs the private half):

```sh
python3 rsa_music.py --private priv.pem --wav duet.wav
```

Feed it a whole identity bundle:

```sh
python3 rsa_music.py --p12 id.p12 --password hunter2 --wav id.wav
```

---

## Make it sound like a real 8-bit classic

The defaults are pretty and polite. That is not what we are here for. Stack the
effects:

```sh
python3 rsa_music.py \
  --p12 id.p12 --password hunter2 \
  --8bit \                 # pulse + triangle + LFSR noise, bit-crushed
  --arp \                  # arpeggiate the harmony into chiptune "chords"
  --arp-hz 15 \            # arp speed in Hz (see below)
  --drums \                # noise-channel beat seeded by SHA-256(n)
  --portamento 0.05 \      # glide between notes
  --tempo 128 \
  --wav banger.wav
```

> 🎛️ **The house mix (author's preferred settings).** After far too much
> A/B-ing, this is the combo that reliably slaps — melody arps at a rate where
> the chord tones dance, a shuffle so the line breathes instead of marching,
> and the key's own drummer. No glide; keep it crisp:
>
> ```sh
> python3 rsa_music.py --private priv.pem \
>   --8bit --arp-melody --arp-hz 25 --swing 0.4 --drums --tempo 128 \
>   --wav banger.wav
> ```
>
> Swap `--private priv.pem` for `--p12 id.p12 --password …` to feed it a whole
> identity. Crank `--arp-hz` toward 60 if you want full per-frame chaos, or add
> `--portamento 0.05` back in if you like it slippery.

### `--8bit` — the chip

Swaps the warm additive sine voices for the real hardware religion: a **pulse
wave** lead (adjustable duty), an **NES-style triangle** bass, and **15-bit
LFSR noise** for percussion, all run through a 3–4-bit amplitude crush. The
`--8bit` MIDI also remaps to square/synth-bass/saw GM programs so it stays
crunchy in a regular player.

### `--arp` / `--arp-melody` — faking chords like it's 1985

A single pulse channel can't play a chord, so the classics *cheated*: cycle one
voice through the chord tones fast enough that your ear fuses them into a buzzy
shimmer. That's an **arpeggio**, and it's the single most recognizable trick in
the chiptune canon.

`--arp` does it to the harmony; `--arp-melody` does it to the melody instead.

### `--arp-hz` — the whole reason this section exists

Real hardware arps ran at the **video frame rate** — one note per frame, ~50 Hz
(PAL) or ~60 Hz (NTSC) — which is *fast*, tempo be damned. So arp speed here is
an **absolute rate in notes/second**, not a note value:

- `--arp-hz 60` → true per-frame NTSC buzz
- `--arp-hz 30` → half-frame, still shimmering
- `--arp-hz 15` → you can hear the individual chord tones dance
- *(omit it)* → sensible tempo-relative 16th notes

Crucially, changing the rate **subdivides the same time window** — faster means
*more* notes packed in, not a shorter song. The tune stays the same length; it
just gets buzzier.

### `--drums` — the noise channel

An extra percussion track: **kick** (a pitch-dropping triangle blip), **snare**
and **hats** (LFSR noise bursts, the 2A03's fourth channel). The 16-step
pattern is seeded from the first four bytes of `SHA-256(n)`, so the *groove is a
fingerprint of your key* — a downbeat backbone keeps it musical, the hash drives
the fills. Different modulus, different beat. (We seed from the hash rather than
`e`, because `e` is 65537 for basically everyone and everyone deserves their own
drummer.)

### `--swing` — make the arp breathe

A uniform arp marches like a metronome. `--swing AMOUNT` (0..0.9) alternates
**long–short** note lengths for a shuffle groove, while keeping each pair's
total constant so the timing grid stays locked. `0.4` is a tasteful swing;
higher gets dotted and lurchy. Applies to whichever line is arped.

### `--portamento` — glide

Continuous pitch slide between notes, `SECONDS` long. In the WAV it's real
phase-integrated glide; in the MIDI it's emitted as CC 65/CC 5 and honored by
whatever synth feels like it.

### `--scale` — pick your mood

`minor_pentatonic` (default, can't lose), `major_pentatonic`, `natural_minor`,
`dorian`, `major`, `blues`. Everything is quantized to the scale so even a
2048-bit prime can't play a wrong note.

---

## All the knobs

```
--public FILE        public key PEM (PKCS#1 or SPKI)
--private FILE       private key PEM (PKCS#1 or PKCS#8)
--p12 FILE           PKCS#12 / .pfx bundle (uses openssl to crack it open)
--password PW        password for the .p12
--out FILE           MIDI output (default rsa.mid)
--wav FILE           also render standalone audio (no synth needed)
--scale NAME         musical scale to quantize into
--tempo BPM          tempo (default 100)
--8bit / --chip      chiptune pulse/triangle/noise voices
--arp                arpeggiate the harmony
--arp-melody         arpeggiate the melody instead
--arp-hz HZ          arp speed in notes/sec (~60 = per-frame NES)
--swing [AMOUNT]     shuffle the arp note lengths, 0..0.9 (default 0.4)
--drums              noise-channel beat seeded by SHA-256(n)
--portamento [SEC]   glide between notes (default 0.12s)
```

---

## How the sausage (waveform) is made

- **DER by hand.** `der_integers()` walks the TLV tree, descends into BIT STRING
  / OCTET STRING wrappers, strips leading ASN.1 version fields, and hands back
  `n, e[, d, p, q]`. Works on PKCS#1, SPKI, and PKCS#8.
- **Mapping.** Each byte of a big integer picks a scale degree + octave; its
  nibbles pick velocity and note length. Deterministic, total, no RNG.
- **Synthesis.** `synth_note()` integrates phase sample-by-sample (so pitch can
  glide mid-note), sums either sine harmonics or a chip oscillator, applies an
  attack/decay/release envelope, and optionally bit-crushes. Repeated
  `(pitch, dur, velocity)` combos are cached, because a pentatonic scale reuses
  notes constantly and we're not made of clock cycles.
- **MIDI.** `build_midi()` emits a format-1 SMF byte-for-byte: tempo meta track,
  one MTrk per voice, a GM channel-10 percussion track. Variable-length quantities
  and everything. `hexdump` it if you don't believe me.

---

## FAQ

**Is this cryptographically meaningful?**
No. It's cryptographically *adjacent*. Big difference.

**Can I reverse the audio back into the key?**
The melody? It's just the public modulus, help yourself. The bass encodes
`p XOR q`, so… please don't render keys you love. See the disclaimer you skipped.

**Why does it sound like a Commodore 64?**
Thank you.

**PAL or NTSC?**
`--arp-hz 50` vs `--arp-hz 60`. We don't take sides. (We take the NTSC side.)

---

Made with `math.sin`, spite for dependencies, and a deep respect for the MOS
6581. `RUN`.
