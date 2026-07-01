#!/usr/bin/env python3
"""
rsa_music.py — turn an RSA keypair into a Standard MIDI File.

Concept ("Keypair Duet"):
  * The PUBLIC key's modulus (n) drives a melody line.
  * The PRIVATE key's material (d / p / q) drives a bass + harmony line.
  * A matching public/private pair therefore plays as a two-hand duet.
    Anyone can render the melody from the public key, but only the holder of
    the private key can produce the full harmonization underneath it.

Everything is mapped into a musical scale so the result stays consonant, and
the tonal center is derived from the key itself, so different keys sound
different but the *same* key always produces the *same* music (deterministic).

No third-party dependencies: the PEM/DER is parsed by hand and the MIDI file
is written byte-for-byte with the standard library only.

Usage:
    python3 rsa_music.py --public pub.pem --out song.mid
    python3 rsa_music.py --public pub.pem --private priv.pem --out duet.mid
    python3 rsa_music.py --private priv.pem --scale dorian --tempo 96 --out d.mid

Accepts PKCS#1 ("RSA PUBLIC/PRIVATE KEY"), SPKI ("PUBLIC KEY") and
PKCS#8 ("PRIVATE KEY") PEM files.
"""

import argparse
import base64
import hashlib
import math
import struct
import sys
import wave


# --------------------------------------------------------------------------- #
# 1. Minimal DER / PEM parsing (enough to recover the RSA integers)
# --------------------------------------------------------------------------- #

def pem_blocks(text):
    """Yield (label, der_bytes) for each -----BEGIN X----- block in a PEM."""
    label = None
    b64 = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("-----BEGIN "):
            label = line[len("-----BEGIN "):-len("-----")].strip()
            b64 = []
        elif line.startswith("-----END "):
            if label is not None:
                yield label, base64.b64decode("".join(b64))
            label, b64 = None, []
        elif label is not None:
            b64.append(line)


def _read_len(data, i):
    """Read a DER length starting at index i; return (length, next_index)."""
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    length = int.from_bytes(data[i:i + n], "big")
    return length, i + n


def der_integers(data):
    """
    Walk a DER blob depth-first and return every INTEGER value (as Python ints)
    in the order encountered. Descends into SEQUENCE/SET/context tags and into
    the DER encapsulated by BIT STRING / OCTET STRING wrappers.
    """
    out = []
    i, n = 0, len(data)
    while i < n:
        tag = data[i]
        i += 1
        length, i = _read_len(data, i)
        content = data[i:i + length]
        i += length

        tag_no = tag & 0x1F
        constructed = tag & 0x20

        if tag_no == 0x02 and not constructed:                 # INTEGER
            out.append(int.from_bytes(content, "big"))
        elif constructed or tag_no in (0x10, 0x11):            # SEQUENCE / SET / [n]
            out.extend(der_integers(content))
        elif tag_no == 0x03:                                   # BIT STRING
            # first byte = unused-bits count; the rest is encapsulated DER
            out.extend(der_integers(content[1:]))
        elif tag_no == 0x04:                                   # OCTET STRING
            try:
                out.extend(der_integers(content))              # PKCS#8 wrapper
            except Exception:
                pass
        # OBJECT IDENTIFIER, NULL, etc. carry no integers we need
    return out


def rsa_numbers(pem_text):
    """
    Extract RSA integers from a PEM. Returns a dict with whatever is available:
    always {'n', 'e'} for public material, plus {'d', 'p', 'q'} for private.
    Also reports the detected kind ('public' or 'private').
    """
    for label, der in pem_blocks(pem_text):
        ints = der_integers(der)
        # Strip leading ASN.1 version integers (always 0 for two-prime RSA;
        # PKCS#8 adds a second leading 0). The modulus n is never 0.
        while ints and ints[0] == 0:
            ints.pop(0)
        if len(ints) >= 5:                    # version-stripped: n,e,d,p,q,...
            n, e, d, p, q = ints[0], ints[1], ints[2], ints[3], ints[4]
            return {"kind": "private", "n": n, "e": e, "d": d, "p": p, "q": q}
        if len(ints) >= 2:                    # n, e
            return {"kind": "public", "n": ints[0], "e": ints[1]}
    raise ValueError("no RSA key found in PEM input")


# --------------------------------------------------------------------------- #
# 2. Musical mapping
# --------------------------------------------------------------------------- #

SCALES = {
    "minor_pentatonic": [0, 3, 5, 7, 10],
    "major_pentatonic": [0, 2, 4, 7, 9],
    "natural_minor":    [0, 2, 3, 5, 7, 8, 10],
    "dorian":           [0, 2, 3, 5, 7, 9, 10],
    "major":            [0, 2, 4, 5, 7, 9, 11],
    "blues":            [0, 3, 5, 6, 7, 10],
}

DIVISION = 480                       # ticks per quarter note
DURS = [DIVISION // 2, DIVISION, DIVISION * 3 // 4, DIVISION * 2]  # 8th, 4th, dotted-8th, half


def int_to_bytes(x):
    """Big-endian minimal byte representation of a non-negative int."""
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def tonal_root(n):
    """Pick a root pitch-class (0-11) deterministically from the modulus."""
    return sum(int_to_bytes(n)) % 12


def make_line(data, scale, base_note, oct_range, root_pc,
              vel_lo, vel_hi, dur_pool, stride=1):
    """
    Turn a byte string into a list of (pitch, velocity, duration_ticks) notes.

    Each byte selects a scale degree + octave; its nibbles pick velocity and
    duration. `stride` > 1 samples fewer, longer notes (used for the bass).
    """
    notes = []
    span = vel_hi - vel_lo
    for b in data[::stride]:
        degree = b % len(scale)
        octave = (b // len(scale)) % oct_range
        pitch = base_note + root_pc + 12 * octave + scale[degree]
        pitch = max(0, min(127, pitch))
        velocity = vel_lo + (b & 0x0F) * span // 15
        duration = dur_pool[(b >> 5) % len(dur_pool)]
        notes.append((pitch, velocity, duration))
    return notes


def swung_durations(count, base_dur, remainder, swing):
    """
    Return `count` note lengths summing to base_dur*count + remainder. With
    swing>0 they alternate long/short (a shuffle) instead of being uniform, so
    the melody breathes; each long/short pair still sums to 2*base_dur, keeping
    the timing grid aligned.
    """
    durs = []
    j = 0
    while j < count:
        if swing and j + 1 < count:
            long = round(base_dur * (1.0 + swing))
            durs.append(long)
            durs.append(2 * base_dur - long)          # pair sum stays constant
            j += 2
        else:
            durs.append(base_dur)
            j += 1
    durs[-1] += remainder
    return durs


def make_arp(data, scale, base_note, oct_range, root_pc, vel_lo, vel_hi,
             window_ticks, step_ticks, stride=1, swing=0.0):
    """
    Turn bytes into fast arpeggios: each byte picks a scale position, then a
    triad (degrees d, d+2, d+4 within the scale) is played as rapid notes that
    fill `window_ticks` — the classic chiptune "chord". `step_ticks` sets the
    arp speed (a small value ≈ one note per video frame gives the NES buzz);
    the count of notes per byte scales so the total time per byte stays fixed.
    `swing` (0..1) alternates note lengths for a shuffle groove.
    """
    notes = []
    span = vel_hi - vel_lo
    count = max(1, round(window_ticks / step_ticks))
    base_dur = max(1, window_ticks // count)
    remainder = window_ticks - base_dur * count      # keep bytes grid-aligned
    durs = swung_durations(count, base_dur, remainder, swing)
    for b in data[::stride]:
        degree = b % len(scale)
        octave = (b // len(scale)) % oct_range
        triad = []
        for k in (0, 2, 4):
            dd = degree + k
            oc = octave + dd // len(scale)
            pitch = base_note + root_pc + 12 * oc + scale[dd % len(scale)]
            triad.append(max(0, min(127, pitch)))
        velocity = vel_lo + (b & 0x0F) * span // 15
        for j in range(count):
            notes.append((triad[j % 3], velocity, durs[j]))
    return notes


# --------------------------------------------------------------------------- #
# 3. Standard MIDI File writer (format 1)
# --------------------------------------------------------------------------- #

def vlq(value):
    """Encode an int as a MIDI variable-length quantity."""
    out = bytearray([value & 0x7F])
    value >>= 7
    while value:
        out.insert(0, (value & 0x7F) | 0x80)
        value >>= 7
    return bytes(out)


def note_events(notes, channel):
    """Serialize a monophonic note list into MTrk event bytes (no header)."""
    ev = bytearray()
    for pitch, velocity, duration in notes:
        ev += vlq(0) + bytes([0x90 | channel, pitch, velocity])       # note on
        ev += vlq(duration) + bytes([0x80 | channel, pitch, 0])       # note off
    return bytes(ev)


def track_chunk(event_bytes):
    return b"MTrk" + struct.pack(">I", len(event_bytes)) + event_bytes


def build_drum_track(hits):
    """Build a GM percussion MTrk (channel 10) from absolute-tick drum hits."""
    hit_len = DIVISION // 8
    events = []  # (abs_tick, message_bytes)
    for tick, kind, vel in hits:
        note = DRUM_NOTES[kind]
        events.append((tick, bytes([0x99, note, vel])))          # note on, ch10
        events.append((tick + hit_len, bytes([0x89, note, 0])))  # note off, ch10
    events.sort(key=lambda e: e[0])
    ev = bytearray()
    last = 0
    for tick, msg in events:
        ev += vlq(tick - last) + msg
        last = tick
    ev += vlq(0) + b"\xFF\x2F\x00"
    return track_chunk(bytes(ev))


# GM programs for the 8-bit approximation (square/synth-bass/saw leads).
CHIP_PROGRAMS = {0: 80, 1: 38, 2: 81}


def build_midi(tracks, tempo_bpm, chip=False, portamento=None, drums=None):
    """tracks: list of (program, channel, notes). Returns SMF bytes."""
    # Track 0: tempo / meta.
    us_per_quarter = 60_000_000 // tempo_bpm
    meta = bytearray()
    meta += vlq(0) + b"\xFF\x51\x03" + us_per_quarter.to_bytes(3, "big")
    meta += vlq(0) + b"\xFF\x58\x04\x04\x02\x18\x08"       # 4/4 time signature
    meta += vlq(0) + b"\xFF\x2F\x00"                       # end of track
    chunks = [track_chunk(bytes(meta))]

    # Portamento time as a coarse MIDI controller value (best-effort hint;
    # actual glide is guaranteed only in the WAV renderer).
    porta_val = min(127, int(portamento * 300)) if portamento else 0

    for program, channel, notes in tracks:
        if chip:
            program = CHIP_PROGRAMS.get(channel, program)
        ev = bytearray()
        ev += vlq(0) + bytes([0xC0 | channel, program])   # program change
        if portamento:
            ev += vlq(0) + bytes([0xB0 | channel, 65, 127])       # portamento ON
            ev += vlq(0) + bytes([0xB0 | channel, 5, porta_val])  # portamento time
        ev += note_events(notes, channel)
        ev += vlq(0) + b"\xFF\x2F\x00"                     # end of track
        chunks.append(track_chunk(bytes(ev)))

    if drums:
        chunks.append(build_drum_track(drums))

    header = b"MThd" + struct.pack(">IHHH", 6, 1, len(chunks), DIVISION)
    return header + b"".join(chunks)


# --------------------------------------------------------------------------- #
# 3b. Pure-Python WAV renderer (additive synthesis, no dependencies)
# --------------------------------------------------------------------------- #

# A "voice" describes how a channel is synthesized. Two families:
#   additive: warm tone built from sine harmonics.
#   chip:     classic 8-bit oscillator (pulse/triangle) + amplitude bit-crush.
# Common fields: attack/release (s), decay (exp rate, 0 = sustained), gain.
TIMBRES = {
    0: {"kind": "additive", "harmonics": [1.0, 0.5, 0.25, 0.12],
        "attack": 0.005, "release": 0.06, "decay": 3.0, "gain": 0.9},   # melody piano
    1: {"kind": "additive", "harmonics": [1.0, 0.35, 0.1],
        "attack": 0.005, "release": 0.05, "decay": 1.2, "gain": 1.0},   # bass
    2: {"kind": "additive", "harmonics": [1.0, 0.6, 0.4, 0.2],
        "attack": 0.08, "release": 0.12, "decay": 0.0, "gain": 0.6},    # harmony pad
}

CHIP_TIMBRES = {
    0: {"kind": "chip", "wave": "pulse", "duty": 0.5, "bits": 4,
        "attack": 0.002, "release": 0.02, "decay": 0.8, "gain": 0.8},   # square lead
    1: {"kind": "chip", "wave": "triangle", "duty": 0.5, "bits": 4,
        "attack": 0.002, "release": 0.02, "decay": 0.0, "gain": 1.0},   # NES-style bass
    2: {"kind": "chip", "wave": "pulse", "duty": 0.125, "bits": 3,
        "attack": 0.004, "release": 0.03, "decay": 0.0, "gain": 0.55},  # thin pulse pad
}


def midi_to_freq(pitch):
    return 440.0 * 2.0 ** ((pitch - 69) / 12.0)


def synth_note(freq_start, freq_end, glide_samples, n_samples, velocity, voice, sr):
    """
    Render one note to a list of float samples in roughly [-1, 1].

    The pitch glides (log-linear, musically even) from freq_start up/down to
    freq_end over the first `glide_samples`, then holds. With freq_start ==
    freq_end (or glide_samples == 0) this is an ordinary fixed-pitch note.
    Phase is integrated sample-by-sample so the glide is continuous.

    `voice` selects the oscillator: additive sine harmonics, or an 8-bit
    pulse/triangle wave with amplitude bit-crushing.
    """
    chip = voice["kind"] == "chip"
    amp = voice["gain"] * (0.3 + 0.7 * velocity / 127.0)
    a = max(1, int(voice["attack"] * sr))
    r = max(1, int(voice["release"] * sr))
    half = max(1, n_samples // 2)          # keep envelope sane for very short notes
    a, r = min(a, half), min(r, half)
    decay = voice["decay"]
    two_pi_over_sr = 2.0 * math.pi / sr
    inv_sr = 1.0 / sr
    ratio = freq_end / freq_start if freq_start > 0 else 1.0

    if chip:
        wave_kind = voice["wave"]
        duty = voice["duty"]
        levels = (1 << voice["bits"]) - 1        # amplitude quantization steps

    buf = [0.0] * n_samples
    phase = 0.0          # cycles (0..1 per period) for chip; radians for additive
    for i in range(n_samples):
        if glide_samples and i < glide_samples:
            freq = freq_start * ratio ** (i / glide_samples)
        else:
            freq = freq_end

        if chip:
            phase = (phase + freq * inv_sr) % 1.0
            if wave_kind == "triangle":
                s = 4.0 * abs(phase - 0.5) - 1.0          # /\ shape, -1..1
            else:                                          # pulse / square
                s = 1.0 if phase < duty else -1.0
        else:
            phase += freq * two_pi_over_sr
            s = 0.0
            for h, ha in enumerate(voice["harmonics"], start=1):
                s += ha * math.sin(h * phase)

        env = 1.0
        if i < a:
            env = i / a
        elif i > n_samples - r:
            env = (n_samples - i) / r
        if decay:
            env *= math.exp(-decay * i * inv_sr)

        val = amp * env * s
        if chip:                                           # crunchy bit-crush
            val = round(val * levels) / levels
        buf[i] = val
    return buf


# Percussion: MIDI GM drum notes and per-kind synth character.
DRUM_NOTES = {"kick": 36, "snare": 38, "hat": 42}


def synth_drum(kind, n_samples, velocity, sr):
    """
    Render one 8-bit drum hit. Kick is a pitch-dropping triangle blip; snare
    and hat are LFSR "noise-channel" bursts (NES-style), differing in clock
    period and decay. Returns float samples in roughly [-1, 1].
    """
    amp = 0.4 + 0.6 * velocity / 127.0
    buf = [0.0] * n_samples
    inv_sr = 1.0 / sr

    if kind == "kick":
        f0, f1 = 150.0, 45.0                       # pitch envelope: drop
        ratio = f1 / f0
        phase = 0.0
        for i in range(n_samples):
            f = f0 * ratio ** (i / n_samples)
            phase = (phase + f * inv_sr) % 1.0
            s = 4.0 * abs(phase - 0.5) - 1.0        # triangle
            env = math.exp(-6.0 * i * inv_sr)
            buf[i] = amp * env * s
        return buf

    # snare / hat: 15-bit LFSR noise (like the NES noise channel)
    period = 5 if kind == "snare" else 1           # bigger period = lower/grittier
    decay = 16.0 if kind == "snare" else 55.0      # hat decays much faster
    gain = 0.9 if kind == "snare" else 0.5
    reg = 0x7FFF
    val = 1.0
    for i in range(n_samples):
        if i % period == 0:
            bit = (reg ^ (reg >> 1)) & 1
            reg = (reg >> 1) | (bit << 14)
            val = 1.0 if (reg & 1) else -1.0
        env = math.exp(-decay * i * inv_sr)
        buf[i] = amp * gain * env * val
    return buf


def _xorshift32(seed):
    """Tiny deterministic PRNG generator, seeded by e."""
    x = seed & 0xFFFFFFFF or 0x1234567
    while True:
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        yield x & 0xFFFFFFFF


def modulus_seed(n):
    """
    A 32-bit drum seed = the first 4 bytes of SHA-256(modulus). Using a hash
    (rather than e, which is almost always 65537) makes the beat unique per key
    while staying fully deterministic.
    """
    return int.from_bytes(hashlib.sha256(int_to_bytes(n)).digest()[:4], "big")


def drum_pattern(seed, steps=16):
    """
    Build a 16-step (one bar of 16ths) drum pattern from a numeric seed.
    A downbeat backbone keeps it grooving; the seed drives the fills/variation,
    so a different key yields a different beat.
    Returns a list of lists of (kind, velocity) per step.
    """
    rng = _xorshift32(seed)
    pattern = []
    for i in range(steps):
        r = next(rng)
        hits = []
        if i in (0, 8) or r % 6 == 0:
            hits.append(("kick", 110 if i == 0 else 95))
        if i in (4, 12) or (r >> 3) % 12 == 0:
            hits.append(("snare", 100))
        if i % 2 == 0 or (r >> 6) % 3 == 0:
            hits.append(("hat", 70 if i % 2 else 55))
        pattern.append(hits)
    return pattern


def drum_hits(seed, total_ticks):
    """Loop the seeded pattern across the whole song on a 16th-note grid."""
    pattern = drum_pattern(seed)
    step = DIVISION // 4                            # a sixteenth note
    hits = []
    tick, s = 0, 0
    while tick < total_ticks:
        for kind, vel in pattern[s % len(pattern)]:
            hits.append((tick, kind, vel))
        tick += step
        s += 1
    return hits


def render_wav(tracks, tempo_bpm, path, sr=44100, chip=False, portamento=None, drums=None):
    """
    Mix all tracks into a 16-bit mono WAV. Notes per track play in sequence.

    chip=True uses 8-bit pulse/triangle voices. portamento (seconds or None)
    glides each note's pitch from the previous note over that time. drums is an
    optional list of (abs_tick, kind, velocity) noise-channel hits.
    """
    sec_per_tick = 60.0 / (tempo_bpm * DIVISION)
    timbre_set = CHIP_TIMBRES if chip else TIMBRES
    cache = {}

    # Lay out every note as (start_sample, samples_list); track total length.
    laid_out = []
    total = 0
    for program, channel, notes in tracks:
        voice = timbre_set.get(channel, timbre_set[0])
        pos = 0        # samples from track start
        prev_pitch = None
        for pitch, velocity, dur_ticks in notes:
            n = max(1, int(dur_ticks * sec_per_tick * sr))
            if portamento and prev_pitch is not None and prev_pitch != pitch:
                start_pitch = prev_pitch
                glide = min(int(portamento * sr), n)
            else:
                start_pitch, glide = pitch, 0
            key = (channel, start_pitch, pitch, glide, n, velocity)
            wave_buf = cache.get(key)
            if wave_buf is None:
                wave_buf = synth_note(midi_to_freq(start_pitch), midi_to_freq(pitch),
                                      glide, n, velocity, voice, sr)
                cache[key] = wave_buf
            laid_out.append((pos, wave_buf))
            pos += n
            prev_pitch = pitch
        total = max(total, pos)

    # Noise-channel drums, placed on their absolute grid positions.
    if drums:
        drum_len = {"kick": int(0.18 * sr), "snare": int(0.15 * sr), "hat": int(0.05 * sr)}
        drum_cache = {}
        for tick, kind, vel in drums:
            n = drum_len[kind]
            key = (kind, vel)
            hit = drum_cache.get(key)
            if hit is None:
                hit = synth_drum(kind, n, vel, sr)
                drum_cache[key] = hit
            start = int(tick * sec_per_tick * sr)
            laid_out.append((start, hit))
            total = max(total, start + n)

    # Mix into a master buffer.
    master = [0.0] * total
    for start, wave_buf in laid_out:
        for i, v in enumerate(wave_buf):
            master[start + i] += v

    # Normalize to avoid clipping, then quantize to 16-bit PCM.
    peak = max((abs(v) for v in master), default=1.0) or 1.0
    scale = 0.89 * 32767.0 / peak
    frames = bytearray()
    for v in master:
        frames += struct.pack("<h", int(v * scale))

    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(bytes(frames))
    return total / sr


# --------------------------------------------------------------------------- #
# 4. Orchestration
# --------------------------------------------------------------------------- #

def compose(public=None, private=None, scale_name="minor_pentatonic", tempo=100,
            arp=False, arp_melody=False, arp_hz=None, swing=0.0, drums=False):
    scale = SCALES[scale_name]

    # Decide which key sources the melody vs. the bass/harmony.
    pub = private if (public is None and private is not None) else public
    if pub is None:
        raise ValueError("need at least one key")

    root_pc = tonal_root(pub["n"])
    tracks, summary = [], []

    def arp_step():
        """Arp note length in ticks + a label; absolute Hz or tempo-relative 16ths."""
        if arp_hz:                                 # absolute rate (60 ≈ per-frame NES)
            return max(1, round(tempo / 60.0 * DIVISION / arp_hz)), f"{arp_hz:g} Hz"
        return DIVISION // 4, "16th notes"         # 16th notes, tempo-relative

    # Melody — from the public modulus (Acoustic Grand Piano, program 0).
    melody_src = int_to_bytes(pub["n"])
    if arp_melody:
        step, rate_txt = arp_step()
        melody = make_arp(melody_src, scale, base_note=60, oct_range=3,
                          root_pc=root_pc, vel_lo=64, vel_hi=112,
                          window_ticks=DIVISION, step_ticks=step, stride=1, swing=swing)
        sw = f", swing {swing:g}" if swing else ""
        summary.append(f"melody: {len(melody)} arp notes from public modulus (n) @ {rate_txt}{sw}")
    else:
        melody = make_line(melody_src, scale, base_note=60, oct_range=3,
                           root_pc=root_pc, vel_lo=64, vel_hi=112, dur_pool=DURS)
        summary.append(f"melody: {len(melody)} notes from public modulus (n)")
    tracks.append((0, 0, melody))

    # Bass + harmony — only if we hold private material.
    if private is not None:
        bass_src = int_to_bytes(private["p"] ^ private["q"])   # combine the primes
        bass = make_line(bass_src, scale, base_note=36, oct_range=2,
                         root_pc=root_pc, vel_lo=70, vel_hi=100,
                         dur_pool=[DIVISION, DIVISION * 2], stride=1)
        tracks.append((32, 1, bass))          # Acoustic Bass
        summary.append(f"bass:   {len(bass)} notes from private primes (p^q)")

        harm_src = int_to_bytes(private["d"])
        if arp:
            step, rate_txt = arp_step()            # one beat of arp per source byte
            harmony = make_arp(harm_src, scale, base_note=48, oct_range=2,
                               root_pc=root_pc, vel_lo=55, vel_hi=90,
                               window_ticks=DIVISION, step_ticks=step, stride=1, swing=swing)
            summary.append(f"arps:   {len(harmony)} notes from private exponent (d) @ {rate_txt}")
        else:
            harmony = make_line(harm_src, scale, base_note=48, oct_range=2,
                                root_pc=root_pc, vel_lo=50, vel_hi=80,
                                dur_pool=[DIVISION * 2, DIVISION * 4], stride=3)
            summary.append(f"harmony:{len(harmony)} notes from private exponent (d)")
        tracks.append((48, 2, harmony))       # String Ensemble pad / saw in chip

    # Noise drum track, looped across the whole song, seeded by a hash of the
    # modulus (its SHA-256 prefix) so the beat is unique per key.
    drum_events = None
    if drums:
        total_ticks = max(sum(d for _, _, d in notes) for _, _, notes in tracks)
        seed = modulus_seed(pub["n"])
        drum_events = drum_hits(seed, total_ticks)
        summary.append(f"drums:  {len(drum_events)} noise hits seeded by SHA-256(n) prefix = {seed:#010x}")

    root_name = ["C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"][root_pc]
    return tracks, root_name, summary, drum_events


def numbers_from_p12(path, password):
    """
    Extract RSA numbers from a PKCS#12 (.p12/.pfx) bundle by asking the local
    `openssl` to dump its private key as PEM, then parsing that. The bundle's
    private key already contains n and e, so this yields the full keypair.
    """
    import subprocess
    cmd = ["openssl", "pkcs12", "-in", path, "-nocerts", "-nodes",
           "-passin", f"pass:{password}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemExit("openssl not found on PATH; required to read .p12 files")
    if proc.returncode != 0:
        # Old bundles may need the legacy provider (OpenSSL 3.x).
        retry = subprocess.run(cmd + ["-legacy"], capture_output=True, text=True)
        if retry.returncode != 0:
            raise SystemExit(
                "openssl could not open the .p12 (wrong password?):\n"
                + (proc.stderr or "").strip())
        proc = retry
    nums = rsa_numbers(proc.stdout)
    if nums["kind"] != "private":
        raise SystemExit("no RSA private key found in the .p12 bundle")
    return nums


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert an RSA keypair into music (MIDI + WAV).")
    ap.add_argument("--public", help="public key PEM file")
    ap.add_argument("--private", help="private key PEM file")
    ap.add_argument("--p12", help="PKCS#12 (.p12/.pfx) bundle holding the keypair")
    ap.add_argument("--password", default="", help="password for the .p12 bundle")
    ap.add_argument("--out", default="rsa.mid", help="output MIDI file (default rsa.mid)")
    ap.add_argument("--wav", help="also render audio to this WAV file")
    ap.add_argument("--scale", default="minor_pentatonic", choices=sorted(SCALES),
                    help="musical scale to quantize into")
    ap.add_argument("--tempo", type=int, default=100, help="tempo in BPM")
    ap.add_argument("--8bit", "--chip", dest="chip", action="store_true",
                    help="use chiptune pulse/triangle voices")
    ap.add_argument("--portamento", nargs="?", type=float, const=0.12, default=None,
                    metavar="SECONDS",
                    help="glide between notes (default 0.12s if given without a value)")
    ap.add_argument("--arp", action="store_true",
                    help="arpeggiate the harmony line (chiptune chords)")
    ap.add_argument("--arp-melody", action="store_true",
                    help="arpeggiate the melody line (from the modulus) instead")
    ap.add_argument("--arp-hz", type=float, default=None, metavar="HZ",
                    help="arp speed in notes/sec (~60 = classic per-frame NES arp); "
                         "default is tempo-relative 16th notes")
    ap.add_argument("--swing", nargs="?", type=float, const=0.4, default=0.0,
                    metavar="AMOUNT",
                    help="shuffle the arp note lengths, 0..0.9 (default 0.4 if bare)")
    ap.add_argument("--drums", action="store_true",
                    help="add a noise-channel drum track seeded by exponent e")
    args = ap.parse_args(argv)

    if not (args.public or args.private or args.p12):
        ap.error("provide --p12, or --public and/or --private")

    public = private = None
    if args.p12:
        private = numbers_from_p12(args.p12, args.password)
    if args.public:
        with open(args.public) as f:
            public = rsa_numbers(f.read())
    if args.private:
        with open(args.private) as f:
            private = rsa_numbers(f.read())
            if private["kind"] != "private":
                ap.error(f"{args.private} does not contain a private key")

    tracks, root_name, summary, drums = compose(
        public, private, args.scale, args.tempo,
        arp=args.arp, arp_melody=args.arp_melody, arp_hz=args.arp_hz,
        swing=args.swing, drums=args.drums)

    midi = build_midi(tracks, args.tempo, chip=args.chip,
                      portamento=args.portamento, drums=drums)
    with open(args.out, "wb") as f:
        f.write(midi)
    print(f"Wrote {args.out} ({len(midi)} bytes)")
    fx = []
    if args.chip:
        fx.append("8-bit")
    if args.arp or args.arp_melody:
        tag = "arps" + ("(mel)" if args.arp_melody else "")
        fx.append(f"{tag}@{args.arp_hz:g}Hz" if args.arp_hz else tag)
    if args.swing:
        fx.append(f"swing {args.swing:g}")
    if args.drums:
        fx.append("drums")
    if args.portamento:
        fx.append(f"portamento {args.portamento:g}s")
    print(f"Key of {root_name} {args.scale}, {args.tempo} BPM"
          + (f" [{', '.join(fx)}]" if fx else ""))
    for line in summary:
        print("  " + line)

    if args.wav:
        print(f"Rendering audio to {args.wav} ...")
        seconds = render_wav(tracks, args.tempo, args.wav, chip=args.chip,
                             portamento=args.portamento, drums=drums)
        print(f"Wrote {args.wav} ({seconds:.1f}s of audio)")
    else:
        print("\nPlay the MIDI with any player, e.g.:")
        print(f"  fluidsynth -a coreaudio /path/to/soundfont.sf2 {args.out}")
        print(f"  timidity {args.out}   # or open in a DAW / QuickTime")
        print("Or add --wav out.wav to render standalone audio (no synth needed).")


if __name__ == "__main__":
    sys.exit(main())
