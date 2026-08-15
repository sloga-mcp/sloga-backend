#!/usr/bin/env python3
"""Regenerate the AVIF test fixtures in crates/core/files/tests/assets/.

    python3 scripts/gen-avif-fixtures.py

Produces four files:

    dice.avif          still, ISOBMFF major brand `avif`
    anim-icos.avif     20 frames, major brand `avis`
    exif-gps.avif      dice.avif plus an Exif item (Make, Model, GPS IFD)
    anim-exif-gps.avif anim-icos.avif plus the same Exif item

Two of these exist to pin down behaviour that is easy to get wrong:

`anim-icos.avif` has an `avis` major brand because that is what ffmpeg writes for
anything multi-frame. `infer` and `imagesize` accept it, image-rs does not, so it is
the regression test for pinning the decoder format from the mime rather than sniffing.

The Exif-bearing pair has to be constructed rather than captured: ffmpeg will not
write an Exif item into AVIF, and exiftool/exiv2/pillow-heif are not assumed present.
Building one is the inverse of stripping one, so it exercises the same box handling.

Requires ffmpeg with libaom-av1. Nothing else.
"""

import struct
import subprocess
import sys
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "crates/core/files/tests/assets"


def box(typ: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def full_box(typ: bytes, version: int, flags: int, payload: bytes) -> bytes:
    return box(typ, struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload)


def build_tiff_exif() -> bytes:
    """A little-endian TIFF with Make/Model and a GPS IFD at 51deg30'N 000deg07'W."""
    make = b"SlogaTestCam\x00"
    model = b"AVIF-EXIF-FIXTURE\x00"

    make_off = 50
    model_off = make_off + len(make)
    gps_ifd_off = model_off + len(model)
    if gps_ifd_off % 2:
        gps_ifd_off += 1
    pad = gps_ifd_off - (model_off + len(model))

    lat_off = gps_ifd_off + 2 + 12 * 2 + 4
    lon_off = lat_off + 24

    out = bytearray()
    out += b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)

    out += struct.pack("<H", 3)
    out += struct.pack("<HHII", 0x010F, 2, len(make), make_off)     # Make
    out += struct.pack("<HHII", 0x0110, 2, len(model), model_off)   # Model
    out += struct.pack("<HHII", 0x8825, 4, 1, gps_ifd_off)          # GPSInfo pointer
    out += struct.pack("<I", 0)

    assert len(out) == make_off
    out += make + model + b"\x00" * pad

    assert len(out) == gps_ifd_off
    out += struct.pack("<H", 2)
    out += struct.pack("<HHII", 0x0002, 5, 3, lat_off)              # GPSLatitude
    out += struct.pack("<HHII", 0x0004, 5, 3, lon_off)              # GPSLongitude
    out += struct.pack("<I", 0)

    assert len(out) == lat_off
    for num, den in ((51, 1), (30, 1), (0, 1)):
        out += struct.pack("<II", num, den)
    assert len(out) == lon_off
    for num, den in ((0, 1), (7, 1), (0, 1)):
        out += struct.pack("<II", num, den)

    return bytes(out)


def parse_top_level(buf):
    boxes, off = [], 0
    while off + 8 <= len(buf):
        size = struct.unpack(">I", buf[off:off + 4])[0]
        typ = buf[off + 4:off + 8]
        if size == 0:
            size = len(buf) - off
        boxes.append((typ, off, size))
        off += size
    return boxes


def children_of_meta(buf, off, size):
    """meta is a FullBox: four bytes of version/flags before its children."""
    out, p, end = {}, off + 12, off + size
    while p + 8 <= end:
        sz = struct.unpack(">I", buf[p:p + 4])[0]
        out[buf[p + 4:p + 8]] = buf[p:p + sz]
        p += sz
    return out


def original_item1_length(buf, meta_off, meta_size) -> int:
    """Item 1 keeps its own extent length.

    For an animated AVIF the mdat payload is [still primary item][video samples], so
    using the whole payload would make the still item over-claim into the sample data.
    """
    p, end = meta_off + 12, meta_off + meta_size
    while p + 8 <= end:
        size = struct.unpack(">I", buf[p:p + 4])[0]
        if buf[p + 4:p + 8] == b"iloc":
            version = buf[p + 8]
            q = p + 12
            sizes = buf[q]; q += 1
            offset_size, length_size = sizes >> 4, sizes & 0xF
            base_offset_size = buf[q] >> 4; q += 1
            q += 2 + 2                                   # item_count, item_ID
            if version >= 1:
                q += 2
            q += 2 + base_offset_size + 2 + offset_size  # to the extent_length
            return int.from_bytes(buf[q:q + length_size], "big")
        p += size
    raise ValueError("no iloc found")


def shift_stco(moov: bytes, delta: int) -> bytes:
    """Rewrite every stco entry by delta.

    stco holds absolute file offsets, so growing meta (which inserting an Exif item
    does) moves mdat and invalidates them. This is only needed for injection --
    stripping overwrites in place precisely so it never has to do this.
    """
    out = bytearray(moov)
    idx = 0
    while True:
        idx = out.find(b"stco", idx)
        if idx < 0:
            return bytes(out)
        p = idx + 8
        count = struct.unpack(">I", out[p:p + 4])[0]
        p += 4
        for i in range(count):
            at = p + 4 * i
            val = struct.unpack(">I", out[at:at + 4])[0]
            out[at:at + 4] = struct.pack(">I", val + delta)
        idx += 4


def inject_exif(src: Path, dst: Path):
    buf = src.read_bytes()
    tops = {t: (o, s) for t, o, s in parse_top_level(buf)}
    ftyp = buf[tops[b"ftyp"][0]:tops[b"ftyp"][0] + tops[b"ftyp"][1]]
    meta_off, meta_size = tops[b"meta"]
    kids = children_of_meta(buf, meta_off, meta_size)
    mdat_off, mdat_size = tops[b"mdat"]
    image_data = buf[mdat_off + 8:mdat_off + mdat_size]
    moov = buf[tops[b"moov"][0]:tops[b"moov"][0] + tops[b"moov"][1]] if b"moov" in tops else b""

    item1_len = original_item1_length(buf, meta_off, meta_size)
    exif_payload = struct.pack(">I", 0) + build_tiff_exif()   # tiff_header_offset = 0

    def infe(item_id, item_type):
        return full_box(b"infe", 2, 0,
                        struct.pack(">HH", item_id, 0) + item_type + b"\x00")

    iinf = full_box(b"iinf", 0, 0, struct.pack(">H", 2) + infe(1, b"av01") + infe(2, b"Exif"))
    iref = full_box(b"iref", 0, 0, box(b"cdsc", struct.pack(">HHH", 2, 1, 1)))

    def iloc_with(off1, off2):
        body = struct.pack(">BB", (4 << 4) | 4, 0) + struct.pack(">H", 2)
        for item_id, o, ln in ((1, off1, item1_len), (2, off2, len(exif_payload))):
            body += struct.pack(">HHH", item_id, 0, 1)
            body += struct.pack(">II", o, ln)
        return full_box(b"iloc", 0, 0, body)

    iloc_len = len(iloc_with(0, 0))          # fixed width, so the layout is knowable
    meta_size_new = 8 + (4 + len(kids[b"hdlr"]) + len(kids[b"pitm"]) + iloc_len
                         + len(iinf) + len(iref) + len(kids[b"iprp"]))
    mdat_payload_start = len(ftyp) + meta_size_new + len(moov) + 8

    iloc = iloc_with(mdat_payload_start, mdat_payload_start + len(image_data))
    assert len(iloc) == iloc_len

    meta = full_box(b"meta", 0, 0,
                    kids[b"hdlr"] + kids[b"pitm"] + iloc + iinf + iref + kids[b"iprp"])
    assert len(meta) == meta_size_new

    if moov:
        moov = shift_stco(moov, mdat_payload_start - (mdat_off + 8))

    dst.write_bytes(ftyp + meta + moov + box(b"mdat", image_data + exif_payload))
    print(f"  {dst.name}: {dst.stat().st_size} bytes")


def ffmpeg(args):
    subprocess.run(["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", *args], check=True)


def main():
    ASSETS.mkdir(parents=True, exist_ok=True)
    still, anim = ASSETS / "dice.avif", ASSETS / "anim-icos.avif"

    print("generating base fixtures with ffmpeg")
    ffmpeg(["-f", "lavfi", "-i", "testsrc=size=320x240:rate=1", "-frames:v", "1",
            "-c:v", "libaom-av1", "-cpu-used", "8", str(still)])
    ffmpeg(["-f", "lavfi", "-i", "testsrc=size=320x240:rate=10", "-frames:v", "20",
            "-c:v", "libaom-av1", "-cpu-used", "8", str(anim)])

    if anim.read_bytes()[8:12] != b"avis":
        sys.exit("ffmpeg did not write an avis major brand; the regression test needs one")

    print("injecting Exif")
    inject_exif(still, ASSETS / "exif-gps.avif")
    inject_exif(anim, ASSETS / "anim-exif-gps.avif")
    print("done")


if __name__ == "__main__":
    main()
