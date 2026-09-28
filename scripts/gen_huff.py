#!/usr/bin/env python3
"""Generate the Rust Huffman tables from nginx-c.

    scripts/gen_huff.py decode > /tmp/decode_table.rs
    scripts/gen_huff.py encode > /tmp/encode_tables.rs

The output is pasted into crates/ngx-http/src/huff_decode.rs and
huff_encode.rs. The tables must match ngx_http_huff_decode.c and
ngx_http_huff_encode.c entry for entry: nginx's lenient decoding of
over-long all-ones padding comes from the decode table, not from logic.
"""

import re
import sys

C = "/home/ubuntu/rnginx/nginx-c/src/http/"


def table_body(src, name):
    start = src.index(name)
    start = src.index("{", src.index("=", start))
    end = src.index("\n};", start)
    return src[start + 1:end]


def decode():
    src = open(C + "ngx_http_huff_decode.c").read()
    body = table_body(src, "ngx_http_huff_decode_codes[256][16]")
    codes = re.findall(r"\{(0x[0-9a-f]{2}), (0x[0-9a-f]{2}), (0x[0-9a-f]{2}), (0x[0-9a-f]{2})\}", body)
    assert len(codes) == 256 * 16, len(codes)
    out = ["static CODES: [[Code; 16]; 256] = ["]
    for state in range(256):
        out.append("    // %d" % state)
        out.append("    [")
        row = codes[state * 16:(state + 1) * 16]
        for i in range(0, 16, 4):
            out.append("        " + " ".join("c(%s, %s, %s, %s)," % q for q in row[i:i + 4]))
        out.append("    ],")
    out.append("];")
    print("\n".join(out))


def encode():
    src = open(C + "ngx_http_huff_encode.c").read()
    for name, rust in (("ngx_http_huff_encode_table[256]", "TABLE"),
                       ("ngx_http_huff_encode_table_lc[256]", "TABLE_LC")):
        body = table_body(src, name)
        codes = re.findall(r"\{(0x[0-9a-f]{8}),\s*(\d+)\}", body)
        assert len(codes) == 256, (name, len(codes))
        print("static %s: [(u32, u32); 256] = [" % rust)
        for i in range(0, 256, 4):
            print("    " + " ".join("(%s, %s)," % q for q in codes[i:i + 4]))
        print("];")
        print()


if __name__ == "__main__":
    {"decode": decode, "encode": encode}[sys.argv[1]]()
