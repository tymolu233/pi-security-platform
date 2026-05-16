#!/usr/bin/env python3
"""Helper to write JSON files without shell escaping issues.

Usage:
  write_json.py <output_path> key1=value1 key2=value2 key3='["a","b"]'

Values that look like JSON arrays/objects/null/booleans are parsed as such.
Everything else is treated as a string.

Example:
  write_json.py /workspace/cache/distorted.triage.json \
    binary=distorted format=ELF64 arch=x86_64 language=C \
    packed=upx-4.22-corrupted \
    'key_strings_found=["CCB_M4gic_K3y","CCB!"]' \
    'companion_files=["flag.txt.enc"]' \
    flag_found=null \
    escalate_to=re-dynamic \
    'escalate_reason=UPX packed corrupted headers, key found but algo unknown'
"""
import json
import sys
import os

def parse_value(v):
    if v == 'null' or v == 'None':
        return None
    if v == 'true':
        return True
    if v == 'false':
        return False
    if v.startswith('[') or v.startswith('{'):
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v
    try:
        return int(v)
    except ValueError:
        pass
    return v

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <output_path> key=value ...", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    data = {}

    for arg in sys.argv[2:]:
        if '=' not in arg:
            print(f"Warning: skipping invalid arg (no '='): {arg}", file=sys.stderr)
            continue
        key, value = arg.split('=', 1)
        data[key] = parse_value(value)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"Written: {output_path} ({len(data)} keys)")

if __name__ == '__main__':
    main()
