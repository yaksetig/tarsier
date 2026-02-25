#!/usr/bin/env python3
"""Update Homebrew formula version and SHA256 checksums after a release."""
import re
import sys


def main():
    if len(sys.argv) != 6:
        print(
            f"Usage: {sys.argv[0]} VERSION SHA_AARCH64_DARWIN SHA_X86_64_DARWIN SHA_AARCH64_LINUX SHA_X86_64_LINUX",
            file=sys.stderr,
        )
        sys.exit(1)

    version, sha_a64_dar, sha_x64_dar, sha_a64_lin, sha_x64_lin = sys.argv[1:6]
    mapping = {
        "aarch64-apple-darwin": sha_a64_dar,
        "x86_64-apple-darwin": sha_x64_dar,
        "aarch64-unknown-linux-gnu": sha_a64_lin,
        "x86_64-unknown-linux-gnu": sha_x64_lin,
    }

    with open("Formula/tarsier.rb") as f:
        lines = f.readlines()

    # Update version
    lines = [
        re.sub(r'version ".*"', f'version "{version}"', l) if 'version "' in l else l
        for l in lines
    ]

    # Update sha256 values by finding the URL line and updating the next sha256 line
    for i, line in enumerate(lines):
        for target, sha in mapping.items():
            if target in line and "url " in line:
                for j in range(i + 1, min(i + 3, len(lines))):
                    if "sha256" in lines[j]:
                        lines[j] = re.sub(
                            r'sha256 ".*"', f'sha256 "{sha}"', lines[j]
                        )
                        break

    with open("Formula/tarsier.rb", "w") as f:
        f.writelines(lines)

    print(f"Updated Formula/tarsier.rb to version {version}")


if __name__ == "__main__":
    main()
