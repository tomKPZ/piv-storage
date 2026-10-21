#!/usr/bin/env python3
"""Allow only the observed Debian header-package additions to boot config."""
from pathlib import Path
import sys

ADDITIONS = {
    'CONFIG_MODULE_SIG_ALL=y',
    'CONFIG_MODULE_SIG_KEY="output/signing_key.pem"',
    'CONFIG_SYSTEM_TRUSTED_KEYS=""',
}


def main():
    boot = Path(sys.argv[1]).read_text().splitlines()
    headers = Path(sys.argv[2]).read_text().splitlines()
    release = sys.argv[3] if len(sys.argv) > 3 else '6.12.113+deb13-amd64'
    ADDITIONS.add(f'CONFIG_BUILD_SALT="{release}"')
    if not ADDITIONS.isdisjoint(boot):
        raise RuntimeError('Unexpected packaging entries in boot config')
    if not ADDITIONS.issubset(headers):
        raise RuntimeError('Expected Debian header packaging entries missing')
    if boot != [line for line in headers if line not in ADDITIONS]:
        raise RuntimeError('Boot/header config differs beyond reviewed packaging entries')
    print('Boot/header configs agree apart from four pinned packaging entries')


if __name__ == '__main__':
    main()
