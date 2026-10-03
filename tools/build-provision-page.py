"""Build docs/provision.html's wasm and inline it (enc-ble M5).

The page's setup session is `rusty_esp_signal-web` built for wasm32 in the
`wasm-release` profile and bound with `wasm-bindgen --target no-modules`; its
glue and the wasm (base64, as `PAGE_WASM`) go between the page's
`/*wasm:begin*/` and `/*wasm:end*/` markers, so the page stays one file a
browser opens with nothing else served.

Also builds the device simulator (`--features sim`, `--target nodejs`) into
target/provision-sim for tools/provision-page-check.mjs.

    python tools/build-provision-page.py           # build both, write the page
    python tools/build-provision-page.py --check   # build, and fail if the page differs

Needs: the wasm32-unknown-unknown target and wasm-bindgen-cli 0.2.128 (the
crate pins the same version).
"""
import base64
import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, 'docs', 'provision.html')
TARGET = os.environ.get('CARGO_TARGET_DIR', os.path.join(ROOT, 'target'))
BEGIN, END = '/*wasm:begin*/', '/*wasm:end*/'


def run(*args, **kw):
    print('+', ' '.join(args), flush=True)
    subprocess.run(args, check=True, cwd=ROOT, **kw)


def build(profile, features, bindgen_target, out_dir):
    cmd = ['cargo', 'build', '-p', 'rusty_esp_signal-web', '--target', 'wasm32-unknown-unknown',
           '--profile', profile]
    if features:
        cmd += ['--features', features]
    run(*cmd)
    wasm = os.path.join(TARGET, 'wasm32-unknown-unknown', profile, 'rusty_esp_signal_web.wasm')
    run('wasm-bindgen', '--target', bindgen_target, '--no-typescript', '--out-dir', out_dir, wasm)


def write(path, text):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    os.replace(tmp, path)


def main():
    check = '--check' in sys.argv[1:]
    page_out = os.path.join(TARGET, 'provision-page')
    sim_out = os.path.join(TARGET, 'provision-sim')
    build('wasm-release', None, 'no-modules', page_out)
    build('wasm-release', 'sim', 'nodejs', sim_out)

    glue = open(os.path.join(page_out, 'rusty_esp_signal_web.js'), encoding='utf-8').read()
    wasm = open(os.path.join(page_out, 'rusty_esp_signal_web_bg.wasm'), 'rb').read()
    block = (BEGIN + '\n' + glue.rstrip('\n') + '\n'
             + '// the wasm above binds: ' + str(len(wasm)) + ' bytes, sha256 '
             + hashlib.sha256(wasm).hexdigest() + '\n'
             + 'const PAGE_WASM = "' + base64.b64encode(wasm).decode() + '";\n' + END)

    page = open(PAGE, encoding='utf-8').read()
    i, j = page.index(BEGIN), page.index(END) + len(END)
    new = page[:i] + block + page[j:]
    if check:
        if new != page:
            sys.exit('docs/provision.html is not what this build produces: run tools/build-provision-page.py')
        print('docs/provision.html matches the build')
        return
    write(PAGE, new)
    print(f'docs/provision.html: {len(new.encode())} bytes; wasm {len(wasm)} bytes, sha256 {hashlib.sha256(wasm).hexdigest()}')


if __name__ == '__main__':
    main()
