"""Build docs/provision.html's wasm and inline it (enc-ble M5).

The page's setup session is `rusty_esp_signal-web` built for wasm32 in the
`wasm-release` profile and bound with `wasm-bindgen --target no-modules`; its
glue and the wasm (base64, as `PAGE_WASM`) go between the page's
`/*wasm:begin*/` and `/*wasm:end*/` markers, so the page stays one file a
browser opens with nothing else served.

Also builds the device simulator (`--features sim`, `--target nodejs`) into
target/provision-sim for tools/provision-page-check.mjs.

The setup page a device serves from its own open network (E7, protocol
section 11.2) is built from the same parts: docs/setup-page.html takes the
same wasm block and provision.html's session script (between its
`/*session:begin*/` and `/*session:end*/` markers), and its gzip goes to
crates/rusty_esp_signal-core/src/setup/setup-page.html.gz (no timestamp, so
the bytes are the build's alone), which the firmware serves at `/` with
the core crate's `setup-page` feature.

    python tools/build-provision-page.py           # build both, write the page
    python tools/build-provision-page.py --check   # build, and fail if the page differs

Needs: the wasm32-unknown-unknown target and wasm-bindgen-cli 0.2.128 (the
crate pins the same version).
"""
import base64
import gzip
import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, 'docs', 'provision.html')
SETUP_PAGE = os.path.join(ROOT, 'docs', 'setup-page.html')
SETUP_GZ = os.path.join(ROOT, 'crates', 'rusty_esp_signal-core', 'src', 'setup', 'setup-page.html.gz')
SESSION_BEGIN, SESSION_END = '/*session:begin*/', '/*session:end*/'
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

    # the setup page: the same wasm, provision.html's session script
    opening = '<script id="session">\n'
    session = new[new.index(opening) + len(opening):]
    session = session[:session.index('</script>')]
    setup = open(SETUP_PAGE, encoding='utf-8').read()
    i, j = setup.index(BEGIN), setup.index(END) + len(END)
    setup = setup[:i] + block + setup[j:]
    i, j = setup.index(SESSION_BEGIN), setup.index(SESSION_END) + len(SESSION_END)
    setup_new = setup[:i] + SESSION_BEGIN + '\n' + session.rstrip('\n') + '\n' + SESSION_END + setup[j:]
    gz = gzip.compress(setup_new.encode(), compresslevel=9, mtime=0)

    if check:
        stale = [name for name, now, want in [
            ('docs/provision.html', page, new),
            ('docs/setup-page.html', open(SETUP_PAGE, encoding='utf-8').read(), setup_new),
        ] if now != want]
        if not os.path.exists(SETUP_GZ) or open(SETUP_GZ, 'rb').read() != gz:
            stale.append('setup-page.html.gz')
        if stale:
            sys.exit(f'{", ".join(stale)} not what this build produces: run tools/build-provision-page.py')
        print('docs/provision.html, docs/setup-page.html and its gzip match the build')
        return
    write(PAGE, new)
    write(SETUP_PAGE, setup_new)
    with open(SETUP_GZ + '.tmp', 'wb') as f:
        f.write(gz)
    os.replace(SETUP_GZ + '.tmp', SETUP_GZ)
    print(f'docs/provision.html: {len(new.encode())} bytes; wasm {len(wasm)} bytes, sha256 {hashlib.sha256(wasm).hexdigest()}')
    print(f'docs/setup-page.html: {len(setup_new.encode())} bytes, gzip {len(gz)} bytes')


if __name__ == '__main__':
    main()
