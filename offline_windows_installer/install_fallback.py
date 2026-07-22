"""
Fallback installer: extracts all .whl files from packages/ into site-packages.
Used when pip fails (SSL timeout, pip broken, etc.).
"""
import os
import sys
import site
import zipfile


REQUIRED = ['multipart', 'fastapi', 'uvicorn', 'openpyxl', 'pydantic', 'starlette',
            'anyio', 'h11', 'click', 'annotated_types', 'typing_extensions',
            'typing_inspection', 'idna', 'colorama', 'et_xmlfile', 'annotated_doc',
            'pydantic_core']


def find_writable_site_packages():
    candidates = []
    try:
        candidates.append(('user', site.getusersitepackages()))
    except Exception:
        pass
    try:
        for p in site.getsitepackages():
            if 'site-packages' in p.lower():
                candidates.append(('system', p))
    except Exception:
        pass

    for kind, path in candidates:
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, '_write_probe_')
            with open(probe, 'w') as f:
                f.write('x')
            os.remove(probe)
            return path, kind
        except Exception:
            continue
    return None, None


def _is_compatible_wheel(filename):
    """
    Return True if the wheel is compatible with the running Python version.
    Skips platform-specific wheels built for a different Python version
    (e.g. cp312 wheel when running cp314, and vice-versa).
    Pure-Python wheels (py3-none-any, py2.py3-none-any) are always compatible.
    """
    parts = filename.rstrip('.whl').split('-')
    if len(parts) < 5:
        return True  # can't parse, try anyway
    python_tag = parts[2]   # e.g. cp312, cp314, py3, py2.py3
    abi_tag    = parts[3]   # e.g. cp312, none
    # Pure-Python wheel — always compatible
    if python_tag.startswith('py') or abi_tag == 'none':
        return True
    # CPython-specific: check major+minor match
    running = f'cp{sys.version_info.major}{sys.version_info.minor}'
    return python_tag == running


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    packages_dir = os.path.join(script_dir, 'packages')

    if not os.path.isdir(packages_dir):
        print(f'ERROR: packages/ folder not found at {packages_dir}')
        return 1

    all_wheels = [f for f in os.listdir(packages_dir) if f.endswith('.whl')]
    wheels = [w for w in all_wheels if _is_compatible_wheel(w)]
    skipped = len(all_wheels) - len(wheels)

    if not wheels:
        print('ERROR: No compatible .whl files in packages/ folder')
        return 1

    print(f'Python: {sys.version.split()[0]}')
    if skipped:
        print(f'Skipped {skipped} incompatible platform wheel(s) (different Python version).')

    site_packages, kind = find_writable_site_packages()
    if not site_packages:
        print('ERROR: No writable site-packages found. Try running as Administrator.')
        return 1

    print(f'Target ({kind}): {site_packages}')
    print(f'Installing {len(wheels)} packages...')
    print()

    for whl in sorted(wheels):
        whl_path = os.path.join(packages_dir, whl)
        try:
            with zipfile.ZipFile(whl_path) as z:
                z.extractall(site_packages)
            print(f'  OK  {whl}')
        except Exception as e:
            print(f'  ERR {whl}: {e}')

    print()
    print('Verifying...')
    ok = True
    for mod in ['fastapi', 'uvicorn', 'openpyxl', 'multipart', 'pydantic']:
        try:
            import importlib
            m = importlib.import_module(mod)
            ver = getattr(m, '__version__', '?')
            print(f'  OK  {mod} {ver}')
        except ImportError:
            print(f'  FAIL {mod} — not importable (may need to restart Python)')
            ok = False

    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
