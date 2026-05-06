import textwrap
code = textwrap.dedent("""\
    #!/usr/bin/env python3
    # CWE complete download & verify tool
    # Strategy: XML zip -> authoritative ID list -> per-entry REST API fetch
    from __future__ import annotations
    import argparse, hashlib, io, json, os, ssl, sys, threading, time
    import urllib.error, urllib.request, xml.etree.ElementTree as ET, zipfile
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from typing import Any, Optional

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    API_BASE    = 'https://cwe-api.mitre.org/api/v1'
    XML_ZIP_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
    XML_NS      = {'cwe': 'http://cwe.mitre.org/cwe-7'}


    def ensure_dir(path):
        os.makedirs(path, exist_ok=True)


    def file_sha256(path):
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except FileNotFoundError:
            return None


    def write_if_changed(obj, path):
        ensure_dir(os.path.dirname(path) or '.')
        new_bytes = json.dumps(obj, ensure_ascii=False, indent=2).encode('utf-8')
        if hashlib.sha256(new_bytes).hexdigest() == file_sha256(path):
            return False
        tmp = path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(new_bytes)
        os.replace(tmp, path)
        return True


    def load_json_file(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None


    def http_get_bytes(url, max_retries=5, timeout=90):
        last_err = RuntimeError('no attempts')
        for attempt in range(1, max_retries + 1):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'CWE-Browser/2.0'})
                with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
                    return resp.read()
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise
                last_err = e
            except Exception as e:
                last_err = e
            if attempt < max_retries:
                time.sleep(min(2 ** (attempt - 1), 30))
        raise last_err


    def fetch_api_json(path, max_retries=5):
        raw = http_get_bytes(API_BASE + path, max_retries=max_retries)
        return json.loads(raw.decode('utf-8'))


    def fetch_xml_ids(max_retries=5):
        print('Downloading official XML zip (authoritative ID source)...')
        raw = http_get_bytes(XML_ZIP_URL, max_retries=max_retries, timeout=120)
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            xml_name = next(n for n in z.namelist() if n.endswith('.xml'))
            xml_bytes = z.read(xml_name)
        tree = ET.fromstring(xml_bytes)

        def get_ids(tag):
            return sorted(
                {el.get('ID') for el in tree.findall(f'.//cwe:{tag}', XML_NS) if el.get('ID')},
                key=lambda x: int(x)
            )

        result = {
            'weaknesses': get_ids('Weakness'),
            'categories': get_ids('Category'),
            'views':      get_ids('View'),
        }
        print(f"XML parsed: {len(result['weaknesses'])} weaknesses, "
              f"{len(result['categories'])} categories, {len(result['views'])} views")
        return result


    class Downloader:
        def __init__(self, max_threads=8, max_retries=5):
            self.max_threads = max_threads
            self.max_retries = max_retries
            self._lock = threading.Lock()
            self.failed = []
            self.saved = 0
            self.skipped = 0

        def _fetch_one(self, api_path, out_file, force):
            if not force and os.path.exists(out_file):
                try:
                    with open(out_file, 'r', encoding='utf-8') as f:
                        json.load(f)
                    with self._lock:
                        self.skipped += 1
                    return
                except Exception:
                    pass
            try:
                data = fetch_api_json(api_path, max_retries=self.max_retries)
                changed = write_if_changed(data, out_file)
                with self._lock:
                    if changed:
                        self.saved += 1
                    else:
                        self.skipped += 1
            except Exception as e:
                with self._lock:
                    self.failed.append((api_path, str(e)))

        def run(self, tasks, force=False, label=''):
            total = len(tasks)
            done = [0]
            lock = threading.Lock()

            def wrapped(api_path, out_file):
                self._fetch_one(api_path, out_file, force)
                with lock:
                    done[0] += 1
                    if done[0] % 100 == 0 or done[0] == total:
                        pct = done[0] * 100 // total
                        print(f'  [{label}] {done[0]}/{total} ({pct}%)', flush=True)

            with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
                futures = [ex.submit(wrapped, p, f) for p, f in tasks]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception:
                        pass


    def _merge_summary(out_dir, name, ids, entry_dir, key):
        entries = []
        for eid in ids:
            data = load_json_file(os.path.join(entry_dir, f'{eid}.json'))
            if data:
                entries.append(data)
        write_if_changed({key: entries}, os.path.join(out_dir, f'{name}.json'))
        print(f'  {name}.json: {len(entries)}/{len(ids)} entries')


    def verify(out_dir, xml_ids=None):
        if xml_ids is None:
            xml_ids = fetch_xml_ids()
        all_ok = True
        for name, ids, subdir in [
            ('Weakness',  xml_ids['weaknesses'], 'weaknesses'),
            ('Category',  xml_ids['categories'], 'categories'),
            ('View',      xml_ids['views'],      'views'),
        ]:
            entry_dir = os.path.join(out_dir, subdir)
            missing = [eid for eid in ids if not os.path.exists(os.path.join(entry_dir, f'{eid}.json'))]
            corrupt = []
            for eid in ids:
                p = os.path.join(entry_dir, f'{eid}.json')
                if os.path.exists(p):
                    try:
                        with open(p, encoding='utf-8') as f:
                            json.load(f)
                    except Exception:
                        corrupt.append(eid)
            status = 'OK' if not missing and not corrupt else 'FAIL'
            print(f'  [{status}] {name}: {len(ids)} total, missing={len(missing)}, corrupt={len(corrupt)}')
            if missing:
                sample = missing[:20]
                print(f'    missing IDs: {sample}{"..." if len(missing) > 20 else ""}')
            if corrupt:
                print(f'    corrupt IDs: {corrupt}')
            if missing or corrupt:
                all_ok = False
        for fname, key in [('weaknesses.json', 'Weaknesses'), ('categories.json', 'Categories'), ('views.json', 'Views')]:
            p = os.path.join(out_dir, fname)
            data = load_json_file(p)
            count = len(data.get(key, [])) if data else 0
            expected = len(xml_ids[fname.replace('.json', '')])
            status = 'OK' if count == expected else 'FAIL'
            print(f'  [{status}] {fname}: {count}/{expected}')
            if count != expected:
                all_ok = False
        return all_ok


    def download_all(out_dir, incremental=False, force=False, max_threads=8, max_retries=5):
        ensure_dir(out_dir)
        print('Checking CWE version...')
        version = fetch_api_json('/cwe/version', max_retries=max_retries)
        ver_path = os.path.join(out_dir, 'version.json')
        remote_ver = version.get('ContentVersion') if isinstance(version, dict) else None
        if incremental and not force:
            local_ver = (load_json_file(ver_path) or {}).get('ContentVersion')
            if local_ver and local_ver == remote_ver:
                print(f'Version unchanged ({remote_ver}), incremental mode: nothing to do.')
                return
        write_if_changed(version, ver_path)
        print(f'Current version: {remote_ver}')

        xml_ids = fetch_xml_ids(max_retries=max_retries)

        # Weaknesses
        w_dir = os.path.join(out_dir, 'weaknesses')
        ensure_dir(w_dir)
        w_tasks = [(f'/cwe/weakness/{wid}', os.path.join(w_dir, f'{wid}.json')) for wid in xml_ids['weaknesses']]
        dl = Downloader(max_threads=max_threads, max_retries=max_retries)
        print(f'\\nFetching {len(w_tasks)} Weakness entries...')
        dl.run(w_tasks, force=force, label='Weakness')
        print(f'  saved={dl.saved}, skipped={dl.skipped}, failed={len(dl.failed)}')
        for p, e in dl.failed[:10]:
            print(f'    {p}: {e}')

        # Categories
        c_dir = os.path.join(out_dir, 'categories')
        ensure_dir(c_dir)
        c_tasks = [(f'/cwe/category/{cid}', os.path.join(c_dir, f'{cid}.json')) for cid in xml_ids['categories']]
        dl2 = Downloader(max_threads=max_threads, max_retries=max_retries)
        print(f'\\nFetching {len(c_tasks)} Category entries...')
        dl2.run(c_tasks, force=force, label='Category')
        print(f'  saved={dl2.saved}, skipped={dl2.skipped}, failed={len(dl2.failed)}')

        # Views
        v_dir = os.path.join(out_dir, 'views')
        ensure_dir(v_dir)
        v_tasks = [(f'/cwe/view/{vid}', os.path.join(v_dir, f'{vid}.json')) for vid in xml_ids['views']]
        dl3 = Downloader(max_threads=max_threads, max_retries=max_retries)
        print(f'\\nFetching {len(v_tasks)} View entries...')
        dl3.run(v_tasks, force=force, label='View')
        print(f'  saved={dl3.saved}, skipped={dl3.skipped}, failed={len(dl3.failed)}')

        # Merge summary files
        print('\\nMerging summary JSON files...')
        _merge_summary(out_dir, 'weaknesses', xml_ids['weaknesses'], w_dir, 'Weaknesses')
        _merge_summary(out_dir, 'categories', xml_ids['categories'], c_dir, 'Categories')
        _merge_summary(out_dir, 'views',      xml_ids['views'],      v_dir, 'Views')

        # Relations
        rel_dir = os.path.join(out_dir, 'relations')
        ensure_dir(rel_dir)
        all_ids = xml_ids['weaknesses'] + xml_ids['categories'] + xml_ids['views']
        rel_tasks = [
            (f'/cwe/{cid}/{rel}', os.path.join(rel_dir, f'{cid}_{rel}.json'))
            for cid in all_ids
            for rel in ('parents', 'children', 'descendants', 'ancestors')
        ]
        dl4 = Downloader(max_threads=max_threads, max_retries=max_retries)
        print(f'\\nFetching {len(rel_tasks)} relation files...')
        dl4.run(rel_tasks, force=force, label='Relations')
        print(f'  saved={dl4.saved}, skipped={dl4.skipped}, failed={len(dl4.failed)}')

        print('\\n--- Verify ---')
        verify(out_dir, xml_ids)
        print('Download complete.')


    def parse_args():
        p = argparse.ArgumentParser(description='CWE full database download & verify')
        p.add_argument('--out-dir',     default='data')
        p.add_argument('--incremental', action='store_true')
        p.add_argument('--force',       action='store_true')
        p.add_argument('--threads',     type=int, default=8)
        p.add_argument('--max-retries', type=int, default=5)
        p.add_argument('--verify-only', action='store_true')
        return p.parse_args()


    def main():
        args = parse_args()
        out_dir = os.path.abspath(args.out_dir)
        if args.verify_only:
            print(f'Verifying: {out_dir}')
            ok = verify(out_dir)
            sys.exit(0 if ok else 1)
        try:
            download_all(out_dir, incremental=args.incremental, force=args.force,
                         max_threads=args.threads, max_retries=args.max_retries)
        except KeyboardInterrupt:
            print('\\nInterrupted.')
            sys.exit(1)
        except Exception as e:
            print(f'ERROR: {e}', file=sys.stderr)
            sys.exit(2)


    if __name__ == '__main__':
        main()
""")

with open('src/download_cwe.py', 'w', encoding='utf-8') as f:
    f.write(code)
print('Rewrite OK, lines:', code.count('\n'))
