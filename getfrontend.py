import argparse
import base64
import hashlib
import html
import sys
import re
import time
import zipfile
import requests
import os
import json
import threading
import urllib3

from urllib.parse import urljoin, urlparse
from queue import Queue

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Logger:
    LOG = 1
    DEBUG = 2
    VERBOSE_DEBUG = 3

    def __init__(self):
        self.level = self.LOG

    def write(self, level, *args, **kwargs):
        if level <= self.level:
            print(*args, **kwargs, file=sys.stderr)

    def log(self, *args, **kwargs):
        self.write(self.LOG, *args, **kwargs)

    def debug(self, *args, **kwargs):
        self.write(self.DEBUG, *args, **kwargs)

    def vdebug(self, *args, **kwargs):
        self.write(self.VERBOSE_DEBUG, *args, **kwargs)


log = Logger()


class SourceMapError(Exception):
    pass


def normpath(path):
    # os.path.normpath allows //, we can't since these are protocol-relative urls
    path = os.path.normpath(path)

    if path.startswith('//'):
        path = path[1:]

    return path


class FArchive:
    def __init__(self):
        self.files = {}
        self.names = set()
        self.effective_names = {}

    def normalize_name(self, name):
        name = normpath('/' + name)[1:]
        return name

    def get_unique_name(self, name):
        base_name, ext = os.path.splitext(name)
        counter = 2
        while name in self.names:
            name = f"{base_name}_{counter}{ext}"
            counter += 1
        self.names.add(name)

        return name

    def add_file(self, name, content):
        name = self.normalize_name(name)

        content_hash = hashlib.md5(content).hexdigest()
        name_key = name + '//' + content_hash

        if self.effective_names.get(name + '//' + content_hash):
            # same name + existing content has means we can skip it
            return

        name = self.get_unique_name(name)
        self.effective_names[name_key] = name

        assert name not in self.files

        self.files[name] = content

    def write_to_file(self, wf):
        with zipfile.ZipFile(wf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for name, content in self.files.items():
                zf.writestr(name, content)

    def save_to_directory(self, path):
        os.makedirs(path, exist_ok=True)

        for name, content in self.files.items():
            file_path = os.path.join(path, name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            with open(file_path, 'wb') as f:
                f.write(content)

    def dump_to_stdout(self):
        for name, content in self.files.items():
            print(f"// {name}\n// [{len(content)}] bytes\n")
            print(content.decode())


class Client:
    def __init__(self, timeout: None | float | tuple[float, float] = (8, 16), cookies: dict | None = None, headers: dict | None = None):
        self.timeout = timeout
        self.sleep = 5
        self.rs = requests.Session()
        self.rs.verify = False

        if cookies:
            self.rs.cookies.update(cookies)

        if headers:
            self.rs.headers.update(headers)

    def request(self, method, url, *args, **kwargs):
        try:
            while True:
                try:
                    res = self.rs.request(method, url, *args, timeout=self.timeout, **kwargs)

                    if res.status_code in (408, 429, 500, 502, 503, 504):
                        log.log('retrying', url)
                        time.sleep(self.sleep)
                        continue

                    return res

                except requests.exceptions.RequestException as e:
                    log.log('non-status request error, retrying', url, e)
                    time.sleep(self.sleep)
                    continue

        except Exception as e:
            log.log('non-status request exception', url, e)
            return None

    def get(self, *args, **kwargs):
        return self.request('GET', *args, **kwargs)


class Fetcher:
    def __init__(self, client: Client, n_workers):
        self.input_queue = Queue()
        self.output_queue = Queue()
        self.client = client
        self.queued_urls = set()
        self.lock = threading.Lock()
        self.pending_urls = 0

        self.n_workers = n_workers
        for _ in range(n_workers):
            threading.Thread(target=self.worker).start()

    def queue(self, url, *args):
        # called from the main thread only

        if url not in self.queued_urls:
            self.pending_urls += 1
            self.queued_urls.add(url)
            self.input_queue.put([url, *args])

    def get_response(self):
        # called from the main thread only

        if not self.pending_urls:
            self.shutdown_workers()
            return None

        ret = self.output_queue.get()
        self.pending_urls -= 1
        return ret

    def worker(self):
        while True:
            arg = self.input_queue.get()
            if arg is None:
                break

            [url, *args] = arg

            response = self.client.get(url) # doesn't throw
            self.output_queue.put([url, response, *args])

    def shutdown_workers(self):
        for _ in range(self.n_workers):
            self.input_queue.put(None)


def prepare_link(link):
    if '?' in link:
        link = link.split('?', 1)[0]

    if '#' in link:
        link = link.split('#', 1)[0]

    return link


class Crawler:
    def __init__(self, gf, root, save_prefix=''):
        self.gf: GetFrontend = gf

        self.save_prefix = save_prefix # this also affects url assets
        self.root = root

        self.webpack_chunk_formats = []
        self.possible_webpack_chunk_ids = set()

    def check_prefix(self, link):
        if not self.gf.prefix_whitelist:
            return True

        for prefix in self.gf.prefix_whitelist:
            if link.startswith(prefix):
                return True

        return False

    def save_fetched_asset(self, path, content):
        # path is an url
        # this is meant for original assets

        path = re.sub(r'^(https?:)//', r'\1', path)
        return self.gf.save_asset(self.save_prefix + path, content)

    def save_mapped_asset(self, path, content, origin_path):
        return self.save_generated_asset(path, content, origin_path, 'mapped')

    def save_unpacked_asset(self, path, content, origin_path):
        return self.save_generated_asset(path, content, origin_path, 'unpacked')

    def save_generated_asset(self, path, content, origin_path, label):
        origin = re.search(r'https?://([^/]+)', origin_path).group(1)
        self.gf.save_asset(f'{self.save_prefix}{label}@{origin}/{path}', content)

    def queue(self, link, tag, *args):
        self.gf.fetcher.queue(link, self, tag, *args)

    def queue_link(self, link, tag=None, fallback=None):
        if not self.check_prefix(link) and not fallback:
            return

        link = prepare_link(link)

        if tag is None:
            if link.endswith('.css') and not self.gf.skip_css:
                tag = 'css'
            elif re.search(r'\.m?[jt]sx?$', link):
                tag = 'js'
            elif self.gf.other_asset_extensions and link.endswith('.webmanifest'):
                tag = 'webmanifest'
            elif self.gf.other_asset_extensions and re.search(rf'{self.gf.asset_ext_pat}$', link, flags=re.IGNORECASE):
                tag = 'asset'

        if not tag and fallback:
            tag = fallback

        if tag:
            self.queue(link, tag)

    def handle_result(self, url, response, mode, *args):
        response = self.gf.check_response(url, response)
        if response:
            if mode == 'dynamic':
                content_type = response.headers.get('content-type', '')
                if ';' in content_type:
                    content_type = content_type.split(';', 1)[0]

                match content_type:
                    case "text/javascript" | "application/javascript" | "application/x-javascript":
                        mode = 'js'
                    case "text/css":
                        mode = 'css'
                    case "text/html" | "application/xhtml+xml" | "application/xml":
                        mode = 'page'
                    case _:
                        mode = 'asset'

                log.debug('dynamic mode detected as', mode, 'for url', url)

            match mode:
                case "page":
                    self.handle_html_response(url, response)
                case "nextjs":
                    self.handle_nextjs_manifest(url, response)
                case "js":
                    self.handle_js(url, response)
                case "css":
                    self.handle_css(url, response)
                case "remote_entry_js":
                    self.handle_remote_module(url, response, *args)
                case "webmanifest":
                    self.handle_webmanifest(url, response)
                case "asset":
                    self.handle_asset(url, response)

    def handle_js_data(self, content, path, skip_sourcemaps=False):
        self.find_webpack_chunk_info(content, path)
        self.find_federated_modules(content, path)
        self.find_webpack_chunk_refs(content, path)
        self.find_vite_chunks(content, path)
        self.unpack_webpack_eval_sources(content, path)

        if not skip_sourcemaps:
            self.handle_content_sourcemaps(content, path)

        # module scan, here we might encounter absolute links
        for module_link in find_import_references(content, path):
            self.queue_link(module_link)

        self.find_imported_scripts(content, path)
        self.find_workers(content, path)
        self.find_manifests(content, path)

        if self.gf.aggressive_mode:
            self.run_aggressive_scan(content, path)

    def handle_js(self, url, res):
        res = self.gf.decode_response(res)

        skip_sourcemaps = False

        if self.gf.ignore_vendor:
            last_part = url.rsplit('/', 1)[-1]
            if re.match(r'(chunk[-.])?vendors?[-.]', last_part):
                skip_sourcemaps = True
                log.debug('skipping maps for', url, 'due to vendor detection')

        self.handle_js_data(res, url, skip_sourcemaps=skip_sourcemaps)

        should_save = True

        if not skip_sourcemaps:
            # it's often the case that there wasn't a comment but a sourcemap exists
            # we don't queue because we need the result here
            if self.fetch_and_handle_srcmap(url + '.map'):
                should_save = False

        if should_save or self.gf.save_original_assets:
            self.save_fetched_asset(url, res.encode())

    def handle_css_data(self, content, path):
        self.handle_content_sourcemaps(content, path)

        url_pat = r'''(?<![a-zA-Z0-9$_])url\(\s*['"]?(?!data:)([^'")]+)'''
        import_pat = rf'''@import(?:\s*['"]([^'"]+)['"]|\s+{url_pat})'''

        for m in re.finditer(import_pat, content):
            link = urljoin(path, m.group(1) or m.group(2))
            log.log('adding css import', link)
            self.queue_link(link, 'css')

        if self.gf.other_asset_extensions:
            for m in re.finditer(url_pat, content):
                link = urljoin(path, m.group(1))
                log.log('adding css url asset', link)
                self.queue_link(link)

    def handle_css(self, path, res):
        res = self.gf.decode_response(res)

        self.handle_css_data(res, path)

        should_save = True

        if self.fetch_and_handle_srcmap(path + '.map'):
            should_save = False

        if should_save or self.gf.save_original_assets:
            self.save_fetched_asset(path, res.encode())

    def handle_content_sourcemaps(self, content, path, inline_only=False):
        had_sourcemap = False

        # url sourcemaps.. we normally append .map
        # and normally there should be only one
        # otherwise that's probably spam (like nonexisting files inside eval)
        sourcemap_urls = re.findall(r'sourceMappingURL=(?!data:application/json)([^\s?#*]+)', content)
        if not inline_only and (len(sourcemap_urls) < 2 or self.gf.all_srcmap_urls):
            for src_map in sourcemap_urls:
                link = urljoin(path, src_map)
                if self.fetch_and_handle_srcmap(link):
                    had_sourcemap = True

        json_map_contents = []

        # iterate inline sourcemaps
        for m in re.finditer(r'sourceMappingURL=data:application/json;(?:charset=([^;]+);)?base64,([A-Za-z0-9/+]+)', content):
            charset = m.group(1) or 'utf-8'
            map_content = base64.b64decode(m.group(2) + '==').decode(charset)
            json_map_contents.append(map_content)

        # iterate JSON-embedded sourcemaps (example observed in css-loader)
        if '{"version":3,"sources":[' in content and '"sourcesContent":[' in content:
            str_pat_part = r'"(?:(?:\\.|[^"\\]+)*)"'
            str_arr_pat_part = rf'\[(?:{str_pat_part},?)*\]'

            for m in re.finditer(rf'\{"{"}"version":3,"sources":{str_arr_pat_part}(?:,{str_pat_part}:(?:{str_pat_part}|{str_arr_pat_part}))+\{"}"}', content):
                log.debug(f'found embedded source map at {path}')
                map_content = m.group(0)
                json_map_contents.append(map_content)

        for map_content in json_map_contents:
            try:
                data = json.loads(map_content)
                self.handle_srcmap_data(data, path)
                had_sourcemap = True
            except (json.decoder.JSONDecodeError, SourceMapError) as e:
                log.debug(f'warn: inline sourcemap at {path} was not correct', e)

        return had_sourcemap

    def handle_nextjs_manifest(self, url, res):
        res = self.gf.decode_response(res)
        base = url[:url.index('/_next/') + len('/_next/')]

        if self.gf.save_original_assets:
            self.save_fetched_asset(url, res.encode())

        res = res.replace('\\u002F', '/')

        for m in re.finditer(r'''"(static/(?:chunks|css)/[^"]+\.(m?jsx?|css))([#?][^"]*)?"''', res):
            link = urljoin(base, m.group(1))
            log.log('adding nextjs chunk from manifest', link)
            self.queue_link(link)

        if self.gf.aggressive_mode:
            self.run_aggressive_scan(res, url)

    def handle_webmanifest(self, url, res):
        res = self.gf.decode_response(res)
        if not res:
            return

        self.save_fetched_asset(url, res.encode())
        self.run_aggressive_scan(res, url)

    def handle_asset(self, url, res):
        self.save_fetched_asset(url, res.content)

    def fetch_and_handle_srcmap(self, path):
        if path in self.gf.fetched_sourcemaps:
            return self.gf.fetched_sourcemaps[path]

        ok = True

        url = urljoin(self.root, path)
        response = self.gf.get_url(url)
        if not response:
            log.log(f'no source map at {path}')
            self.gf.fetched_sourcemaps[path] = False
            return

        try:
            try:
                data = response.json()
            except Exception:
                raise SourceMapError('not json')

            self.handle_srcmap_data(data, path)

        except SourceMapError as e:
            log.log(f'source map at {path} error:', e)
            ok = False

        self.gf.fetched_sourcemaps[path] = ok

        return ok

    def _prepare_mapped_asset(self, name, content, real_dir=None):
        if name.startswith('webpack://'):
            name = name[len('webpack://'):]

        # not sure if we could normalize the name..
        name = re.sub(r'(\/|^)\.(?=\/|$)', r'', name)
        name = re.sub(r'(\/|^)\.\.(?=\/|$)', '\1_', name)

        if name.startswith('/'):
            name = name[1:]

        if '/' not in name and real_dir:
            log.debug('using real_dir prefix', real_dir)
            name = real_dir + '/' + name

        name = re.sub(r'//+', r'/', name)

        if '?' in name:
            left, right = name.split('?', 1)

            if '/' in right or '?' in right:
                log.debug('unusual name', name)

            right = '_' + re.sub(r'[^a-zA-Z0-9_.-]', '_', right)

            base_name, ext = os.path.splitext(left)

            name = base_name + right + ext
        else:
            base_name, ext = os.path.splitext(name)

        # content processing, for example unpack angular .html
        content = self.process_src_asset(name, ext, content)

        return name, content

    def handle_srcmap_data(self, data, origin):
        real_dir = None

        try:
            try:
                if len(data['sources']) != len(data['sourcesContent']):
                    log.debug('warn: invalid source map sources length in', origin)
            except KeyError:
                raise SourceMapError('no sources content')

            if 'file' in data and '!.' in data['file']:
                last_part = data['file'].rsplit('!.', 1)[-1]
                file_part = last_part.split('?', 1)[0]

                real_dir = os.path.dirname(file_part)

                if real_dir.startswith('/'):
                    real_dir = real_dir[1:]

                # for webpack, this might be a chain, but it could give us the idea
                # of the original file location, as sometimes the location in
                # ['sources'] might not be complete

            for x in range(min(len(data['sources']), len(data['sourcesContent']))):
                if not data['sourcesContent'][x]:
                    # yeah, it can happen
                    continue

                name = data['sources'][x]
                content = data['sourcesContent'][x]

                # ignore names here
                if name.endswith('/'):
                    log.debug('skipping source map entry: name', name, 'ends with a slash, content is', content)
                    continue

                name, content = self._prepare_mapped_asset(name, content, real_dir=real_dir)

                # nested source maps? not practically useful
                if self.gf.extract_nested_sourcemaps:
                    self.handle_content_sourcemaps(content, origin, True)

                self.save_mapped_asset(name, content.encode(), origin)

        except (TypeError, ValueError) as e:
            raise SourceMapError(f'invalid data {e}')

    def process_src_asset(self, name, ext, content):
        # currently we only unpack html templates here
        if ext == '.html':
            if m := re.match(r'^(?:module\.exports\s*=\s*|export default\s+)(".+");?\s*(\n\s*//[^\n]*)*$', content):
                try:
                    json_content = json.loads(m.group(1))
                    log.debug('replacing html', name)
                    return json_content
                except json.decoder.JSONDecodeError:
                    pass

        return content

    def find_workers(self, content, current_path):
        worker_pat = r'''(?:[^a-zA-Z0-9$_]new\s+(?:Shared)?Worker|navigator\.serviceWorker\.register)\s*\(\s*(?!data:)['"]([^'"]+)['"]\s*[,)]'''
        for m in re.finditer(worker_pat, content):
            link = urljoin(self.root, m.group(1))
            log.log('adding worker', link)
            self.queue_link(link, tag='js')

    def find_imported_scripts(self, content, current_path):
        pat = r'''(?:^|[^a-zA-Z0-9_$])importScripts\s*\(\s*((?:['"][^'"]+['"],?\s*)+)\)'''
        for m in re.finditer(pat, content):
            for mv in re.finditer(r'''['"]([^'"]+)['"]''', m.group(1)):
                link = urljoin(current_path, mv.group(1))
                log.log('adding imported script', link)
                self.queue_link(link, tag='js')

    def find_manifests(self, content, current_path):
        # search for remix manifest
        if '/manifest-' in current_path:
            if content.startswith('window.__remixManifest={'):
                for m in re.finditer(r'"(/[^"]+\.js)(?:[?#][^"]*)?', content):
                    link = urljoin(self.root, m.group(1))
                    log.log('adding remix link', link)
                    self.queue_link(link)

    def find_vite_chunks(self, content, current_path):
        # limited vite support, we rely on duplication to find the base path..
        # .js files are picked up by imports, but .css files seem to only be here
        vite_file_pat = r'''['"]([^'"]+)['"]'''
        vite_pat = rf'(?:__vite__fileDeps|__vite__mapDeps\.viteFileDeps)\s*=\s*\[\s*((?:{vite_file_pat},?\s*)+)\]'

        had_vite_deps = False
        vite_deps = []

        for m in re.finditer(vite_pat, content):
            for mf in re.finditer(vite_file_pat, m.group(1)):
                had_vite_deps = True
                dep = mf.group(1)

                if dep.startswith('.'):
                    chunk_path = urljoin(current_path, dep)
                    log.log('adding vite2 rel', chunk_path)
                    self.queue_link(chunk_path)
                else:
                    vite_deps.append(dep)

        vite_base = None
        if vite_deps:
            # process deps that have base
            vite_base = None

            # we need at least one import to find the base path

            if m := re.search(rf'''\(\s*\(\)\s*=>\s*import\({vite_file_pat}\),\s*__vite__mapDeps\(\[(\d+)''', content):
                proper_path = urljoin(current_path, m.group(1))
                dep_path = vite_deps[int(m.group(2))]

                assert proper_path.endswith(dep_path)

                vite_base = proper_path[:-len(dep_path)]
                log.debug('vite base', vite_base)
            else:
                log.debug('failed to find vite base path')
                vite_base = self.root

            if vite_base:
                for dep in vite_deps:
                    chunk_path = urljoin(vite_base, dep)
                    log.log('adding vite', chunk_path)
                    self.queue_link(chunk_path)

        elif not had_vite_deps:
            # the older variant with no __vite__mapDeps
            # here we use the first import to derive the base path

            for m in re.finditer(rf'''\(\s*\(\)\s*=>\s*import\({vite_file_pat}\),\s*\[\s*(({vite_file_pat},?\s*)+)''', content):
                deps = []
                for dm in re.finditer(vite_file_pat, m.group(2)):
                    chk = dm.group(1)
                    if chk.startswith('.'):
                        chunk_path = urljoin(current_path, chk)
                        log.log('adding vite1 rel', chunk_path)
                        self.queue_link(chunk_path)
                    else:
                        deps.append(chk)

                if not deps:
                    continue

                # now we have those that require a base

                if not vite_base:
                    proper_path = urljoin(current_path, m.group(1))
                    dep_path = deps[0]

                    if not proper_path.endswith(dep_path):
                        # that's not vite...
                        continue

                    vite_base = proper_path[:-len(dep_path)]
                    log.debug('vite base2', vite_base)

                for dep in deps:
                    chunk_path = urljoin(vite_base, dep)
                    log.log('adding vite2', chunk_path)
                    self.queue_link(chunk_path)

    def unpack_webpack_eval_sources(self, content, current_path):
        for m in re.finditer(r'''[\n{]eval\s*\(\s*(?:"((?:\\.|[^"\\])+)"|'((?:\\.|[^'\\])+)')\s*\)''', content):
            src = ''

            if src := m.group(2): # transform single quotes so we can decode as json
                src = src.replace("\\'", "'").replace('"', '\\"')
            else:
                src = m.group(1)

            if '//# sourceURL=' not in src:
                continue

            src = json.loads('"' + src + '"')

            if m := re.search(r'\n//# sourceURL=([^\n?]+)[?]?', src):
                name = m.group(1)
                content = src[:m.start()]

                name, content = self._prepare_mapped_asset(name, content)
                log.debug('unpacking eval asset', name, 'from', current_path)
                self.save_unpacked_asset(name, content.encode(), current_path)

    def add_webpack_chunk_format(self, fmt):
        self.webpack_chunk_formats.append([fmt, set()])

    def add_possible_webpack_chunk_id(self, chunk_id):
        self.possible_webpack_chunk_ids.add(chunk_id)

    def queue_possible_webpack_chunks(self):
        for resolve, queued in self.webpack_chunk_formats:
            for chunk_id in self.possible_webpack_chunk_ids - queued:
                self.queue_link(resolve(chunk_id))

            queued.update(self.possible_webpack_chunk_ids)

    def find_webpack_chunk_info(self, res, current_path):
        # todo: this vs remote? what if we encounter remoteEntry.js

        # this works since 2015
        is_webpack_chunk_runtime = 'ChunkLoadError' in res or "'Loading chunk '" in res or '"Loading chunk "' in res or 'Automatic publicPath is not supported in this browser' in res

        if not is_webpack_chunk_runtime:
            return

        res = res.replace('\\u002F', '/')

        if current_path in self.gf.public_path_map:
            public_path = self.gf.public_path_map[current_path]
        
        else:
            public_path = ''

            # note for paths like someVariable + sth, we assume someVariable is empty
            for m in re.finditer(r'''(?:\w|__webpack_require__)\.p\s*=(\s*[\w.]+\s*\+)?\s*(?P<quot>['"])(?P<path>[^'"]*)(?P=quot)\s*[,;})]''', res):
                # we pick the last one
                public_path = m.group('path')

            if 'Automatic publicPath is not supported in this browser' in res:
                # in one case it was relative to the script.. is it always true for automatic publicpath?
                # EDIT: well, no... need more data
                public_path = urljoin(current_path, 'abc')[:-3]

            # public_path is sometimes empty.. in that case it won't work with urljoin, we assume the root folder is used
            if public_path == '':
                public_path = urljoin(self.root, 'abc')[:-3]

            # relative to root, not the script
            public_path = urljoin(self.root, public_path)

        log.debug('webpack public path for', current_path, 'is', public_path)

        # first we need some cleanup, clean /******/ then clean // comments
        wr = re.sub(r'/\*{3,}/', ' ', res)
        # be careful not to trip strings like https://
        wr = re.sub(r'\n\s*//.*', ' ', wr)

        # resolve full hashes
        def make_hash_repl(target):
            def hash_repl(m):
                ret = target
                if maxlen := m.group('maxlen'):
                    log.debug('maxlen', maxlen)
                    ret = target[:int(maxlen)]

                return '"' + ret + '"'

            return hash_repl

        hash_maxlen_pat = r'(?:\.(?:slice|substr(?:ing)?)\(\s*0,\s*(?P<maxlen>\d+)\))?'

        if 'hotCurrentHash' in wr and (full_hash := re.search(r'[^a-zA-Z0-9$_]hotCurrentHash\s*=\s*"(?P<hash>[a-fA-F0-9]+)"', wr)):
            full_hash = full_hash.group('hash')
            log.debug('hotcurrenthash', full_hash)
            wr = re.sub(rf'hotCurrentHash{hash_maxlen_pat}', make_hash_repl(full_hash), wr)

        last_match = None
        for m in re.finditer(r'''(__webpack_require__|\w)\.h\s*=\s*(?:function\s*\(\s*\)\s*\{\s*return(?![a-zA-Z0-9$_])|\(\s*\)\s*=>(?:\s*\{\s*return(?![a-zA-Z0-9$_]))?)\s*(?:\(\s*)?['"](?P<hash>[^'"]+)['"]''', wr):
            last_match = m

        if m := last_match:
            full_hash = m.group('hash')
            log.debug('replacing full hash', full_hash)
            wr = re.sub(rf'(?<![a-zA-Z0-9_$])(__webpack_require__|\w)\.h\(\){hash_maxlen_pat}', make_hash_repl(full_hash), wr)

        wr = re.sub(r'"\s*\+\s*"', '', wr) # clean concatenated strings, must be done also after replacing hashes

        # also need scoring for this "big" part

        r1v_func = r'(?:function(?:\s+\w+|\s*)\(\s*\w+\s*\)\s*\{\s*|\(?\s*?\w+\s*\)?\s*=>\s*(?:\{\s*|\(\s*)?)'
        r1v_func_start = r'(?:function(?:\s+\w+|\s*)\(\s*\w+\s*\)\s*\{\s*|=>\s*(?:\{\s*|\(\s*)?)' # optimized

        static_path_param = r'''['"]\s*\+\s*\w+\s*\+\s*['"]'''
        static_path_inner_pat = rf'''[^'"]+(?:{static_path_param}[^'"]+)?'''
        static_multi_ids_pat = r'''\{(?:(?:\d+(?:e\d+)|['"][^'"]+['"]):1,?)+\}\s*\[\w+\]'''
        static_chunk_pat1 = rf'''if\s*\((?:\w+\s*===\s*(?P<static1_id>\d+(?:e\d+)|['"][^'"]+['"])|(?P<static1_ids>{static_multi_ids_pat}))\)\s*return\s*['"](?P<static1_path>{static_path_inner_pat})['"]\s*;\s*'''
        static_chunk_pat2 = rf'''(?:(?P<static2_id>\d+(?:e\d+)|['"][^'"]+['"])===\w+|(?P<static2_ids>{static_multi_ids_pat}))\?['"](?P<static2_path>{static_path_inner_pat})['"]:'''

        start_v1 = rf'(?:{r1v_func_start}(return(?![a-zA-Z0-9$_])\s*\(?\s*)?|\.src\s*=\s*(?:\([^;]{"{,5}"})?)(?:\w|__webpack_require__)\.p\s*\+'
        # return is possible in two locations depending on static_chunks variant
        start_v2 = rf'\.u\s*=\s*{r1v_func}(return(?![a-zA-Z0-9$_])\s*\(?\s*)?(?P<static_chunks>(?:{static_chunk_pat1}|{static_chunk_pat2})+)?(return(?![a-zA-Z0-9$_])\s*\(?\s*)?'

        prefix_pat = r'''['"](?P<prefix>[^"' ]*)['"]'''

        # premap can be identity or in a compact form
        # but... there might be no premap.. we saw this with federated modules
        premap_pat = r'''(?:\(\s*\{(?P<premap>[^{}]*)\}\s*\[(?:\s*\w+\s*=)?\s*\w+\s*\]\s*\|\|\s*\w+\s*\)|\{(?P<premap_e>[^{}]*)\}\s*\[(?:\s*\w+\s*=)?\s*\w+\s*\]|\((?:(?P<cpm_id>\d+)\s*===\s*\w+|\w+\s*===\s*(?P<cpm_id_2>\d+))\s*\?\s*"(?P<cpm_value>[^"]+)"\s*:\s*\w+\)|(?P<identity>\w+))'''

        # exhaustive maps
        map_pat = r'''(?:['"](?P<sep>[^"' ]*)['"]\s*\+\s*)?\{(?P<map>[^{}]*)\}\s*\[(?:\w+\s*=\s*)?\w+\]'''

        qmap_pat_common = r'''\?\w+=)['"]\s*\+\s*\{(?P<qmap>[^{}]*)\}\s*\[(?:\w+\s*=\s*)?\w+\]\s*[,;]'''
        qmap_pat = r'''['"](?P<qmap_sep>[^"' ]*\.m?jsx?''' + qmap_pat_common
        qmap_css_pat = r'''['"](?P<qmap_sep>[^"' ]*\.css''' + qmap_pat_common

        suffix_pat = r'''(?:['"](?P<suffix>[^"']*\.m?jsx?)(?:\?t=\d+)?['"]\s*[^+]|(?P<void_suffix>(?<=:)void\(?\s*0\s*\)?|undefined))'''

        def parse_chunk_match(m, search_static=False):
            prefix = m.group('prefix') or ''
            suffix = m.group('suffix') or ''

            known_ids = set()
            exhaustive = False

            # premap should be constructed for the chunk format...
            # either from parse chunkmap if a dict, or from cm map
            # or identity
            # empty premap is not truthy but it's not "None", can't use "or"
            if m.group('premap_e') is not None:
                pm = m.group('premap_e')
                exhaustive = True
            else:
                pm = m.group('premap')

            if pm is not None:
                premap = parse_chunkmap(pm)
                known_ids.update(premap.keys())
            elif cid := m.group('cpm_id') or m.group('cpm_id_2'):
                premap = {cid: m.group('cpm_value')}
                known_ids.add(cid)
            elif m.group('identity'):
                premap = {}
            else:
                premap = None

            cmap = m.group('map') or m.group('qmap')
            if cmap:
                cmap = parse_chunkmap(cmap)
                known_ids.update(cmap.keys())
                exhaustive = True

            if m.group('qmap'):
                sep = m.group('qmap_sep')
            else:
                sep = m.group('sep') or ''

            static_map = {}
            if search_static:
                if sp := m.group('static_chunks'):
                    for sm in re.finditer(rf'{static_chunk_pat1}|{static_chunk_pat2}', sp):
                        chunk_ids = []

                        if single_id := sm.group('static1_id') or sm.group('static2_id'):
                            chunk_ids.append(parse_chunk_id(single_id))
                        else:
                            ids = sm.group('static1_ids') or sm.group('static2_ids')
                            for scm in re.finditer(r'''(\d+(?:e\d+)|['"][^'"]+['"]):1''', ids):
                                chunk_ids.append(parse_chunk_id(scm.group(1)))

                        path_src = sm.group('static1_path') or sm.group('static2_path')

                        for chunk_id in chunk_ids:
                            chunk_path = re.sub(static_path_param, chunk_id, path_src)
                            log.debug('static path', chunk_path)
                            static_map[chunk_id] = chunk_path
                            known_ids.add(chunk_id)

                    log.debug('static path map', static_map)

            def resolve(chunk_id):
                if chunk_id in static_map:
                    chunk_path = static_map[chunk_id]
                else:
                    chunk_path = premap.get(chunk_id, chunk_id) if premap is not None else ''
                    chunk_path += sep + (cmap[chunk_id] if cmap else '')
                    chunk_path = prefix + chunk_path + suffix

                return urljoin(public_path, chunk_path)

            depends_on_id = static_map or premap is not None or cmap

            return depends_on_id, known_ids, exhaustive, resolve

        has_exhaustive_chunks = False

        pattern = rf'(?:{start_v1}|{start_v2})\s*(?:{prefix_pat}\s*\+\s*)?(?:{premap_pat}\s*\+\s*)?(?:{qmap_pat}|(?:{map_pat}\s*\+\s*)?{suffix_pat})'

        last_match = None
        for m in re.finditer(pattern, wr):
            last_match = m

        if m := last_match:
            depends_on_id, known_ids, exhaustive, resolve = parse_chunk_match(m, True)
            log.debug('webpack match result', current_path, known_ids)

            # the js version should depend on the id somehow..
            if not depends_on_id:
                log.log('webpack: no premap and no map', current_path)

            if exhaustive:
                has_exhaustive_chunks = True
                # here we don't add the chunk format deliberately

                for chunk_id in known_ids:
                    self.queue_link(resolve(chunk_id))

            else:
                self.add_webpack_chunk_format(resolve)
                for chunk_id in known_ids:
                    self.add_possible_webpack_chunk_id(chunk_id)

                self.queue_possible_webpack_chunks()

        if not self.gf.skip_css:
            suffix_css_pat = r'''['"](?P<suffix>[^"']*\.css)(?:\?t=\d+)?['"]\s*[^+]'''
            css_pattern = rf'(?P<prelude>\.miniCssF\s*=\s*{r1v_func}(return(?![a-zA-Z0-9$_])\s*)?|(?:for\s*\(|\{"{"})\s*var \w+\s*=)\s*(?:{prefix_pat}\s*\+\s*)?(?:{premap_pat}\s*\+\s*)?(?:{qmap_css_pat}|(?:{map_pat}\s*\+\s*)?{suffix_css_pat})'

            last_match = None
            for m in re.finditer(css_pattern, wr):
                last_match = m

            # css chunks.. they're always exhaustive (a subset of js chunks?)
            if m := last_match:
                has_css_map = None

                # try to find the 01 map, a subset of emap
                if 'var ' in m.group('prelude'):
                    # in this case we match the map..  backwards
                    if m2 := re.search(r'''(?:[;,]|\]\s*\w+\s*\[)\}\s*((?:,?1\s*:\s*(?:\d+(?:e\d+)|["'][^'"]*['"])\s*)+)\{''', wr[:m.start()][::-1]):
                        has_css_map = m2.group(1)[::-1]

                else:
                    # the map is inside the minicss
                    if m2 := re.search(r'''\.miniCss\s*=\s*(?:function|\().*?\{(\s*((?:\d+(?:e\d+)|["'][^'"]*['"])\s*:\s*1,?\s*)+)\}''', wr, flags=re.DOTALL):
                        has_css_map = m2.group(1)

                if has_css_map is not None:
                    cstr = has_css_map
                    has_css_map = set()

                    for cid in re.findall(r'''([a-zA-Z0-9_$]+|['"][^'"]+['"])\s*:\s*1,?''', cstr):
                        has_css_map.add(parse_chunk_id(cid))

                depends_on_id, known_ids, exhaustive, resolve = parse_chunk_match(m)
                log.debug('css chunks', has_css_map, known_ids)

                if not depends_on_id and not has_css_map:
                    # corner case: only one chunk... :D
                    has_css_map = set([''])

                if has_css_map is None:
                    # basically this.. "should not happen"
                    # might happen if css chunks not used
                    log.log('webpack: no css bitmap', current_path)

                    has_css_map = set()
                    for chunk_id in known_ids:
                        has_css_map.add(chunk_id)

                for chunk_id in has_css_map:
                    self.queue_link(resolve(chunk_id))

        if not has_exhaustive_chunks:
            # these are all inside the webpack runtime, not other chunks
            # preload/prefetch maps

            chunk_id_pat = r'\d+(?:e\d+)|"[^"]+"' # map keys might be strings

            for pm in re.finditer(r'var \w+\s*=\s*\{(?P<map>[^{}]+)\};\s*(__webpack_require__|\w)\.f\.pre(?:load|fetch)\s*=', wr):
                for pcm in re.finditer(rf'({chunk_id_pat})\s*:\s*\[([^\[\]]+)\]', pm.group('map')):
                    chunk_id = parse_chunk_id(pcm.group(1))
                    log.debug('adding dephead', chunk_id)
                    self.add_possible_webpack_chunk_id(chunk_id)

                    for pcmc in re.finditer(chunk_id_pat, pcm.group(2)):
                        chunk_id = parse_chunk_id(pcmc.group(0))
                        log.debug('adding depchild', chunk_id)

                        self.add_possible_webpack_chunk_id(chunk_id)

            # startup prefetch
            for pm in re.finditer(r'\[([^\[\]]+)\]\.map\((?:__webpack_require__|\w)\.E\)', wr):
                for pmc in re.finditer(chunk_id_pat, pm.group(1)):
                    chunk_id = parse_chunk_id(pmc.group(0))
                    log.debug('adding startup', chunk_id)
                    self.add_possible_webpack_chunk_id(chunk_id)

            self.queue_possible_webpack_chunks()

    def find_webpack_chunk_refs(self, res, current_path):
        # first we need some cleanup, clean /******/ clean // comments, clean escapes
        # note these refs can be inside eval
        wr = re.sub(r'/\*{3,}/|\\[nt]', ' ', res)
        wr = re.sub(r'\n\s*//.*', ' ', wr) # be careful not to trip strings like https://
        wr = wr.replace(r'\"', '"')

        req_pat = r'(?:__webpack_require__|__nested_webpack_require_\d+__|\w)\.e'

        # search for context maps (for dynamic require support)
        # these probably aren't exhaustive
        # we simply look for all integers and strings except map keys and first items
        chunk_id_pat = r'[{,]\s*(\d+(?:e\d+)|"[^"]+")(?!\s*:)'

        added = False

        if re.search(rf'Promise\.all\(\w+\.slice\(\d+\)\.map\({req_pat}\)|return\s+(?:\w\s*\?\s*)?{req_pat}\(\w+\[[1-3]\]\)\.then', wr):
            # we need to find a map, but we don't really know which variable is correct
            # keys in this context map are strings

            map_found = False

            for m in re.finditer(r'''var \w+\s*=\s*\{((['"][^'"]*['"]|[\[\],\s:]|[0-9e])+)\}''', wr):
                log.debug('async context: found map variable', m.group(1))
                map_found = True

                for md in re.finditer(chunk_id_pat, m.group(1)):
                    chunk_id = parse_chunk_id(md.group(1))
                    log.debug('adding chunk from context map', chunk_id)
                    self.add_possible_webpack_chunk_id(chunk_id)
                    added = True

            assert map_found

        # search for possible ensure references, they might contain comments
        # chunk ids can also be strings..
        # now we try to avoid false positives, so we assume no spaces inside

        chunk_id_pat = r'''\d+(?:e\d+)|['"][^"'\s]+['"]'''
        chunk_ref_pat = rf'(?:__webpack_require__|__nested_webpack_require_\d+__|\W\w)\.e\((?:/\*.*?\*/\s*)?({chunk_id_pat})\)'

        for m in re.finditer(chunk_ref_pat, wr):
            chunk_id = parse_chunk_id(m.group(1))
            log.debug('adding manual chunk', chunk_id)
            self.add_possible_webpack_chunk_id(chunk_id)
            added = True

        if added:
            self.queue_possible_webpack_chunks()

    def find_federated_modules(self, res, current_path):
        for m in re.finditer(r'''new Promise\([^&}]*?['"](https?://[^'"?#]+.js)(?:[?#][^'"]*)?['"][^{]+\{[^{}]*?['"]ScriptExternalLoadError['"][^{'"]+['"]([^'"]+)['"]''', res):
            url, app_name = m.group(1), m.group(2)

            log.log('adding federated module', m.group(1), m.group(2))
            self.queue(url, 'remote_entry_js', app_name)

    def handle_remote_module(self, url, res, app_name):
        res = self.gf.decode_response(res)

        # it's not mapped, so save it as is
        self.save_fetched_asset(url, res.encode())

        # we need public path, but it needs to be absolute
        public_path = re.search(r'''(?:\w|__webpack_require__)\.p\s*=\s*['"](https?://[^'"?#]+/)''', res)
        assert public_path
        public_path = public_path.group(1)

        log.debug('remote module', app_name, 'path', public_path)
        rm_crawler = Crawler(self.gf, public_path, f'module:{app_name}/')

        # just send this js file to the new crawler, it should handle it all
        rm_crawler.handle_js_data(res, url)

    def run_aggressive_scan(self, content, path):
        # todo: should we scan css url here? would only matter for non-quoted

        content = re.sub(r'\\u002f', '/', content, flags=re.IGNORECASE)
        content = re.sub(r'\\u005c', '\\\\', content, flags=re.IGNORECASE)
        content = re.sub(r'''\\(['"])''', r'\1', content)
        content = re.sub(r'\\[nrt]', ' ', content)
        content = re.sub(r'\\/', '/', content)

        for m in re.finditer(self.gf.aggressive_rel_pat, content, flags=re.IGNORECASE):
            # two variants - relative to the script or relative to the document

            lpart = m.group(1).replace('\\', '')
            link = urljoin(path, lpart)
            link2 = urljoin(self.root, lpart)

            log.log('aggressive rel match', path, link)
            self.queue_link(link)

            if link != link2:
                log.log('aggressive rel doc match', path, link2)
                self.queue_link(link2)

        for m in re.finditer(self.gf.aggressive_abs_pat, content, flags=re.IGNORECASE):
            link = urljoin(path, m.group(0).replace('\\', ''))
            log.log('aggressive abs match', path, link)
            self.queue_link(link)

    def find_nextjs_chunks(self, content, links):
        has_manifest = False
        next_path = None

        for link in links:
            if '/_next/static/' not in link:
                continue

            if not next_path:
                next_path = urljoin(self.root, link[:link.index('/_next/static/') + len('/_next/')])

            if '/_next/static/chunks/' not in link and link.endswith('/_buildManifest.js'):
                has_manifest = True
                log.log('adding next.js manifest', link)
                self.queue(link, 'nextjs')

        if has_manifest or not next_path:
            return

        content = content.replace('\\u002F', '/')
        content = content.replace(r'\"', '"')

        for m in re.finditer(r'"(?:_next/|\d+:)?(static/(?:chunks|css)/[^"]+\.(?:m?jsx?|css))(?:[#?][^"]*)?"', content):
            link = next_path + m.group(1)
            log.log('adding nextjs chunk from non-manifest', link)
            self.queue_link(next_path + m.group(1))

    def handle_html_response(self, url, response):
        links = []

        if link_header := response.headers.get('link'): # multiple are joined by comma
            for m in re.finditer(r'<([^>?#]+)', link_header):
                log.debug('preload header', m.group(1))
                links.append(m.group(1))

        html_content = self.gf.decode_response(response)

        # generally should guess as much as we can from html
        # we assume there's only one html source

        # we intentionally want to catch attributes like data-href
        for m in re.finditer(r'''(?:href|src)\s*=\s*(?:['"]|(?=/))(?!data:)([^"'?#> ]+)''', html_content):
            log.debug('link', m.group(1))
            links.append(m.group(1))

        # here we actually want to avoid false positives
        if not self.gf.ignore_base_tag and (m := re.search(r'''<base (?:[^>]+ )?href\s*=\s*['"]([^'">]+)['"]''', html_content)):
            url = urljoin(url, m.group(1))
            log.log('base url changed to', url)

        links = [urljoin(url, prepare_link(link)) for link in links]
        links = [link for link in links if self.check_prefix(link)]

        # todo maybe optional, maybe log that the script was filtered?
        links = filter_es_variants(links)

        # special handlers run first since only the first tag for an url is queued
        self.find_nextjs_chunks(html_content, links)

        if self.gf.other_asset_extensions:
            for m in re.finditer(r'''<link ([^>]*?)rel=['"]?manifest['"]?([^>]*)/?>''', html_content):
                if hm := re.search(r'''href=['"]?([^'"\s]+)''', m.group(1) + m.group(2)):
                    link = urljoin(url, hm.group(1))
                    log.log('adding link manifest', link)
                    self.queue_link(link, 'webmanifest')

        for link in links:
            self.queue_link(link)

        # save this file
        this_file_path = url + 'index.html' if url.endswith('/') else url
        if not re.search(r'\.html?', this_file_path, flags=re.IGNORECASE):
            this_file_path += '.html'

        self.save_fetched_asset(urljoin(url, this_file_path), html_content.encode())

        # handle inline scripts
        inline_script_content = ''
        for m in re.finditer(r'''<script(?: [^>]*)?>(.*?)</script>''', html_content, flags=re.DOTALL):
            script_content = html.unescape(m.group(1)).strip()
            if script_content:
                inline_script_content += '\n//=====\n' + script_content
                self.handle_js_data(script_content, url)

        if inline_script_content:
            self.save_fetched_asset(this_file_path + '.__inline.js', inline_script_content.encode())

        # handle inline styles
        inline_style_content = ''
        for m in re.finditer(r'''<style(?: [^>]*)?>(.*?)</style>''', html_content, flags=re.DOTALL):
            style_content = html.unescape(m.group(1)).strip()
            if style_content:
                inline_style_content += '\n/*=====*/\n' + style_content
                self.handle_css_data(style_content, url)

        if inline_style_content and not self.gf.skip_css:
            self.save_fetched_asset(this_file_path + '.__inline.css', inline_style_content.encode())

        # scan for importmaps
        for m in re.finditer(r'''<script [^>]*?type\s*=\s*['"]?importmap['"]?[^>]*?>(.+?)</script>''', html_content, flags=re.DOTALL):
            imap = None
            try:
                imap = json.loads(html.unescape(m.group(1)))
            except Exception:
                log.debug('warn: invalid importmap')
                continue

            if not imap:
                continue

            for name, src in imap.get('imports', {}).items():
                if not name.endswith('/'):
                    self.queue_link(urljoin(url, src))
                else:
                    log.log('NOT IMPLEMENTED: importmap entry ending with a slash')

                # todo: support self.import_paths lookup
                # but here some might be already imported so we'd need to add all to lpath

        if self.gf.other_asset_extensions:
            # attribute styles
            for m in re.finditer(r'''style\s*=\s*(?:['"])([^"']+)''', html_content):
                self.handle_css_data(m.group(1), url)

            # srcset
            for m in re.finditer(r'''srcset\s*=\s*(?:['"])([^"']+)''', html_content, flags=re.IGNORECASE):
                for m2 in re.finditer(r'(?:^|,)\s*(?!data:)([^,\s]+)', m.group(1)):
                    link = urljoin(url, m2.group(1))
                    log.log('adding link from srcset', link)
                    self.queue_link(link)

        if self.gf.aggressive_mode:
            # aggressive mode is also for html since inline handlers can contain js
            # this also looks into html comments
            content = html_content.replace('&quot;', '"').replace('&apos;', "'").replace('&#39;', "'")
            self.run_aggressive_scan(content, url)


class GetFrontend:
    def __init__(self, config):
        self.root = config['root']
        if self.root.count('/') < 3 and not self.root.endswith('/'):
            # normalize it so that we know that if it doesn't end with a slash
            # it's a particular file, not a directory index
            self.root += '/'

        self.prefix_whitelist = self.make_prefix_whitelist(config.get('origin_whitelist', []))

        self.ignore_vendor = config.get('ignore_vendor')
        self.all_srcmap_urls = config.get('all_srcmap_urls')
        self.save_original_assets = config.get('save_original_assets')
        self.skip_css = config.get('skip_css')
        self.extract_nested_sourcemaps = config.get('extract_nested_sourcemaps')
        self.client = Client(cookies=config.get('cookies'), headers=config.get('headers'))

        self.other_asset_extensions: set[str] = config.get('other_asset_extensions', set())
        self.aggressive_mode = config.get('aggressive_mode')
        self.make_scan_patterns()

        self.other_urls = config.get('other_urls', [])
        self.use_original_base = config.get('use_original_base')
        self.ignore_base_tag = config.get('ignore_base_tag')
        self.public_path_map = config.get('public_path_map')

        self.fetcher = Fetcher(self.client, 3)
        self.fetched_sourcemaps: dict[bool] = {} # so we don't fetch .map twice, maps are not fetched via queue

        self.archive = FArchive()

        self.root_crawler = Crawler(self, self.root)

    def make_prefix_whitelist(self, allowed_origins):
        ret = set()

        if allowed_origins:
            ret.add(extract_origin(self.root))
            for origin in allowed_origins:
                if origin.startswith('http://') or origin.startswith('https://'):
                    ret.add(extract_origin(origin))
                else:
                    ret.add(extract_origin(f'http://{origin}'))
                    ret.add(extract_origin(f'https://{origin}'))

        return ret

    def make_scan_patterns(self):
        asset_ext_part = None

        if self.other_asset_extensions:
            asset_ext_part = '|'.join([re.escape(ext) for ext in self.other_asset_extensions])
            self.asset_ext_pat = rf'\.(?:{asset_ext_part})'

        parts = [r'm?[jt]sx?']

        if not self.skip_css:
            parts.append('css')

        if self.other_asset_extensions:
            parts.append(asset_ext_part)

        ext_pat = r'\.(?:' + '|'.join(parts) + r')'

        # aggressive scan can be invoked by handlers, even without self.aggressive_mode
        self.aggressive_rel_pat = rf'''["'`]([^"'`?#<>:]+{ext_pat})(?:[?#][^'"`]+)?['"`]'''
        self.aggressive_abs_pat = rf'''https?://[^"'`?#\s(){"{}"}\[\]<>|!,;]+{ext_pat}(?![a-zA-Z0-9._%/-])'''

    def check_response(self, url, response):
        if response is None:
            # here the exception has already been logged
            return

        if response.status_code == 404:
            log.debug('not found', url)
            return None

        if response.status_code != 200:
            log.log('warning: bad response code', url, response.status_code)

        return response

    def decode_response(self, response):
        # response.text might be too slow because it tries to guess the encoding
        # we don't bother
        text = None

        try:
            text = response.content.decode('utf-8')
        except UnicodeDecodeError:
            text = response.content.decode('iso-8859-1')

        return text

    def get_url(self, url):
        response = self.check_response(url, self.client.get(url))
        return response

    def run(self):
        # root is handled specially because we update the root if the previous
        # one caused a redirect
        root_response = self.get_url(self.root)
        if not root_response:
            raise Exception("can't fetch target")

        if not self.use_original_base and root_response.url != self.root:
            self.root = root_response.url
            log.log('target redirected, new root url', self.root)

        self.root_crawler.handle_html_response(self.root, root_response)

        # self.root_crawler.queue_link(self.root, tag='page')

        if 'ico' in self.other_asset_extensions:
            self.root_crawler.queue_link(urljoin(self.root, '/favicon.ico'))

        for url in self.other_urls:
            self.root_crawler.queue_link(urljoin(self.root, url), fallback='dynamic')

        self.loop()

    def save_asset(self, path, content):
        log.vdebug('saving asset', path)
        self.archive.add_file(path, content)

    def export_to_file(self, fileobj):
        self.archive.write_to_file(fileobj)

    def export_to_directory(self, path):
        self.archive.save_to_directory(path)

    def dump_to_stdout(self):
        self.archive.dump_to_stdout()

    def loop(self):
        while True:
            res = self.fetcher.get_response()
            if res is None:
                break

            url, response, crawler, mode, *args = res
            crawler: Crawler
            log.log('handling', url, mode, *args)
            if response and response.url != url:
                log.log('it redirected to', response.url)

                if not self.use_original_base:
                    url = response.url

            crawler.handle_result(url, response, mode, *args)


def extract_origin(url):
    parsed_url = urlparse(url)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}/"
    return origin


def find_import_references(res, current_path):
    value_pat = r'''['"]([^'"]+)['"]'''

    for m in re.finditer(rf'''(?:(?:^|[^.\s])\s*|[^a-zA-Z0-9_$.\s])import\s*\({value_pat}\)|(?:^|[\n;])\s*import\s*{value_pat}|(?:[{"}"}]|[a-zA-Z0-9$_]\s|\*/)\s*from\s*{value_pat}''', res):
        link = m.group(1) or m.group(2) or m.group(3)

        if '.js' not in link and '.mjs' not in link and '.ts' not in link:
            # we get... many false positives
            continue

        if re.search(r'[<>(){}\[\]]', link): # things like ?v=sth might be there
            continue

        if link.startswith('./') or link.startswith('../') or link.startswith('/'):
            yield urljoin(current_path, link)

        elif link.startswith('http://') or link.startswith('https://'):
            yield link

        else:
            log.log('NOT IMPLEMENTED: using mapped import', link)
            pass


def parse_chunkmap(val):
    chunkmap_entry_pat = r'''([a-zA-Z0-9_$]+|['"][^'"]+['"]):['"]([^"']+)['"]'''
    ret = {}

    if val:
        for k, v in re.findall(chunkmap_entry_pat, val):
            ret[parse_chunk_id(k)] = v

    return ret


def parse_chunk_id(v):
    if v.startswith('"') or v.startswith("'"): # todo not exact, should be json but nothing is exact here
        v = v[1:-1]
    elif 'e' in v and (m := re.match(r'^(\d+)(?:e(\d+))', v)):
        v = m.group(1) + '0'*int(m.group(2))

    return v


def filter_es_variants(links):
    ret = []
    best_dict = {}

    for link in links:
        parts = re.split(r'(?<=[-.])es(\d+|next)(?=[.-])', link, maxsplit=1)

        if len(parts) == 1:
            ret.append(link)
        else:
            key = parts[0] + '?' + parts[2]
            nval = parts[1]
            curr = best_dict.get(key, 0)
            if nval == 'next' or (curr != 'next' and int(nval) > int(curr)):
                best_dict[key] = nval

    for k, v in best_dict.items():
        ret.append(k.replace('?', 'es' + v))

    return ret


def get_config_from_args():
    tpl_common = 'svg,json,webmanifest,ico,eot,woff,woff2,otf,ttf'
    tpl_images = 'jpg,jpeg,png,gif,webp'
    tpl_media = 'mp3,ogg,wav,m4a,opus,mp4,mov,mkv,webm'

    default_ua = 'Mozilla/5.0 (Windows NT 10.0; rv:124.0) Gecko/20100101 Firefox/124.0'

    parser = argparse.ArgumentParser()

    parser.add_argument('url', help='The root url.')
    parser.add_argument('other_urls', nargs='*', help='Other urls that should be scanned.')
    parser.add_argument('-o', '--output', default='-', help='Output can be a zip file (needs to end with .zip), a directory or stdout specified via the - character (default)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, use -vv for even more verbosity.')

    scope_group = parser.add_argument_group('scope options')
    scope_group.add_argument('-wo', '--whitelist-origin', action='append', default=[], help='Make requests to this origin/domain only. May be specified multiple times.')
    scope_group.add_argument('-ob', '--use-original-base', action='store_true', help="Don't change the base url if the original request has redirected. By default, the base url is updated.")
    scope_group.add_argument('-ib', '--ignore-base-tag', action='store_true', help="Ignore html <base> tags.")
    scope_group.add_argument('-c', '--add-cookie', action='append', default=[], help='Add a cookie in the form name=value to all requests.')
    scope_group.add_argument('-H', '--add-header', action='append', default=[], help='Add a given HTTP header (name: value) to all requests.')
    scope_group.add_argument('-ppm', '--public-path-map', action='append', default=[], help='Add a custom public path for a given chunk index file (indexfile=publicpath), see "public path for" in the debug output to find out which index files were found.')

    scan_group = parser.add_argument_group('scan options')
    scan_group.add_argument('-a', '--aggressive-mode', action='store_true', help='Scan JS/HTML files for possible script paths more aggressively.')
    scan_group.add_argument('-i', '--ignore-vendor', action='store_true', help='Do not fetch source maps for scripts starting with vendor.')
    scan_group.add_argument('-nn', '--no-nested-sourcemaps', action='store_true', help='Do not unpack inline sourcemaps found inside mapped content.')
    scan_group.add_argument('-so', '--save-original-assets', action='store_true', help='Save original asset files even if a source map exists.')
    scan_group.add_argument('-as', '--all-srcmap-urls', action='store_true', help='By default only one map specified by sourceMappingURL is fetched for a given script - this option overrides that. Use with caution, might generate many additional requests which are usually unsuccessful.')

    asset_group = parser.add_argument_group('asset options')

    asset_group.add_argument('-ae', '--asset-extensions', action='append', default=[], help='Specify comma-separated list of extensions for additional asset files to be saved. By default only HTML/JS/CSS files are saved. May be specified multiple times.')
    asset_group.add_argument('-sa', '--save-common-assets', action='store_true', help=f'Shortcut for --asset-extensions={tpl_common}')
    asset_group.add_argument('-si', '--save-images', action='store_true', help=f'Shortcut for --asset-extensions={tpl_images}')
    asset_group.add_argument('-sm', '--save-media', action='store_true', help=f'Shortcut for --asset-extensions={tpl_media}')
    asset_group.add_argument('-nc', '--no-css', action='store_true', help='Do not save CSS files.')

    args = parser.parse_args()

    config = {
        'root': args.url,
        'origin_whitelist': args.whitelist_origin,
        'cookies': {k: v for val in args.add_cookie for k, v in [val.split('=', 1)]},
        'headers': {k: v for val in args.add_header for k, v in [val.split(': ', 1)]},
        'other_urls': args.other_urls,
        'aggressive_mode': args.aggressive_mode,
        'ignore_vendor': args.ignore_vendor,
        'extract_nested_sourcemaps': not args.no_nested_sourcemaps,
        'save_original_assets': args.save_original_assets,
        'all_srcmap_urls': args.all_srcmap_urls,
        'skip_css': args.no_css,
        'other_asset_extensions': set([e for exts in args.asset_extensions for e in exts.split(',')]),
        'use_original_base': args.use_original_base,
        'ignore_base_tag': args.ignore_base_tag,
        'public_path_map': {k: v for val in args.public_path_map for k, v in [val.split('=', 1)]},
    }

    if args.save_common_assets:
        config['other_asset_extensions'].update(tpl_common.split(','))

    if args.save_images:
        config['other_asset_extensions'].update(tpl_images.split(','))

    if args.save_media:
        config['other_asset_extensions'].update(tpl_media.split(','))

    if 'User-Agent' not in config['headers'] and 'user-agent' not in config['headers']:
        config['headers']['User-Agent'] = default_ua

    return config, args.output, args.verbose


def main():
    config, output, verbosity = get_config_from_args()

    log.level += verbosity

    gf = GetFrontend(config)
    gf.run()

    if output.endswith('.zip'):
        with open(output, 'wb') as wf:
            gf.export_to_file(wf)

    elif output != '-':
        gf.export_to_directory(output)

    else:
        gf.dump_to_stdout()


if __name__ == '__main__':
    main()
