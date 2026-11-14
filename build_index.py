"""Builds the PEP 503 simple index served at https://pkg.mlaify.io/ by GitHub Pages.

  build_index.py --out <dir> [--sources sources.toml] [--compare <state.json URL>]

Reads sources.toml, lists every GitHub release of each repository in it, and writes a static
site to <dir>:

  CNAME                               the custom domain
  index.html                          a landing page
  pypi/simple/index.html              one link per project
  pypi/simple/<project>/index.html    one link per file, to its GitHub release asset, with
                                      #sha256=<hex> so pip and uv check what they download
  pypi/state.json                     {project: {file: sha256}}, the format ci-publish used
  pypi/build.json                     when this build ran and what it holds

Nothing is downloaded when GitHub has recorded an asset's SHA-256 (the "digest" field); an asset
uploaded before GitHub recorded digests is downloaded once per run and hashed. Drafts and
pre-releases are skipped. The index is rebuilt from scratch every run, so it always says what the
releases hold now.

The build fails, and the live index stays as it was, when the GitHub API fails, when a
repository has no matching assets, or when two releases carry one file name with different
contents. --compare fails when a file another index lists (its state.json, as a URL or a saved
file; for example the index before a move) is missing from this build.

GITHUB_TOKEN, when set, is sent to api.github.com only (never to the download hosts) and raises
the API rate limit. Standard library only, Python 3.11+.

Ported from ci-publish (ci/pkg_sync.py and .github/actions/pkg-index/pkg_index.py), 2026-11-09.
"""
import argparse
import datetime
import hashlib
import html
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
USER_AGENT = "mlaify-pkg-index"
DEFAULT_DOMAIN = "pkg.mlaify.io"
HEAD = '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="pypi:repository-version" content="1.0">'


class BuildError(Exception):
    pass


# --- HTTP -----------------------------------------------------------------------------------

class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """urllib copies every header to a redirect's target. An asset download redirects from
    api.github.com to a signed URL on another host: the token must not follow it (that host
    refuses a request that carries both, and it shouldn't see the token anyway)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and not newurl.startswith(API + "/"):
            new.remove_header("Authorization")
        return new


_opener = urllib.request.build_opener(_NoAuthOnRedirect)


def make_request(url, accept="application/vnd.github+json"):
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(API + "/"):
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def open_url(url, accept="application/vnd.github+json"):
    return _opener.open(make_request(url, accept), timeout=120)


def next_link(header):
    """The rel="next" URL of a GitHub Link header, or None."""
    for part in (header or "").split(","):
        m = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


def list_releases(repo):
    """Every release of owner/name, newest first, following pagination."""
    url = f"{API}/repos/{repo}/releases?per_page=100"
    while url:
        with open_url(url) as r:
            page = json.loads(r.read())
            url = next_link(r.headers.get("Link"))
        yield from page


def hash_asset(api_url):
    """Downloads one release asset through the API and returns its SHA-256 (hex)."""
    h = hashlib.sha256()
    with open_url(api_url, accept="application/octet-stream") as r:
        for chunk in iter(lambda: r.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- Index ----------------------------------------------------------------------------------

def normalize(name):
    """PEP 503 project name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def project_of(filename):
    if filename.endswith(".whl"):
        name = filename.split("-")[0]
    else:
        name = re.sub(r"\.(tar\.gz|zip)$", "", filename).rsplit("-", 1)[0]
    return normalize(name)


def load_sources(path):
    repos = tomllib.loads(Path(path).read_text())["repo"]
    for src in repos:
        m = re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/([A-Za-z0-9_.-]+)", src["repo"])
        if not m or m.group(1) in (".", ".."):
            raise BuildError(f"bad repository name {src['repo']!r}")
        if not src.get("assets"):
            raise BuildError(f"{src['repo']}: no asset patterns")
    return repos


def collect(sources, releases=list_releases, download_hash=hash_asset):
    """{project: {file name: {"url": release asset URL, "sha256": hex}}}."""
    index = {}
    for src in sources:
        repo = src["repo"]
        patterns = [re.compile(p) for p in src["assets"]]
        prefix = f"https://github.com/{repo}/releases/download/"
        found = 0
        for rel in releases(repo):
            if rel.get("draft") or rel.get("prerelease"):
                continue
            for a in rel.get("assets", []):
                name = a["name"]
                if not any(p.fullmatch(name) for p in patterns):
                    continue
                url = a["browser_download_url"]
                if not url.startswith(prefix) or not url.endswith("/" + name):
                    raise BuildError(f"{repo} {rel.get('tag_name')}: unexpected download URL {url}")
                digest = a.get("digest") or ""
                if digest.startswith("sha256:"):
                    sha = digest.split(":", 1)[1].lower()
                else:  # uploaded before GitHub recorded digests
                    sha = download_hash(a["url"])
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    raise BuildError(f"{repo} {rel.get('tag_name')}: bad SHA-256 {sha!r} for {name}")
                files = index.setdefault(project_of(name), {})
                if name in files:
                    if files[name]["sha256"] != sha:
                        raise BuildError(f"{repo}: two releases carry {name} with different contents")
                    continue  # the same file attached to two releases: keep the newer link
                files[name] = {"url": url, "sha256": sha}
                found += 1
        if not found:
            raise BuildError(f"{repo}: no release asset matches its patterns; refusing to publish without it")
    return index


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def render(index, out, domain=DEFAULT_DOMAIN, generated=None):
    out = Path(out)
    generated = generated or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    projects = sorted(index)
    nfiles = sum(len(f) for f in index.values())
    esc = html.escape

    _write(out / "CNAME", domain + "\n")

    simple = out / "pypi" / "simple"
    links = "".join(f'<a href="{esc(p)}/">{esc(p)}</a><br>\n' for p in projects)
    _write(simple / "index.html", f"{HEAD}<title>Simple index</title></head><body>\n{links}</body></html>\n")
    for p in projects:
        links = "".join(
            f'<a href="{esc(e["url"])}#sha256={e["sha256"]}">{esc(n)}</a><br>\n'
            for n, e in sorted(index[p].items()))
        _write(simple / p / "index.html",
               f"{HEAD}<title>Links for {esc(p)}</title></head><body>\n<h1>Links for {esc(p)}</h1>\n"
               f"{links}</body></html>\n")

    state = {p: {n: e["sha256"] for n, e in index[p].items()} for p in projects}
    _write(out / "pypi" / "state.json", json.dumps(state, indent=1, sort_keys=True) + "\n")
    _write(out / "pypi" / "build.json",
           json.dumps({"generated": generated, "projects": len(projects), "files": nfiles}, indent=1) + "\n")
    _write(out / "pypi" / "index.html",
           '<!DOCTYPE html><html><head><meta charset="utf-8"><title>pypi</title></head>'
           '<body><a href="simple/">simple/</a></body></html>\n')

    rows = "".join(f'<li><a href="pypi/simple/{esc(p)}/">{esc(p)}</a> ({len(index[p])} files)</li>\n'
                   for p in projects)
    _write(out / "index.html", f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>M&amp;L AI package index</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}}
code,pre{{background:#f2f2f2;padding:.1rem .3rem}}pre{{padding:.6rem;overflow-x:auto}}
@media (prefers-color-scheme:dark){{body{{background:#111;color:#ddd}}a{{color:#8ab4f8}}code,pre{{background:#222}}}}</style>
</head><body>
<h1>M&amp;L AI package index</h1>
<p>A PEP 503 simple index for AttackMap and its analyzer plugins.
Every file is a GitHub release asset of its project; the index records its SHA-256.
The same files are also on <a href="https://pypi.org/project/attackmap/">PyPI</a>
(<code>uv tool install "attackmap[all]"</code>).</p>
<pre>uv tool install "attackmap[all]" --index mlaify=https://{esc(domain)}/pypi/simple/ --index-strategy first-index</pre>
<p>Use <code>--index-strategy first-index</code> so each package comes from this index when it has it.
See <a href="https://github.com/mlaify/AttackMap">mlaify/AttackMap</a>.</p>
<h2>Projects</h2>
<ul>
{rows}</ul>
<p>Built {esc(generated)} from <a href="https://github.com/mlaify/pkg">mlaify/pkg</a>.</p>
</body></html>
""")


def fetch_state(url):
    """A state.json from a URL, or from a local file."""
    if not url.startswith(("https://", "http://")):
        return json.loads(Path(url).read_text())
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def missing_from(index, state):
    """Files listed in an old state.json that this build lacks or lists with another SHA-256."""
    have = {n: e["sha256"] for files in index.values() for n, e in files.items()}
    return sorted(n for files in state.values() for n, sha in files.items() if have.get(n) != sha)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, help="directory to write the site to (must not exist)")
    ap.add_argument("--sources", default=str(Path(__file__).resolve().parent / "sources.toml"))
    ap.add_argument("--domain", default=DEFAULT_DOMAIN)
    ap.add_argument("--compare", metavar="URL_OR_FILE",
                    help="state.json of another index; fail if it lists a file this build lacks")
    args = ap.parse_args(argv)

    out = Path(args.out)
    if out.exists():
        sys.exit(f"{out} exists; give a new directory")
    try:
        index = collect(load_sources(args.sources))
    except (BuildError, urllib.error.URLError) as e:
        sys.exit(f"build failed: {e}")
    render(index, out, args.domain)
    for p in sorted(index):
        print(f"{p}: {len(index[p])} files")
    print(f"projects={len(index)} files={sum(len(f) for f in index.values())}")

    if args.compare:
        missing = missing_from(index, fetch_state(args.compare))
        for n in missing:
            print(f"missing or different: {n}")
        if missing:
            sys.exit(f"{len(missing)} file(s) in {args.compare} are not in this build")
        print(f"every file in {args.compare} is in this build")


if __name__ == "__main__":
    main()
