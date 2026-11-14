# pkg.mlaify.io

The Python package index for [AttackMap](https://github.com/mlaify/AttackMap) and its 15 analyzer
plugins. A [PEP 503](https://peps.python.org/pep-0503/) simple index served by GitHub Pages at
<https://pkg.mlaify.io/pypi/simple/>.

Since AttackMap 0.6.4 the same packages are also on [PyPI](https://pypi.org/project/attackmap/),
uploaded by each repository's release workflow from the same GitHub release files that this index
links, so both serve identical bytes. Most people can just use PyPI:

```bash
uv tool install "attackmap[all]"
```

This index stays for installs that want only mlaify-built packages:

```bash
uv tool install "attackmap[all]" --index mlaify=https://pkg.mlaify.io/pypi/simple/ --index-strategy first-index
```

`--index-strategy first-index` takes each package from this index when it has it, so a package of
the same name on PyPI is never used instead. Avoid `pip --extra-index-url`: pip takes the highest
version from any index.

## How it works

- [`sources.toml`](sources.toml) lists the repositories and which of their release assets to list.
- [`build_index.py`](build_index.py) reads every non-draft, non-pre-release GitHub release of those
  repositories and writes a static site:
  - `/pypi/simple/` links every project;
  - `/pypi/simple/<project>/` links each file to its GitHub release asset, with
    `#sha256=<hex>` from the digest GitHub recorded, so pip and uv check every download;
  - `/pypi/state.json` (`{project: {file: sha256}}`) and `/pypi/build.json` (when it was built).
- [`.github/workflows/index.yml`](.github/workflows/index.yml) runs the tests, builds the site and
  deploys it to Pages every six hours, on every push to `main` and on demand (Actions → index →
  Run workflow).

The index is rebuilt from the releases on every run. A release you publish appears at the next run;
a release you delete disappears from the index. The files themselves stay on GitHub Releases; this
site holds only HTML and JSON.

A run fails, and deploys nothing, when the GitHub API fails, when a listed repository has no
matching release asset, or when two releases carry one file name with different contents. A failed
scheduled run opens an issue labelled `ci-failure`.

## Adding a project

Add a `[[repo]]` entry to `sources.toml` with patterns that match its wheel and sdist only, then
run the tests:

```bash
python3 tests/test_build_index.py
```

## Freshness

GitHub turns off scheduled workflows in a public repository after 60 days without a commit. Pushes
and manual runs still deploy. `https://pkg.mlaify.io/pypi/build.json` holds the time of the last
build: if it is more than a day old, re-enable the workflow under Actions → index.

## Local build

```bash
python3 build_index.py --out /tmp/pkg-site
# compare with another index's state.json (URL or saved file): fails if it lists a file this build lacks
python3 build_index.py --out /tmp/pkg-site2 --compare https://pkg.mlaify.io/pypi/state.json
```

Python 3.11 or later, standard library only. Set `GITHUB_TOKEN` to raise the API rate limit; it is
sent to `api.github.com` only.
