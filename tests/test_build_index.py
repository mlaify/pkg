"""Tests for build_index.py. Standard library only, no network: python3 -m unittest discover -s tests"""
import json
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import build_index as bi  # noqa: E402

SHA_A = "a" * 64
SHA_B = "b" * 64


def asset(repo, tag, name, sha=SHA_A, digest=True):
    return {
        "name": name,
        "digest": f"sha256:{sha}" if digest else None,
        "browser_download_url": f"https://github.com/{repo}/releases/download/{tag}/{name}",
        "url": f"https://api.github.com/repos/{repo}/releases/assets/{abs(hash(name)) % 10**9}",
    }


def release(repo, tag, names, draft=False, prerelease=False, **kw):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
            "assets": [asset(repo, tag, n, **kw) for n in names]}


GO = {"repo": "mlaify/attackmap-analyzer-go",
      "assets": [r"^attackmap_analyzer_go-[0-9][^/]*-py3-none-any\.whl$",
                 r"^attackmap_analyzer_go-[0-9][^/]*\.tar\.gz$"]}
CORE = {"repo": "mlaify/AttackMap",
        "assets": [r"^attackmap-[0-9][^/]*-py3-none-any\.whl$", r"^attackmap-[0-9][^/]*\.tar\.gz$"]}


def fake_releases(table):
    return lambda repo: iter(table[repo])


def no_download(url):
    raise AssertionError(f"unexpected download of {url}")


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.append(dict(attrs)["href"])


def links_in(path):
    p = Links()
    p.feed(Path(path).read_text())
    return p.links


class Names(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(bi.normalize("Attackmap_Analyzer.Go"), "attackmap-analyzer-go")
        self.assertEqual(bi.normalize("a--b__c..d"), "a-b-c-d")

    def test_project_of(self):
        self.assertEqual(bi.project_of("attackmap_analyzer_go-0.2.0-py3-none-any.whl"), "attackmap-analyzer-go")
        self.assertEqual(bi.project_of("attackmap_analyzer_go-0.2.0.tar.gz"), "attackmap-analyzer-go")
        self.assertEqual(bi.project_of("attackmap-0.6.2.tar.gz"), "attackmap")
        self.assertEqual(bi.project_of("attackmap-0.6.2-py3-none-any.whl"), "attackmap")
        self.assertEqual(bi.project_of("attackmap_analyzer_omeka_s-1.0.zip"), "attackmap-analyzer-omeka-s")

    def test_next_link(self):
        h = ('<https://api.github.com/x?page=2>; rel="next", '
             '<https://api.github.com/x?page=5>; rel="last"')
        self.assertEqual(bi.next_link(h), "https://api.github.com/x?page=2")
        self.assertEqual(bi.next_link('<https://api.github.com/x?page=1>; rel="prev"'), None)
        self.assertIsNone(bi.next_link(None))


class Sources(unittest.TestCase):
    """The shipped sources.toml: every repo of ci-publish's list, and each one's patterns match
    the file names its builds produce and map to the project its repository is named for."""

    def setUp(self):
        self.repos = bi.load_sources(ROOT / "sources.toml")

    def test_list(self):
        names = [s["repo"] for s in self.repos]
        self.assertEqual(len(names), 16)
        self.assertEqual(len(set(names)), 16)
        self.assertIn("mlaify/AttackMap", names)
        self.assertEqual(sum(n.startswith("mlaify/attackmap-analyzer-") for n in names), 15)

    def test_patterns_match_their_project(self):
        for src in self.repos:
            project = src["repo"].split("/")[1].lower()
            stem = project.replace("-", "_")
            pats = [re.compile(p) for p in src["assets"]]
            for f in (f"{stem}-1.2.3-py3-none-any.whl", f"{stem}-1.2.3.tar.gz"):
                with self.subTest(file=f):
                    self.assertTrue(any(p.fullmatch(f) for p in pats))
                    self.assertEqual(bi.project_of(f), project)
            for f in (f"{stem}-1.2.3-cp312-cp312-linux_x86_64.whl", f"{stem}-1.2.3.zip",
                      f"{stem}_extra-1.2.3.tar.gz", f"{stem}-1.2.3.tar.gz.sig", "SHA256SUMS"):
                with self.subTest(file=f):
                    self.assertFalse(any(p.fullmatch(f) for p in pats))

    def test_bad_sources_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.toml"
            p.write_text('[[repo]]\nrepo = "../evil"\nassets = ["x"]\n')
            with self.assertRaises(bi.BuildError):
                bi.load_sources(p)
            p.write_text('[[repo]]\nrepo = "mlaify/.."\nassets = ["x"]\n')
            with self.assertRaises(bi.BuildError):
                bi.load_sources(p)
            p.write_text('[[repo]]\nrepo = "mlaify/x"\nassets = []\n')
            with self.assertRaises(bi.BuildError):
                bi.load_sources(p)


class Collect(unittest.TestCase):
    def test_skips_drafts_prereleases_and_other_assets(self):
        repo = GO["repo"]
        table = {repo: [
            release(repo, "v0.3.0", ["attackmap_analyzer_go-0.3.0-py3-none-any.whl"], draft=True),
            release(repo, "v0.3.0rc1", ["attackmap_analyzer_go-0.3.0rc1.tar.gz"], prerelease=True),
            release(repo, "v0.2.0", ["attackmap_analyzer_go-0.2.0-py3-none-any.whl",
                                     "attackmap_analyzer_go-0.2.0.tar.gz", "SHA256SUMS", "notes.txt"]),
        ]}
        index = bi.collect([GO], fake_releases(table), no_download)
        self.assertEqual(list(index), ["attackmap-analyzer-go"])
        self.assertEqual(sorted(index["attackmap-analyzer-go"]),
                         ["attackmap_analyzer_go-0.2.0-py3-none-any.whl", "attackmap_analyzer_go-0.2.0.tar.gz"])
        e = index["attackmap-analyzer-go"]["attackmap_analyzer_go-0.2.0.tar.gz"]
        self.assertEqual(e["sha256"], SHA_A)
        self.assertEqual(e["url"], f"https://github.com/{repo}/releases/download/v0.2.0/attackmap_analyzer_go-0.2.0.tar.gz")

    def test_uppercase_digest_is_lowered(self):
        repo = GO["repo"]
        table = {repo: [release(repo, "v1", ["attackmap_analyzer_go-1.0.tar.gz"], sha="ABCDEF" + "0" * 58)]}
        index = bi.collect([GO], fake_releases(table), no_download)
        self.assertEqual(index["attackmap-analyzer-go"]["attackmap_analyzer_go-1.0.tar.gz"]["sha256"], "abcdef" + "0" * 58)

    def test_hashes_assets_without_digest(self):
        repo = GO["repo"]
        table = {repo: [release(repo, "v0.1.0", ["attackmap_analyzer_go-0.1.0.tar.gz"], digest=False)]}
        calls = []

        def download(url):
            calls.append(url)
            return SHA_B

        index = bi.collect([GO], fake_releases(table), download)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("https://api.github.com/repos/"))
        self.assertEqual(index["attackmap-analyzer-go"]["attackmap_analyzer_go-0.1.0.tar.gz"]["sha256"], SHA_B)

    def test_repo_without_matching_assets_fails(self):
        table = {GO["repo"]: [release(GO["repo"], "v1", ["other.whl"])], CORE["repo"]: []}
        with self.assertRaisesRegex(bi.BuildError, "attackmap-analyzer-go"):
            bi.collect([GO], fake_releases(table), no_download)
        with self.assertRaisesRegex(bi.BuildError, "AttackMap"):
            bi.collect([CORE], fake_releases(table), no_download)

    def test_bad_digest_fails(self):
        repo = GO["repo"]
        table = {repo: [release(repo, "v1", ["attackmap_analyzer_go-1.0.tar.gz"], sha="xyz")]}
        with self.assertRaisesRegex(bi.BuildError, "bad SHA-256"):
            bi.collect([GO], fake_releases(table), no_download)

    def test_unexpected_download_url_fails(self):
        repo = GO["repo"]
        rel = release(repo, "v1", ["attackmap_analyzer_go-1.0.tar.gz"])
        rel["assets"][0]["browser_download_url"] = "https://evil.example/attackmap_analyzer_go-1.0.tar.gz"
        with self.assertRaisesRegex(bi.BuildError, "unexpected download URL"):
            bi.collect([GO], fake_releases({repo: [rel]}), no_download)
        rel["assets"][0]["browser_download_url"] = (
            "https://github.com/mlaify/other/releases/download/v1/attackmap_analyzer_go-1.0.tar.gz")
        with self.assertRaisesRegex(bi.BuildError, "unexpected download URL"):
            bi.collect([GO], fake_releases({repo: [rel]}), no_download)

    def test_same_file_in_two_releases(self):
        repo = GO["repo"]
        name = "attackmap_analyzer_go-1.0.tar.gz"
        same = {repo: [release(repo, "v1.0.1", [name]), release(repo, "v1.0", [name])]}
        index = bi.collect([GO], fake_releases(same), no_download)
        self.assertIn("/v1.0.1/", index["attackmap-analyzer-go"][name]["url"])  # newest first
        differ = {repo: [release(repo, "v1.0.1", [name], sha=SHA_B), release(repo, "v1.0", [name])]}
        with self.assertRaisesRegex(bi.BuildError, "different contents"):
            bi.collect([GO], fake_releases(differ), no_download)


class Render(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "site"
        core, go = CORE["repo"], GO["repo"]
        table = {
            core: [release(core, "v0.6.2", ["attackmap-0.6.2-py3-none-any.whl", "attackmap-0.6.2.tar.gz"])],
            go: [release(go, "v0.2.0", ["attackmap_analyzer_go-0.2.0-py3-none-any.whl"], sha=SHA_B)],
        }
        self.index = bi.collect([GO, CORE], fake_releases(table), no_download)
        bi.render(self.index, self.out, generated="2026-11-09T00:00:00Z")

    def tearDown(self):
        self.tmp.cleanup()

    def test_cname(self):
        self.assertEqual((self.out / "CNAME").read_text(), "pkg.mlaify.io\n")

    def test_root_index_lists_projects(self):
        root = self.out / "pypi" / "simple" / "index.html"
        self.assertEqual(links_in(root), ["attackmap/", "attackmap-analyzer-go/"])
        self.assertIn('name="pypi:repository-version" content="1.0"', root.read_text())
        for href in links_in(root):
            self.assertTrue((root.parent / href / "index.html").is_file(), href)

    def test_project_page_links_release_assets_with_sha256(self):
        links = links_in(self.out / "pypi" / "simple" / "attackmap-analyzer-go" / "index.html")
        self.assertEqual(links, [
            "https://github.com/mlaify/attackmap-analyzer-go/releases/download/v0.2.0/"
            f"attackmap_analyzer_go-0.2.0-py3-none-any.whl#sha256={SHA_B}"])
        links = links_in(self.out / "pypi" / "simple" / "attackmap" / "index.html")
        self.assertEqual(len(links), 2)
        for link in links:
            url, frag = link.split("#")
            self.assertTrue(url.startswith("https://github.com/mlaify/AttackMap/releases/download/v0.6.2/"))
            self.assertEqual(frag, f"sha256={SHA_A}")

    def test_state_json_keeps_ci_publish_format(self):
        state = json.loads((self.out / "pypi" / "state.json").read_text())
        self.assertEqual(state, {
            "attackmap": {"attackmap-0.6.2-py3-none-any.whl": SHA_A, "attackmap-0.6.2.tar.gz": SHA_A},
            "attackmap-analyzer-go": {"attackmap_analyzer_go-0.2.0-py3-none-any.whl": SHA_B},
        })
        build = json.loads((self.out / "pypi" / "build.json").read_text())
        self.assertEqual(build, {"generated": "2026-11-09T00:00:00Z", "projects": 2, "files": 3})

    def test_landing_page_links_resolve(self):
        page = self.out / "index.html"
        for href in links_in(page):
            if href.startswith("https://"):
                continue
            self.assertTrue((self.out / href / "index.html").is_file(), href)
        self.assertIn("https://pkg.mlaify.io/pypi/simple/", page.read_text())

    def test_html_is_escaped(self):
        out = Path(self.tmp.name) / "esc"
        bi.render({"x": {"x-1.0<b>.tar.gz": {"url": "https://github.com/a/b/releases/download/v1/x?a=1&b=2",
                                              "sha256": SHA_A}}}, out, generated="t")
        text = (out / "pypi" / "simple" / "x" / "index.html").read_text()
        self.assertIn("x-1.0&lt;b&gt;.tar.gz", text)
        self.assertIn("?a=1&amp;b=2#sha256=", text)


class Compare(unittest.TestCase):
    def test_missing_from(self):
        index = {"p": {"p-1.whl": {"url": "u", "sha256": SHA_A}, "p-2.whl": {"url": "u", "sha256": SHA_A}}}
        self.assertEqual(bi.missing_from(index, {"p": {"p-1.whl": SHA_A}}), [])
        self.assertEqual(bi.missing_from(index, {"p": {"p-1.whl": SHA_B}, "q": {"q-1.whl": SHA_A}}),
                         ["p-1.whl", "q-1.whl"])


    def test_fetch_state_reads_a_saved_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            p.write_text(json.dumps({"p": {"p-1.whl": SHA_A}}))
            self.assertEqual(bi.fetch_state(str(p)), {"p": {"p-1.whl": SHA_A}})


class Http(unittest.TestCase):
    def test_token_goes_to_the_api_only(self):
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "t0k"}):
            self.assertEqual(bi.make_request("https://api.github.com/repos/a/b/releases")
                             .get_header("Authorization"), "Bearer t0k")
            self.assertIsNone(bi.make_request("https://github.com/a/b/releases/download/v1/x.whl")
                              .get_header("Authorization"))
            self.assertIsNone(bi.make_request("https://api.github.com.evil.example/x")
                              .get_header("Authorization"))
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(bi.make_request("https://api.github.com/x").get_header("Authorization"))

    def test_redirect_drops_token_off_the_api(self):
        handler = bi._NoAuthOnRedirect()
        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "t0k"}):
            req = bi.make_request("https://api.github.com/repos/a/b/releases/assets/1", "application/octet-stream")
        off = handler.redirect_request(req, None, 302, "Found", {},
                                       "https://release-assets.githubusercontent.com/signed")
        self.assertIsNone(off.get_header("Authorization"))
        on = handler.redirect_request(req, None, 302, "Found", {}, "https://api.github.com/other")
        self.assertEqual(on.get_header("Authorization"), "Bearer t0k")


class Main(unittest.TestCase):
    def test_end_to_end_and_compare(self):
        repo = GO["repo"]
        table = {repo: [release(repo, "v0.2.0", ["attackmap_analyzer_go-0.2.0.tar.gz"])]}
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "s.toml"
            src.write_text('[[repo]]\nrepo = "mlaify/attackmap-analyzer-go"\n'
                           "assets = ['^attackmap_analyzer_go-[0-9][^/]*\\.tar\\.gz$']\n")
            out = Path(d) / "site"
            with mock.patch.object(bi, "list_releases", fake_releases(table)), \
                 mock.patch.object(bi.collect, "__defaults__", (fake_releases(table), no_download)), \
                 mock.patch.object(bi, "fetch_state",
                                   return_value={"attackmap-analyzer-go": {"attackmap_analyzer_go-0.1.0.tar.gz": SHA_A}}):
                with self.assertRaises(SystemExit) as cm:
                    bi.main(["--out", str(out), "--sources", str(src), "--compare", "https://old/state.json"])
                self.assertIn("1 file(s)", str(cm.exception.code))
                self.assertTrue((out / "pypi" / "simple" / "attackmap-analyzer-go" / "index.html").is_file())
                with self.assertRaises(SystemExit) as cm:  # refuses to write into an existing directory
                    bi.main(["--out", str(out), "--sources", str(src)])
                self.assertIn("exists", str(cm.exception.code))

    def test_build_failure_exits_without_writing(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "s.toml"
            src.write_text('[[repo]]\nrepo = "mlaify/x"\nassets = ["^x$"]\n')
            out = Path(d) / "site"
            with mock.patch.object(bi.collect, "__defaults__", (fake_releases({"mlaify/x": []}), no_download)):
                with self.assertRaises(SystemExit) as cm:
                    bi.main(["--out", str(out), "--sources", str(src)])
            self.assertIn("build failed", str(cm.exception.code))
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
