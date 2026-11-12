# Copyright (c) 2026 Fabian Freund.
#
# This file is part of WebLibre (see https://weblibre.eu).
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
"""Tests for update_catalogue.py. Run: python3 -m unittest discover -s tools

Real Ed25519 keys through openssl; the network and the APK checks are fakes.
Set WEBLIBRE_TEST_APK (and ANDROID_HOME) to also run the APK verifier against
a real APK.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

import update_catalogue as uc

NOW = dt.datetime(2026, 12, 1, 6, 0, tzinfo=dt.timezone.utc)
STABLE = "eu.weblibre.gecko"
ALPHA = "eu.weblibre.gecko.alpha"
COMPONENTS = {
    "gecko": {"status": "known", "version": "160.0", "buildId": "20261124093000"},
    "lyrebird": {"status": "unknown"},
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apk_bytes(tag: str, name: str) -> bytes:
    return f"apk {tag} {name}".encode()


def release_json(tag: str, seq: int, *, alpha: bool = False, impeller: bool = True,
                 play: bool | None = None, summary: dict[str, str] | None = None) -> dict[str, Any]:
    track = "alpha" if alpha else "stable"
    targets = []
    for renderer in ("skia", "impeller") if impeller else ("skia",):
        flavor = track + ("Impeller" if renderer == "impeller" else "")
        for abi, digit in uc.ABI_DIGITS.items():
            name = f"app-{flavor}-{abi}-release.apk"
            data = apk_bytes(tag, name)
            targets.append({
                "id": f"{tag}/github/{track}/{renderer}/{abi}",
                "distribution": "github", "track": track, "renderer": renderer, "abi": abi,
                "versionCode": seq * 10 + digit, "minSdk": 26,
                "artifact": {"url": f"{uc.RELEASE_DOWNLOAD_PREFIX}{tag}/{name}",
                             "byteLength": len(data), "sha256": sha(data)},
            })
    if play if play is not None else not alpha:
        targets.append({"id": f"{tag}/play/stable/skia", "distribution": "play", "track": "stable",
                        "renderer": "skia", "versionCode": seq, "minSdk": 26})
    notes: dict[str, Any] = {"url": f"{uc.RELEASE_TAG_PREFIX}{tag}"}
    if summary is not None:
        notes["summary"] = summary
    return {
        "schemaVersion": 1, "packageId": ALPHA if alpha else STABLE, "releaseId": tag,
        "appVersion": tag.removeprefix("v"), "logicalReleaseSequence": seq, "prerelease": alpha,
        "targets": targets, "components": COMPONENTS, "releaseNotes": notes,
    }


class FakeNetwork(uc.Network):
    def __init__(self) -> None:
        super().__init__(None)
        self.releases: list[uc.GithubRelease] = []
        self.files: dict[str, bytes] = {}
        self.downloads: list[str] = []
        self.fail_listing = False

    def add(self, doc: dict[str, Any], published: str | None = None, raw: bytes | None = None,
            tag: str | None = None) -> None:
        tag = tag or doc["releaseId"]
        assets = {}
        for t in doc["targets"]:
            if "artifact" in t:
                url = t["artifact"]["url"]
                name = url.rsplit("/", 1)[1]
                data = self.files.get(url) or apk_bytes(tag, name)
                self.files[url] = data
                assets[name] = uc.GithubAsset(name, len(data), url, f"sha256:{sha(data)}")
        url = f"{uc.RELEASE_DOWNLOAD_PREFIX}{tag}/release.json"
        self.files[url] = raw if raw is not None else json.dumps(doc).encode()
        assets["release.json"] = uc.GithubAsset("release.json", len(self.files[url]), url, None)
        self.releases.append(uc.GithubRelease(
            tag, doc.get("prerelease", False),
            published or f"2026-11-{doc['logicalReleaseSequence'] % 28 + 1:02d}T00:00:00Z", assets))

    def list_releases(self) -> list[uc.GithubRelease]:
        if self.fail_listing:
            raise uc.Fatal("listing releases failed: offline")
        return list(self.releases)

    def fetch(self, url: str, max_bytes: int) -> bytes:
        if url not in self.files:
            raise uc.Fatal(f"downloading {url} failed: 404")
        return self.files[url]

    def download(self, url: str, dest: Path, expected_length: int) -> str:
        self.downloads.append(url)
        data = self.files[url]
        if len(data) != expected_length:
            raise uc.Rejected(f"{url}: {len(data)} bytes, release.json says {expected_length}")
        dest.write_bytes(data)
        return sha(data)


class FakeVerifier:
    def __init__(self) -> None:
        self.bad: set[str] = set()
        self.checked: list[str] = []

    def check(self, apk: Path, target: dict[str, Any], release: dict[str, Any], package_id: str) -> None:
        self.checked.append(target["id"])
        if target["id"] in self.bad:
            raise uc.Rejected("signed by ['0000'], not the production certificate")


def write_policy(root: Path, withdrawn=(), advisories=(), security=None) -> None:
    (root / "policy" / "release-security").mkdir(parents=True, exist_ok=True)
    (root / "policy" / "withdrawn.json").write_text(json.dumps({"withdrawn": [
        {"id": i, "date": "2026-12-01", "reason": "test"} for i in withdrawn]}))
    (root / "policy" / "advisories.json").write_text(json.dumps({"advisories": list(advisories)}))
    for tag, classification in (security or {}).items():
        (root / "policy" / "release-security" / f"{tag}.json").write_text(
            json.dumps({"classification": classification}))


class Keys:
    """Real Ed25519 keys, generated once."""

    def __init__(self, directory: Path):
        self.online = directory / "online.pem"
        self.offline = directory / "offline.pem"
        self.stranger = directory / "stranger.pem"
        for path in (self.online, self.offline, self.stranger):
            path.write_bytes(uc._openssl("genpkey", "-algorithm", "ed25519"))
        self.trusted = [
            uc.TrustedKey("wl-meta-2026a", uc.raw_public_key(self.online)),
            uc.TrustedKey("wl-meta-2026b", uc.raw_public_key(self.offline)),
        ]

    def write_trusted(self, root: Path) -> None:
        (root / "keys").mkdir(exist_ok=True)
        (root / "keys" / "trusted_keys.json").write_text(json.dumps({"keys": [
            {"keyId": k.key_id, "ed25519PublicKey": base64.b64encode(k.public_key).decode()}
            for k in self.trusted]}))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._keydir = tempfile.TemporaryDirectory()
        cls.keys = Keys(Path(cls._keydir.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._keydir.cleanup()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.site = self.root / "site"
        self.keys.write_trusted(self.root)
        write_policy(self.root)
        self.net = FakeNetwork()
        self.verifier = FakeVerifier()
        self.stderr = io.StringIO()
        self._redirect = contextlib.redirect_stderr(self.stderr)
        self._stdout = contextlib.redirect_stdout(io.StringIO())
        self._redirect.__enter__()
        self._stdout.__enter__()

    def tearDown(self) -> None:
        self._stdout.__exit__(None, None, None)
        self._redirect.__exit__(None, None, None)
        self._tmp.cleanup()

    def run_update(self, now: dt.datetime = NOW, refresh: bool = False,
                   signing: list[uc.SigningKey] | None = None) -> uc.UpdateResult:
        return uc.run_update(
            self.site, self.keys.trusted,
            signing or [uc.SigningKey("wl-meta-2026a", self.keys.online)],
            uc.load_policy(self.root / "policy"), self.net, lambda: self.verifier, now, refresh,
        )

    def catalogue(self, package_id: str = STABLE) -> uc.Catalogue:
        return uc.read_catalogue(uc.catalogue_path(self.site, package_id), package_id, self.keys.trusted)

    def tags(self, package_id: str = STABLE) -> list[str]:
        return [r["releaseId"] for r in self.catalogue(package_id).payload["releases"]]


class StrictJsonTest(unittest.TestCase):
    def test_rejections(self) -> None:
        for bad in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":1}}', b"\xef\xbb\xbf{}", b'{"a":NaN}',
                    b'{"a":1} x', b"\xff", ("[" * 17 + "]" * 17).encode()):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(uc.Rejected):
                    uc.strict_json_loads(bad)

    def test_depth_16_is_allowed(self) -> None:
        uc.strict_json_loads(("[" * 16 + "]" * 16).encode())


class EnvelopeTest(Base):
    def envelope(self, payload: bytes = b'{"x":1}', key: Path | None = None, key_id: str = "wl-meta-2026a") -> dict:
        return json.loads(uc.sign_envelope(payload, [uc.SigningKey(key_id, key or self.keys.online)]))

    def verify(self, doc: dict) -> uc.VerifiedEnvelope:
        return uc.verify_envelope(json.dumps(doc).encode(), self.keys.trusted)

    def test_round_trip(self) -> None:
        verified = self.verify(self.envelope())
        self.assertEqual(verified.payload, b'{"x":1}')
        self.assertEqual(verified.key_ids, ["wl-meta-2026a"])

    def test_pae_matches_the_client(self) -> None:
        # The client's dssePae: "DSSEv1 <len type> <type> <len payload> <payload>".
        self.assertEqual(uc.dsse_pae("t", b"ab"), b"DSSEv1 1 t 2 ab")

    def test_offline_key_alone_verifies(self) -> None:
        verified = self.verify(self.envelope(key=self.keys.offline, key_id="wl-meta-2026b"))
        self.assertEqual(verified.key_ids, ["wl-meta-2026b"])

    def test_rejections(self) -> None:
        good = self.envelope()
        cases = {
            "unknown key only": self.envelope(key=self.keys.stranger, key_id="wl-meta-2026x"),
            "stranger under a trusted id": self.envelope(key=self.keys.stranger),
            "payload type": {**good, "payloadType": "application/json"},
            "no signatures": {**good, "signatures": []},
            "tampered payload": {**good, "payload": base64.b64encode(b'{"x":2}').decode()},
            "non-canonical base64": {**good, "payload": good["payload"].rstrip("=")},
            "short signature": {**good, "signatures": [{"keyid": "wl-meta-2026a",
                                                         "sig": base64.b64encode(b"x" * 63).decode()}]},
        }
        for name, doc in cases.items():
            with self.subTest(name):
                with self.assertRaises(uc.Rejected):
                    self.verify(doc)

    def test_too_large(self) -> None:
        with self.assertRaises(uc.Rejected):
            uc.verify_envelope(b" " * (uc.MAX_ENVELOPE_BYTES + 1), self.keys.trusted)


class UpdateTest(Base):
    def test_first_run_publishes_both_catalogues(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.net.add(release_json("v0.51.0-alpha-1", 48, alpha=True))
        result = self.run_update()
        self.assertEqual(len(result.written), 2)
        stable = self.catalogue(STABLE)
        self.assertEqual(stable.revision, 1)
        self.assertEqual(self.tags(STABLE), ["v0.50.0"])
        self.assertEqual(self.tags(ALPHA), ["v0.51.0-alpha-1"])
        self.assertEqual(stable.payload["issuedAt"], "2026-12-01T06:00:00Z")
        self.assertEqual(stable.payload["expiresAt"], "2026-12-31T06:00:00Z")
        release = stable.payload["releases"][0]
        self.assertEqual(release["security"], {"classification": "unknown"})
        self.assertEqual(len(release["targets"]), 7)
        self.assertEqual(len(self.net.downloads), 6 + 3 + 3)
        self.assertFalse(result.problems.errors)

    def test_no_releases_yet_still_publishes_empty_catalogues(self) -> None:
        self.run_update()
        self.assertEqual(self.tags(STABLE), [])
        self.assertEqual(self.catalogue(ALPHA).revision, 1)

    def test_unchanged_run_downloads_and_signs_nothing(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.run_update()
        before = uc.catalogue_path(self.site, STABLE).read_bytes()
        self.net.downloads.clear()
        result = self.run_update(NOW + dt.timedelta(hours=1))
        self.assertEqual(result.written, [])
        self.assertEqual(self.net.downloads, [])
        self.assertEqual(uc.catalogue_path(self.site, STABLE).read_bytes(), before)

    def test_weekly_refresh_resigns_without_downloading(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.run_update()
        self.net.downloads.clear()
        self.run_update(NOW + dt.timedelta(days=7, hours=1))
        stable = self.catalogue(STABLE)
        self.assertEqual(stable.revision, 2)
        self.assertEqual(stable.payload["issuedAt"], "2026-12-08T07:00:00Z")
        self.assertEqual(self.net.downloads, [])

    def test_new_release_downloads_only_its_apks(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.run_update()
        self.net.downloads.clear()
        self.net.add(release_json("v0.51.0", 49))
        self.run_update(NOW + dt.timedelta(hours=1))
        self.assertEqual(self.tags(), ["v0.51.0", "v0.50.0"])
        self.assertEqual(self.catalogue().revision, 2)
        self.assertEqual(len(self.net.downloads), 6)
        self.assertTrue(all("/v0.51.0/" in u for u in self.net.downloads))
        self.assertEqual(self.catalogue(ALPHA).revision, 1)  # untouched

    def test_withdrawal_removes_and_keeps_out(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.net.add(release_json("v0.51.0", 49))
        self.run_update()
        write_policy(self.root, withdrawn=["v0.51.0"])
        self.run_update(NOW + dt.timedelta(hours=1))
        self.assertEqual(self.tags(), ["v0.50.0"])
        self.run_update(NOW + dt.timedelta(days=8), refresh=True)
        self.assertEqual(self.tags(), ["v0.50.0"])

    def test_target_withdrawal(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        write_policy(self.root, withdrawn=["v0.50.0/github/stable/impeller/x86_64"])
        self.run_update()
        ids = [t["id"] for t in self.catalogue().payload["releases"][0]["targets"]]
        self.assertNotIn("v0.50.0/github/stable/impeller/x86_64", ids)
        self.assertEqual(len(ids), 6)

    def test_withdrawn_release_is_never_fetched(self) -> None:
        self.net.add(release_json("v0.50.0", 47), raw=b"not json")
        write_policy(self.root, withdrawn=["v0.50.0"])
        result = self.run_update()
        self.assertFalse(result.problems.errors)

    def test_failed_apk_verification_excludes_the_release(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.net.add(release_json("v0.51.0", 49))
        self.verifier.bad.add("v0.51.0/github/stable/skia/arm64-v8a")
        result = self.run_update()
        self.assertEqual(self.tags(), ["v0.50.0"])
        self.assertTrue(any("v0.51.0: excluded" in e for e in result.problems.errors))

    def test_digest_mismatch_excludes_the_release(self) -> None:
        doc = release_json("v0.50.0", 47)
        self.net.add(doc)
        url = doc["targets"][0]["artifact"]["url"]
        self.net.files[url] = b"x" * len(self.net.files[url])  # same length, other bytes
        result = self.run_update()
        self.assertEqual(self.tags(), [])
        self.assertTrue(any("SHA-256" in e for e in result.problems.errors))

    def test_known_target_with_a_new_digest_stops_the_run(self) -> None:
        doc = release_json("v0.50.0", 47)
        self.net.add(doc)
        self.run_update()
        before = uc.catalogue_path(self.site, STABLE).read_bytes()
        changed = copy.deepcopy(doc)
        changed["targets"][0]["artifact"]["sha256"] = "0" * 64
        self.net.releases.clear()
        self.net.add(changed)
        self.net.releases[0].assets[changed["targets"][0]["artifact"]["url"].rsplit("/", 1)[1]].digest = None
        with self.assertRaises(uc.Fatal):
            self.run_update(NOW + dt.timedelta(hours=1))
        self.assertEqual(uc.catalogue_path(self.site, STABLE).read_bytes(), before)

    def test_network_failure_publishes_nothing(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.run_update()
        before = uc.catalogue_path(self.site, STABLE).read_bytes()
        self.net.fail_listing = True
        with self.assertRaises(uc.Fatal):
            self.run_update(NOW + dt.timedelta(days=8))
        self.assertEqual(uc.catalogue_path(self.site, STABLE).read_bytes(), before)

    def test_all_releases_vanishing_stops_the_run(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.run_update()
        self.net.releases.clear()
        with self.assertRaises(uc.Fatal):
            self.run_update(NOW + dt.timedelta(days=8))

    def test_deleted_release_drops_out(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.net.add(release_json("v0.51.0", 49))
        self.run_update()
        self.net.releases = [r for r in self.net.releases if r.tag != "v0.51.0"]
        self.run_update(NOW + dt.timedelta(hours=1))
        self.assertEqual(self.tags(), ["v0.50.0"])

    def test_head_that_does_not_verify_stops_the_run(self) -> None:
        self.run_update()
        path = uc.catalogue_path(self.site, STABLE)
        doc = json.loads(path.read_text())
        doc["signatures"] = json.loads(uc.sign_envelope(b"{}", [uc.SigningKey("wl-meta-2026a", self.keys.stranger)]))["signatures"]
        path.write_text(json.dumps(doc))
        with self.assertRaises(uc.Fatal):
            self.run_update(NOW + dt.timedelta(days=8))

    def test_head_signed_by_the_offline_key_is_accepted(self) -> None:
        self.run_update(signing=[uc.SigningKey("wl-meta-2026b", self.keys.offline)])
        self.run_update(NOW + dt.timedelta(days=8))
        self.assertEqual(self.catalogue().revision, 2)

    def test_invalid_release_json_is_excluded(self) -> None:
        foreign = release_json("v0.50.0", 47)
        foreign["targets"][0]["artifact"]["url"] = "https://evil.example/app-stable-x86_64-release.apk"
        mixed = release_json("v0.50.0", 47)
        mixed["targets"][0]["track"] = "alpha"
        wrong_code = release_json("v0.50.0", 47)
        wrong_code["targets"][0]["versionCode"] = 999
        bad = {
            "wrong package": {**release_json("v0.50.0", 47), "packageId": "com.example"},
            "releaseId is not the tag": {**release_json("v0.50.0", 47), "releaseId": "v0.48.0"},
            "foreign artifact url": foreign,
            "alpha target in stable": mixed,
            "version code": wrong_code,
            "not json": None,
        }
        for name, doc in bad.items():
            with self.subTest(name):
                self.net = FakeNetwork()
                self.net.add(release_json("v0.49.0", 45))
                if doc is None:
                    self.net.add(release_json("v0.50.0", 47), raw=b"{")
                else:
                    self.net.add(doc, tag="v0.50.0")
                for f in list(self.site.rglob("*.json")):
                    f.unlink()
                result = self.run_update()
                self.assertEqual(self.tags(), ["v0.49.0"])
                self.assertTrue(result.problems.errors)

    def test_duplicate_sequence_excludes_both(self) -> None:
        self.net.add(release_json("v0.50.0", 47))
        self.net.add(release_json("v0.50.1", 47))
        self.net.add(release_json("v0.49.0", 45))
        result = self.run_update()
        self.assertEqual(self.tags(), ["v0.49.0"])
        self.assertTrue(result.problems.errors)

    def test_retains_ten_newest_and_summaries_on_five(self) -> None:
        for i in range(12):
            self.net.add(release_json(f"v0.{40 + i}.0", 30 + i, impeller=False, summary={"en": f"notes {i}"}))
        self.run_update()
        releases = self.catalogue().payload["releases"]
        self.assertEqual([r["logicalReleaseSequence"] for r in releases], list(range(41, 31, -1)))
        self.assertEqual(sum("summary" in r["releaseNotes"] for r in releases), 5)
        self.assertIn("summary", releases[0]["releaseNotes"])

    def test_summary_limits(self) -> None:
        cases = {
            "too long": ({"en": "x" * 2001}, None),
            "emoji count as two": ({"en": "😀" * 1001}, None),
            "too many bytes": ({"en": "ä" * 1600}, None),
            "no en": ({"de": "Hallo"}, None),
            "blank": ({"en": "ok", "de": "  "}, None),
            "unknown language dropped": ({"en": "ok", "fr": "salut"}, {"en": "ok"}),
            "fine": ({"en": "- a\n- b", "de": "- a"}, {"de": "- a", "en": "- a\n- b"}),
        }
        for name, (summary, expected) in cases.items():
            with self.subTest(name):
                problems = uc.Problems()
                self.assertEqual(uc._summary({"summary": summary}, problems, "v1"), expected)

    def test_policy_reaches_the_catalogue(self) -> None:
        advisory = {"id": "WL-2026-001", "url": "https://weblibre.eu/a/1", "severity": "high",
                    "affected": {"introducedInSequence": 31, "fixedInSequence": 47}}
        alpha_only = {**advisory, "id": "WL-2026-002", "packages": [ALPHA]}
        write_policy(self.root, advisories=[advisory, alpha_only], security={"v0.50.0": "fixesIncluded"})
        self.net.add(release_json("v0.50.0", 47))
        self.run_update()
        stable = self.catalogue().payload
        self.assertEqual(stable["advisories"], [advisory])
        self.assertEqual(stable["releases"][0]["security"], {"classification": "fixesIncluded"})
        alpha = self.catalogue(ALPHA).payload
        self.assertEqual([a["id"] for a in alpha["advisories"]], ["WL-2026-001", "WL-2026-002"])
        self.assertNotIn("packages", alpha["advisories"][1])

    def test_advisory_change_publishes(self) -> None:
        self.run_update()
        write_policy(self.root, advisories=[{"id": "WL-1", "url": "https://x.example/1", "severity": "low",
                                             "affected": {"fixedInSequence": 3}}])
        self.run_update(NOW + dt.timedelta(minutes=5))
        self.assertEqual(self.catalogue().revision, 2)

    def test_malformed_policy_stops_the_run(self) -> None:
        (self.root / "policy" / "advisories.json").write_text(json.dumps({"advisories": [
            {"id": "WL-1", "url": "http://insecure", "severity": "low", "affected": {"fixedInSequence": 3}}]}))
        with self.assertRaises(uc.Fatal):
            uc.load_policy(self.root / "policy")

    def test_signed_by_two_keys_during_rotation(self) -> None:
        self.run_update(signing=[uc.SigningKey("wl-meta-2026a", self.keys.online), uc.SigningKey("wl-meta-2026b", self.keys.offline)])
        envelope = uc.verify_envelope(uc.catalogue_path(self.site, STABLE).read_bytes(), self.keys.trusted)
        self.assertEqual(envelope.key_ids, ["wl-meta-2026a", "wl-meta-2026b"])


class ManifestCheckTest(unittest.TestCase):
    target = {"id": "v0.50.0/github/stable/skia/arm64-v8a", "track": "stable", "renderer": "skia",
              "abi": "arm64-v8a", "versionCode": 473}
    release = {"logicalReleaseSequence": 47, "appVersion": "0.50.0", "components": COMPONENTS}
    manifest = {"schemaVersion": 1, "packageId": STABLE, "distribution": "github", "track": "stable",
                "renderer": "skia", "logicalReleaseSequence": 47, "versionName": "0.50.0",
                "abiVersionCodes": {"x86_64": 471, "armeabi-v7a": 472, "arm64-v8a": 473},
                "components": COMPONENTS}

    def test_matching_manifest(self) -> None:
        uc.ApkVerifier.check_manifest(self.manifest, self.target, self.release, STABLE)

    def test_mismatches(self) -> None:
        for key, value in [("distribution", "play"), ("track", "alpha"), ("renderer", "impeller"),
                           ("logicalReleaseSequence", 46), ("packageId", ALPHA), ("versionName", "0.49.0"),
                           ("abiVersionCodes", {"arm64-v8a": 463}), ("components", {})]:
            with self.subTest(key):
                with self.assertRaises(uc.Rejected):
                    uc.ApkVerifier.check_manifest({**self.manifest, key: value}, self.target, self.release, STABLE)


@unittest.skipUnless(os.environ.get("WEBLIBRE_TEST_APK"), "set WEBLIBRE_TEST_APK to a real APK")
class RealApkTest(unittest.TestCase):
    """Runs apksigner and aapt2 on a real APK. A debug APK fails the signer
    check, which is the point; WEBLIBRE_TEST_APK_CERT accepts its certificate
    so the later checks run too."""

    def test_real_apk(self) -> None:
        apk = Path(os.environ["WEBLIBRE_TEST_APK"])
        verifier = uc.ApkVerifier(uc.find_build_tools(None),
                                  os.environ.get("WEBLIBRE_TEST_APK_CERT", uc.PRODUCTION_CERT_SHA256))
        with self.assertRaises(uc.Rejected) as caught:
            verifier.check(apk, {"versionCode": -1, "minSdk": -1, "abi": "none"}, {}, STABLE)
        print(f"\n{apk.name}: {caught.exception}")


if __name__ == "__main__":
    unittest.main()
