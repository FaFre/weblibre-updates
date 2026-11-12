#!/usr/bin/env python3
# Copyright (c) 2026 Fabian Freund.
#
# This file is part of WebLibre (see https://weblibre.eu).
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
"""Builds, signs and verifies WebLibre's update catalogues.

The app repository's plan (plans/APP_UPDATER_IMPLEMENTATION_PLAN.md, 5 and
9.2) is the specification. In short: one signed catalogue per package ID,
served at https://updates.weblibre.eu/v1/<packageId>/catalogue.json, a DSSE
envelope around a JSON payload, signed with Ed25519.

Commands:

  keygen   Create a metadata key pair. The private key is written to a file
           (passphrase-encrypted with --encrypt); the public half is printed in
           the forms keys/trusted_keys.json and the app need.
  update   What the scheduled `sign` job runs: verify the catalogues at the
           branch head, collect the app's releases, verify every APK not
           verified before, and write new signed catalogues if anything
           changed or the head is older than 7 days.
  verify   Verify envelope files (or every catalogue under a site directory)
           against keys/trusted_keys.json.
  sign     Re-sign the payload of an existing envelope with the given key(s)
           alone. For the offline key's recovery drill.
  served   Compare what the live site serves with the site directory.

Only the Python standard library is used. Cryptography goes through the
`openssl` command (3.0 or later); APK checks through `apksigner` and `aapt2`
from the Android SDK build tools.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

# --- Compiled policy --------------------------------------------------------
#
# Everything here is security-relevant and changes only by a reviewed pull
# request. It mirrors constants compiled into the app.

APP_REPO = "FaFre/WebLibre"
RELEASE_DOWNLOAD_PREFIX = f"https://github.com/{APP_REPO}/releases/download/"
RELEASE_TAG_PREFIX = f"https://github.com/{APP_REPO}/releases/tag/"
API_RELEASES = f"https://api.github.com/repos/{APP_REPO}/releases"

# The production APK signing certificate (SHA-256 of the DER certificate),
# also compiled into the app (ProductionSigner.kt) and checked by the app
# repository's verify job.
PRODUCTION_CERT_SHA256 = (
    "8f526e1e53d6bd4dfbf4f4b93c2a91ecb5cb8da5e14ad94c2570e1e3c713527f"
)

# Package ID → the release track its catalogue carries.
PACKAGES = {
    "eu.weblibre.gecko": "stable",
    "eu.weblibre.gecko.alpha": "alpha",
}

PAYLOAD_TYPE = "application/vnd.weblibre.update-catalogue.v1+json"
MAX_ENVELOPE_BYTES = 256 * 1024
MAX_RELEASE_JSON_BYTES = 256 * 1024
MAX_APK_BYTES = 1024 * 1024 * 1024
MAX_JSON_DEPTH = 16

RETAINED_RELEASES = 10  # per package (5.2)
SUMMARIZED_RELEASES = 5  # only the newest carry summaries (5.2)
SCANNED_RELEASES = 60  # newest GitHub releases with a release.json looked at
VALIDITY = dt.timedelta(days=30)
REFRESH_AFTER = dt.timedelta(days=7)

SHIPPED_LANGUAGES = {"en", "de", "es", "id", "ru", "zh"}
MAX_SUMMARY_CHARS = 2000  # UTF-16 code units, as the Dart client counts
MAX_SUMMARY_BYTES = 3 * 1024

ABI_DIGITS = {"x86_64": 1, "armeabi-v7a": 2, "arm64-v8a": 3}
RENDERERS = {"skia", "impeller"}
APK_NAME = re.compile(
    r"^app-(?P<flavor>stable|stableImpeller|alpha|alphaImpeller)"
    r"-(?P<abi>x86_64|armeabi-v7a|arm64-v8a)-release\.apk$"
)
MANIFEST_ENTRY = "assets/weblibre/build_manifest.json"
CLASSIFICATIONS = {"unknown", "fixesIncluded", "critical"}
SEVERITIES = {"unknown", "low", "moderate", "high", "critical"}
COMPONENT_STATUSES = {"known", "unknown", "notBundled"}

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
USER_AGENT = "weblibre-updates-catalogue"

# DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw key follows.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class Fatal(Exception):
    """Stops the run without publishing anything. Needs a human."""


class Rejected(Exception):
    """A document failed verification or validation."""


# --- Strict JSON --------------------------------------------------------------


def strict_json_loads(data: bytes, max_depth: int = MAX_JSON_DEPTH) -> Any:
    """Parses JSON the way the client does: UTF-8 only, no BOM, no duplicate
    keys, no NaN/Infinity, nesting at most `max_depth`."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise Rejected("leading BOM")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise Rejected(f"invalid UTF-8: {e}") from None

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise Rejected(f"duplicate key {key!r}")
            result[key] = value
        return result

    def constant(name: str) -> Any:
        raise Rejected(f"non-JSON number {name}")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except json.JSONDecodeError as e:
        raise Rejected(f"malformed JSON: {e}") from None

    def depth(node: Any, level: int) -> None:
        if isinstance(node, (dict, list)):
            if level > max_depth:
                raise Rejected(f"nesting deeper than {max_depth}")
            for child in node.values() if isinstance(node, dict) else node:
                depth(child, level + 1)

    depth(value, 1)
    return value


def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_canonical(text: Any, what: str) -> bytes:
    if not isinstance(text, str):
        raise Rejected(f"{what} is not a string")
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError:
        raise Rejected(f"{what} is not base64") from None
    if b64(data) != text:
        raise Rejected(f"{what} is not canonical base64")
    return data


def utc_text(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(text: Any, what: str) -> dt.datetime:
    if not isinstance(text, str) or not text.endswith("Z"):
        raise Rejected(f"{what} is not a UTC timestamp")
    try:
        return dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        raise Rejected(f"{what} is not a UTC timestamp") from None


# --- Ed25519 through openssl ------------------------------------------------------


def _openssl(*args: str, stdin: bytes | None = None,
             passin: str | None = None, passout: str | None = None) -> bytes:
    """Runs openssl. Passphrases go through pipes (`fd:N`), never through the
    command line or the environment."""
    fds: list[int] = []
    extra: list[str] = []
    try:
        for flag, value in (("-passin", passin), ("-passout", passout)):
            if value is not None:
                read_end, write_end = os.pipe()
                os.write(write_end, value.encode() + b"\n")
                os.close(write_end)
                fds.append(read_end)
                extra += [flag, f"fd:{read_end}"]
        proc = subprocess.run(
            ["openssl", *args, *extra],
            input=stdin,
            capture_output=True,
            pass_fds=tuple(fds),
        )
    finally:
        for fd in fds:
            os.close(fd)
    if proc.returncode != 0:
        raise Rejected(f"openssl {args[0]} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    path: Path
    passphrase: str | None = None


def raw_public_key(private_key: Path | bytes, passphrase: str | None = None) -> bytes:
    """From a key file, or from an unencrypted PEM in memory."""
    if isinstance(private_key, bytes):
        der = _openssl("pkey", "-pubout", "-outform", "DER", stdin=private_key)
    else:
        der = _openssl("pkey", "-in", str(private_key), "-pubout", "-outform", "DER", passin=passphrase)
    if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        raise Rejected("not an Ed25519 key")
    return der[len(ED25519_SPKI_PREFIX):]


def ed25519_sign(key: SigningKey, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        msg = Path(tmp, "message")
        msg.write_bytes(message)
        sig = _openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(key.path), "-in", str(msg),
                       passin=key.passphrase)
    if len(sig) != 64:
        raise Rejected("openssl produced a signature of the wrong length")
    return sig


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        pub = Path(tmp, "pub.der")
        pub.write_bytes(ED25519_SPKI_PREFIX + public_key)
        msg = Path(tmp, "message")
        msg.write_bytes(message)
        sig = Path(tmp, "sig")
        sig.write_bytes(signature)
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
             "-inkey", str(pub), "-in", str(msg), "-sigfile", str(sig)],
            capture_output=True,
        )
    return proc.returncode == 0


# --- Keys ---------------------------------------------------------------------


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    public_key: bytes


def load_trusted_keys(path: Path) -> list[TrustedKey]:
    doc = strict_json_loads(path.read_bytes())
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise Fatal(f"{path}: expected {{\"keys\": [...]}}")
    keys = []
    for entry in doc["keys"]:
        if not isinstance(entry, dict):
            raise Fatal(f"{path}: malformed key entry")
        key_id = entry.get("keyId")
        if not isinstance(key_id, str) or not KEY_ID.match(key_id):
            raise Fatal(f"{path}: malformed keyId {key_id!r}")
        try:
            public = b64_canonical(entry.get("ed25519PublicKey"), f"{key_id} public key")
        except Rejected as e:
            raise Fatal(f"{path}: {e}") from None
        if len(public) != 32:
            raise Fatal(f"{path}: {key_id} public key is not 32 bytes")
        keys.append(TrustedKey(key_id, public))
    if len({k.key_id for k in keys}) != len(keys):
        raise Fatal(f"{path}: duplicate keyId")
    return keys


def key_id_for(private_key: Path, trusted: list[TrustedKey], passphrase: str | None = None) -> str:
    public = raw_public_key(private_key, passphrase)
    for key in trusted:
        if key.public_key == public:
            return key.key_id
    raise Fatal("the signing key's public half is not in keys/trusted_keys.json")


# --- Envelope -------------------------------------------------------------------


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


@dataclass
class VerifiedEnvelope:
    payload: bytes
    key_ids: list[str]

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def verify_envelope(data: bytes, trusted: list[TrustedKey]) -> VerifiedEnvelope:
    """The client's order (5.1): size, strict parse, payload type, at least one
    valid signature by a trusted key; only then is the payload handed out."""
    if len(data) > MAX_ENVELOPE_BYTES:
        raise Rejected("envelope too large")
    doc = strict_json_loads(data)
    if not isinstance(doc, dict):
        raise Rejected("envelope is not an object")
    if doc.get("payloadType") != PAYLOAD_TYPE:
        raise Rejected("unknown payloadType")
    payload = b64_canonical(doc.get("payload"), "payload")
    signatures = doc.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise Rejected("no signatures")
    message = dsse_pae(PAYLOAD_TYPE, payload)
    verified = []
    for entry in signatures:
        if not isinstance(entry, dict) or not isinstance(entry.get("keyid"), str):
            raise Rejected("malformed signature entry")
        sig = b64_canonical(entry.get("sig"), "signature")
        if len(sig) != 64:
            raise Rejected("signature of the wrong length")
        key = next((k for k in trusted if k.key_id == entry["keyid"]), None)
        if key and ed25519_verify(key.public_key, message, sig):
            verified.append(key.key_id)
    if not verified:
        raise Rejected("no valid signature by a trusted key")
    return VerifiedEnvelope(payload, verified)


def sign_envelope(payload: bytes, signing_keys: list[SigningKey]) -> bytes:
    message = dsse_pae(PAYLOAD_TYPE, payload)
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": b64(payload),
        "signatures": [
            {"keyid": key.key_id, "sig": b64(ed25519_sign(key, message))}
            for key in signing_keys
        ],
    }
    return (json.dumps(envelope, indent=2) + "\n").encode()


# --- Catalogue payload validation ------------------------------------------------


def _obj(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Rejected(f"{what} is not an object")
    return value


def _list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise Rejected(f"{what} is not a list")
    return value


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise Rejected(f"{what} is not a non-empty string")
    return value


def _nat(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise Rejected(f"{what} is not a non-negative integer")
    return value


@dataclass
class Catalogue:
    package_id: str
    revision: int
    issued_at: dt.datetime
    expires_at: dt.datetime
    payload: dict[str, Any]
    digest: str

    def content(self) -> dict[str, Any]:
        """What a new revision is compared on: releases and advisories."""
        return {
            "releases": self.payload.get("releases", []),
            "advisories": self.payload.get("advisories", []),
        }

    def targets(self) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
        """Target ID → (target, its release)."""
        return {
            t["id"]: (t, r)
            for r in self.payload.get("releases", [])
            for t in r.get("targets", [])
        }


def validate_catalogue(payload_bytes: bytes, package_id: str) -> Catalogue:
    """The hard rules of the client's CatalogueCodec, so that nothing this tool
    publishes is rejected by the app as a whole."""
    root = _obj(strict_json_loads(payload_bytes), "payload")
    if root.get("schemaVersion") != 1:
        raise Rejected(f"schemaVersion {root.get('schemaVersion')!r}")
    if _obj(root.get("scope"), "scope").get("packageId") != package_id:
        raise Rejected("catalogue for another package")
    sequences = set()
    for release in _list(root.get("releases"), "releases"):
        release = _obj(release, "release")
        _str(release.get("releaseId"), "releaseId")
        _str(release.get("appVersion"), "appVersion")
        seq = _nat(release.get("logicalReleaseSequence"), "logicalReleaseSequence")
        if seq in sequences:
            raise Rejected("duplicate release sequence")
        sequences.add(seq)
        if release.get("components") is not None:
            _obj(release["components"], "components")
        ids = set()
        for target in _list(release.get("targets"), "targets"):
            target = _obj(target, "target")
            ids.add(_str(target.get("id"), "target.id"))
            _str(target.get("distribution"), "distribution")
            _nat(target.get("versionCode"), "versionCode")
            _nat(target.get("minSdk"), "minSdk")
            if target.get("artifact") is not None:
                artifact = _obj(target["artifact"], "artifact")
                url = _str(artifact.get("url"), "artifact.url")
                if not url.startswith("https://"):
                    raise Rejected("artifact url is not https")
                if not SHA256_HEX.match(str(artifact.get("sha256"))):
                    raise Rejected("artifact sha256 malformed")
                if _nat(artifact.get("byteLength"), "artifact.byteLength") == 0:
                    raise Rejected("artifact is empty")
            if target.get("components") is not None:
                _obj(target["components"], "target.components")
        if len(ids) != len(release["targets"]):
            raise Rejected("duplicate target id")
    if root.get("advisories") is not None:
        for advisory in _list(root["advisories"], "advisories"):
            advisory = _obj(advisory, "advisory")
            _str(advisory.get("id"), "advisory.id")
            affected = _obj(advisory.get("affected"), "advisory.affected")
            _nat(affected.get("fixedInSequence"), "fixedInSequence")
            if affected.get("introducedInSequence") is not None:
                _nat(affected["introducedInSequence"], "introducedInSequence")
    issued = parse_utc(root.get("issuedAt"), "issuedAt")
    expires = parse_utc(root.get("expiresAt"), "expiresAt")
    if expires <= issued:
        raise Rejected("expiresAt before issuedAt")
    return Catalogue(
        package_id=package_id,
        revision=_nat(root.get("revision"), "revision"),
        issued_at=issued,
        expires_at=expires,
        payload=root,
        digest=hashlib.sha256(payload_bytes).hexdigest(),
    )


def catalogue_path(site: Path, package_id: str) -> Path:
    return site / "v1" / package_id / "catalogue.json"


def read_catalogue(path: Path, package_id: str, trusted: list[TrustedKey]) -> Catalogue:
    envelope = verify_envelope(path.read_bytes(), trusted)
    return validate_catalogue(envelope.payload, package_id)


# --- Policy -----------------------------------------------------------------------


@dataclass
class Policy:
    withdrawn: set[str] = field(default_factory=set)
    advisories: list[dict[str, Any]] = field(default_factory=list)
    security: dict[str, str] = field(default_factory=dict)

    def advisories_for(self, package_id: str) -> list[dict[str, Any]]:
        result = []
        for advisory in self.advisories:
            packages = advisory.get("packages")
            if packages is None or package_id in packages:
                result.append({k: v for k, v in advisory.items() if k != "packages"})
        return result


def load_policy(directory: Path) -> Policy:
    """Reviewed content: anything malformed stops the run."""
    def load(path: Path) -> Any:
        try:
            return strict_json_loads(path.read_bytes())
        except Rejected as e:
            raise Fatal(f"{path}: {e}") from None

    policy = Policy()

    withdrawn = load(directory / "withdrawn.json")
    if not isinstance(withdrawn, dict) or not isinstance(withdrawn.get("withdrawn"), list):
        raise Fatal("policy/withdrawn.json: expected {\"withdrawn\": [...]}")
    for entry in withdrawn["withdrawn"]:
        if not (isinstance(entry, dict) and isinstance(entry.get("id"), str)
                and isinstance(entry.get("date"), str) and isinstance(entry.get("reason"), str)):
            raise Fatal("policy/withdrawn.json: every entry needs id, date and reason")
        policy.withdrawn.add(entry["id"])

    advisories = load(directory / "advisories.json")
    if not isinstance(advisories, dict) or not isinstance(advisories.get("advisories"), list):
        raise Fatal("policy/advisories.json: expected {\"advisories\": [...]}")
    ids = set()
    for a in advisories["advisories"]:
        try:
            a = _obj(a, "advisory")
            advisory_id = _str(a.get("id"), "id")
            url = _str(a.get("url"), "url")
            if not url.startswith("https://"):
                raise Rejected("url is not https")
            if a.get("severity") not in SEVERITIES:
                raise Rejected(f"severity must be one of {sorted(SEVERITIES)}")
            affected = _obj(a.get("affected"), "affected")
            fixed = _nat(affected.get("fixedInSequence"), "fixedInSequence")
            introduced = affected.get("introducedInSequence")
            if introduced is not None and _nat(introduced, "introducedInSequence") >= fixed:
                raise Rejected("introducedInSequence must be below fixedInSequence")
            if set(affected) - {"fixedInSequence", "introducedInSequence"}:
                raise Rejected("unknown field in affected")
            packages = a.get("packages")
            if packages is not None and (
                not isinstance(packages, list) or not set(packages) <= set(PACKAGES)
            ):
                raise Rejected(f"packages must be a subset of {sorted(PACKAGES)}")
            if set(a) - {"id", "url", "severity", "affected", "packages"}:
                raise Rejected("unknown field")
        except Rejected as e:
            raise Fatal(f"policy/advisories.json: {e}") from None
        if advisory_id in ids:
            raise Fatal(f"policy/advisories.json: duplicate id {advisory_id}")
        ids.add(advisory_id)
        policy.advisories.append(a)

    security_dir = directory / "release-security"
    if security_dir.is_dir():
        for path in sorted(security_dir.glob("*.json")):
            doc = load(path)
            if not isinstance(doc, dict) or doc.get("classification") not in CLASSIFICATIONS or len(doc) != 1:
                raise Fatal(f"{path}: expected {{\"classification\": one of {sorted(CLASSIFICATIONS)}}}")
            policy.security[path.stem] = doc["classification"]

    return policy


# --- Sources ----------------------------------------------------------------------


@dataclass
class GithubAsset:
    name: str
    size: int
    url: str
    digest: str | None  # "sha256:<hex>" when GitHub reports it


@dataclass
class GithubRelease:
    tag: str
    prerelease: bool
    published_at: str
    assets: dict[str, GithubAsset]


class Network:
    """The only place that talks to the network, so tests can replace it."""

    def __init__(self, token: str | None):
        self.token = token

    def _open(self, url: str, api: bool):
        if not url.startswith("https://"):
            raise Fatal(f"refusing non-https URL {url}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        if api:
            request.add_header("Accept", "application/vnd.github+json")
            request.add_header("X-GitHub-Api-Version", "2022-11-28")
            if self.token:
                # Never forwarded on a redirect.
                request.add_unredirected_header("Authorization", f"Bearer {self.token}")
        return urllib.request.urlopen(request, timeout=60)

    def list_releases(self) -> list[GithubRelease]:
        releases: list[GithubRelease] = []
        for page in range(1, 4):
            try:
                with self._open(f"{API_RELEASES}?per_page=100&page={page}", api=True) as response:
                    items = json.loads(response.read())
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                raise Fatal(f"listing releases failed: {e}") from None
            if not isinstance(items, list):
                raise Fatal("listing releases returned something other than a list")
            for item in items:
                if item.get("draft"):
                    continue
                releases.append(GithubRelease(
                    tag=item["tag_name"],
                    prerelease=bool(item.get("prerelease")),
                    published_at=item.get("published_at") or "",
                    assets={
                        a["name"]: GithubAsset(a["name"], a["size"], a["browser_download_url"], a.get("digest"))
                        for a in item.get("assets", [])
                        if a.get("state", "uploaded") == "uploaded"
                    },
                ))
            if len(items) < 100:
                break
        return releases

    def fetch(self, url: str, max_bytes: int) -> bytes:
        try:
            with self._open(url, api=False) as response:
                data = response.read(max_bytes + 1)
        except (urllib.error.URLError, TimeoutError) as e:
            raise Fatal(f"downloading {url} failed: {e}") from None
        if len(data) > max_bytes:
            raise Rejected(f"{url} is larger than {max_bytes} bytes")
        return data

    def download(self, url: str, dest: Path, expected_length: int) -> str:
        """Streams to `dest`, at most `expected_length` bytes; returns SHA-256."""
        digest = hashlib.sha256()
        received = 0
        try:
            with self._open(url, api=False) as response, dest.open("wb") as out:
                while chunk := response.read(1 << 20):
                    received += len(chunk)
                    if received > expected_length:
                        raise Rejected(f"{url} is longer than {expected_length} bytes")
                    digest.update(chunk)
                    out.write(chunk)
        except (urllib.error.URLError, TimeoutError) as e:
            raise Fatal(f"downloading {url} failed: {e}") from None
        if received != expected_length:
            raise Rejected(f"{url}: {received} bytes, release.json says {expected_length}")
        return digest.hexdigest()

    def fetch_served(self, url: str) -> bytes | None:
        """The live site, past the CDN cache. None when it serves nothing."""
        try:
            with self._open(f"{url}?nocache={secrets.token_hex(8)}", api=False) as response:
                return response.read(MAX_ENVELOPE_BYTES + 1)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise Fatal(f"fetching {url} failed: {e}") from None
        except (urllib.error.URLError, TimeoutError) as e:
            raise Fatal(f"fetching {url} failed: {e}") from None


# --- APK verification ----------------------------------------------------------------


def find_build_tools(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(variable)
        if root and (Path(root) / "build-tools").is_dir():
            versions = sorted(
                (p for p in (Path(root) / "build-tools").iterdir() if (p / "apksigner").exists()),
                key=lambda p: [int(x) if x.isdigit() else 0 for x in re.split(r"[.-]", p.name)],
            )
            if versions:
                return versions[-1]
    raise Fatal("no Android build tools found: set ANDROID_HOME or pass --build-tools")


class ApkVerifier:
    """Checks a downloaded APK against its catalogue target (9.2 step 3)."""

    def __init__(self, build_tools: Path, certificate_sha256: str = PRODUCTION_CERT_SHA256):
        self.apksigner = build_tools / "apksigner"
        self.aapt2 = build_tools / "aapt2"
        self.certificate_sha256 = certificate_sha256

    @staticmethod
    def _run(*args: str) -> str:
        proc = subprocess.run(args, capture_output=True, text=True)
        if proc.returncode != 0:
            raise Rejected(f"{Path(args[0]).name} failed: {(proc.stderr or proc.stdout).strip()[:500]}")
        return proc.stdout

    def check(self, apk: Path, target: dict[str, Any], release: dict[str, Any], package_id: str) -> None:
        out = self._run(str(self.apksigner), "verify", "--print-certs", str(apk))
        signers = re.findall(r"certificate SHA-256 digest: ([0-9a-f]{64})", out)
        if signers != [self.certificate_sha256]:
            raise Rejected(f"signed by {signers}, not the production certificate")

        badging = self._run(str(self.aapt2), "dump", "badging", str(apk))
        package = re.search(r"package: name='([^']+)' versionCode='(\d+)'", badging)
        sdk = re.search(r"sdkVersion:'(\d+)'", badging)
        native = re.search(r"native-code: (.+)", badging)
        abis = sorted(re.findall(r"'([^']+)'", native.group(1))) if native else []
        if not package or package.group(1) != package_id:
            raise Rejected(f"package {package and package.group(1)}, expected {package_id}")
        if int(package.group(2)) != target["versionCode"]:
            raise Rejected(f"versionCode {package.group(2)}, target says {target['versionCode']}")
        if not sdk or int(sdk.group(1)) != target["minSdk"]:
            raise Rejected(f"minSdk {sdk and sdk.group(1)}, target says {target['minSdk']}")
        if abis != [target["abi"]]:
            raise Rejected(f"native code {abis}, target says {target['abi']}")

        try:
            with zipfile.ZipFile(apk) as z:
                manifest = strict_json_loads(z.read(MANIFEST_ENTRY))
        except (KeyError, zipfile.BadZipFile) as e:
            raise Rejected(f"no readable build manifest: {e}") from None
        self.check_manifest(manifest, target, release, package_id)

    @staticmethod
    def check_manifest(manifest: Any, target: dict[str, Any], release: dict[str, Any], package_id: str) -> None:
        """The embedded build identity against the target's fields."""
        manifest = _obj(manifest, "build manifest")
        expected = {
            "packageId": package_id,
            "distribution": "github",
            "track": target["track"],
            "renderer": target["renderer"],
            "logicalReleaseSequence": release["logicalReleaseSequence"],
        }
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise Rejected(f"build manifest {key}={manifest.get(key)!r}, expected {value!r}")
        codes = manifest.get("abiVersionCodes")
        if not isinstance(codes, dict) or codes.get(target["abi"]) != target["versionCode"]:
            raise Rejected("build manifest abiVersionCodes disagree with the target")
        if not str(manifest.get("versionName", "")).startswith(release["appVersion"]):
            raise Rejected(f"build manifest versionName {manifest.get('versionName')!r}")
        if manifest.get("components") != release.get("components"):
            raise Rejected("build manifest components differ from release.json")


# --- release.json (untrusted data) -------------------------------------------------


def _summary(notes: Any, problems: "Problems", tag: str) -> dict[str, str] | None:
    """Re-checks 5.2's limits; a summary that breaks them is omitted, never
    fatal."""
    if not isinstance(notes, dict) or notes.get("summary") is None:
        return None
    summary = notes["summary"]
    if not isinstance(summary, dict):
        problems.warn(f"{tag}: summary omitted: not an object")
        return None
    kept = {k: v for k, v in summary.items() if k in SHIPPED_LANGUAGES}
    if set(summary) - SHIPPED_LANGUAGES:
        problems.warn(f"{tag}: summary languages dropped: {sorted(set(summary) - SHIPPED_LANGUAGES)}")
    if not isinstance(kept.get("en"), str):
        problems.warn(f"{tag}: summary omitted: no en text")
        return None
    for locale, text in kept.items():
        if (not isinstance(text, str) or not text.strip()
                or len(text.encode("utf-16-le")) // 2 > MAX_SUMMARY_CHARS
                or len(text.encode()) > MAX_SUMMARY_BYTES):
            problems.warn(f"{tag}: summary omitted: {locale} breaks the limits of 5.2")
            return None
    return dict(sorted(kept.items()))


def _components(value: Any) -> dict[str, Any]:
    components = _obj(value, "components")
    for name, component in components.items():
        component = _obj(component, f"components.{name}")
        if component.get("status", "known") not in COMPONENT_STATUSES:
            raise Rejected(f"components.{name}: unknown status")
        for key, v in component.items():
            if key not in {"status", "version", "buildId", "revision"} or not isinstance(v, str):
                raise Rejected(f"components.{name}.{key} is not allowed")
    return components


def parse_release_json(data: bytes, release: GithubRelease, problems: "Problems") -> tuple[str, dict[str, Any]]:
    """Turns an app release's release.json into a catalogue release entry and
    its package ID. Raises Rejected for anything inconsistent."""
    doc = _obj(strict_json_loads(data), "release.json")
    tag = release.tag
    if doc.get("schemaVersion") != 1:
        raise Rejected(f"schemaVersion {doc.get('schemaVersion')!r}")
    package_id = doc.get("packageId")
    if package_id not in PACKAGES:
        raise Rejected(f"unknown packageId {package_id!r}")
    track = PACKAGES[package_id]
    if doc.get("releaseId") != tag:
        raise Rejected(f"releaseId {doc.get('releaseId')!r} is not the tag")
    if doc.get("appVersion") != tag.removeprefix("v"):
        raise Rejected(f"appVersion {doc.get('appVersion')!r} does not match the tag")
    seq = _nat(doc.get("logicalReleaseSequence"), "logicalReleaseSequence")
    if seq == 0:
        raise Rejected("logicalReleaseSequence is 0")
    components = _components(doc.get("components"))

    targets = []
    for t in _list(doc.get("targets"), "targets"):
        t = _obj(t, "target")
        distribution = t.get("distribution")
        if t.get("track") != track:
            raise Rejected(f"target track {t.get('track')!r} in a {track} package")
        renderer = t.get("renderer")
        if renderer not in RENDERERS:
            raise Rejected(f"unknown renderer {renderer!r}")
        version_code = _nat(t.get("versionCode"), "versionCode")
        min_sdk = _nat(t.get("minSdk"), "minSdk")
        if distribution == "github":
            abi = t.get("abi")
            if abi not in ABI_DIGITS:
                raise Rejected(f"unknown abi {abi!r}")
            if t.get("id") != f"{tag}/github/{track}/{renderer}/{abi}":
                raise Rejected(f"target id {t.get('id')!r}")
            if version_code != seq * 10 + ABI_DIGITS[abi]:
                raise Rejected(f"{t['id']}: versionCode {version_code} is not {seq}*10+{ABI_DIGITS[abi]}")
            artifact = _obj(t.get("artifact"), "artifact")
            url = _str(artifact.get("url"), "artifact.url")
            name = url.removeprefix(f"{RELEASE_DOWNLOAD_PREFIX}{tag}/")
            match = APK_NAME.match(name)
            if url == name or not match:
                raise Rejected(f"{t['id']}: artifact url {url!r} is not one of this release's APKs")
            flavor = match.group("flavor")
            if (match.group("abi") != abi or not flavor.startswith(track)
                    or flavor.endswith("Impeller") != (renderer == "impeller")):
                raise Rejected(f"{t['id']}: artifact {name} is not this target's")
            sha = artifact.get("sha256")
            if not isinstance(sha, str) or not SHA256_HEX.match(sha):
                raise Rejected(f"{t['id']}: malformed sha256")
            length = _nat(artifact.get("byteLength"), "byteLength")
            if not 0 < length <= MAX_APK_BYTES:
                raise Rejected(f"{t['id']}: byteLength {length}")
            asset = release.assets.get(name)
            if asset is None or asset.size != length:
                raise Rejected(f"{t['id']}: the release has no asset {name} of {length} bytes")
            if asset.digest and asset.digest != f"sha256:{sha}":
                raise Rejected(f"{t['id']}: GitHub reports {asset.digest} for {name}")
            targets.append({
                "id": t["id"], "distribution": "github", "track": track, "renderer": renderer,
                "abi": abi, "versionCode": version_code, "minSdk": min_sdk,
                "artifact": {"url": url, "byteLength": length, "sha256": sha},
            })
        elif distribution == "play":
            if track != "stable" or renderer != "skia":
                raise Rejected("play target outside stable/skia")
            if t.get("id") != f"{tag}/play/{track}/{renderer}":
                raise Rejected(f"target id {t.get('id')!r}")
            if version_code != seq:
                raise Rejected(f"play versionCode {version_code} is not the sequence {seq}")
            if "artifact" in t:
                raise Rejected("play target with an artifact")
            targets.append({
                "id": t["id"], "distribution": "play", "track": track, "renderer": renderer,
                "versionCode": version_code, "minSdk": min_sdk,
            })
        else:
            raise Rejected(f"unknown distribution {distribution!r}")
    if not targets:
        raise Rejected("no targets")
    if len({t["id"] for t in targets}) != len(targets):
        raise Rejected("duplicate target id")
    targets.sort(key=lambda t: t["id"])

    notes: dict[str, Any] = {"url": f"{RELEASE_TAG_PREFIX}{tag}"}
    raw_notes = doc.get("releaseNotes")
    if isinstance(raw_notes, dict) and raw_notes.get("url") not in (None, notes["url"]):
        raise Rejected(f"releaseNotes.url {raw_notes.get('url')!r}")
    summary = _summary(raw_notes, problems, tag)
    if summary:
        notes["summary"] = summary

    return package_id, {
        "releaseId": tag,
        "appVersion": doc["appVersion"],
        "logicalReleaseSequence": seq,
        "targets": targets,
        "components": components,
        "releaseNotes": notes,
    }


# --- The update run ----------------------------------------------------------------


class Problems:
    """Problems that exclude a release (errors) or only lose a detail
    (warnings). Errors make the run end unsuccessfully, after publishing."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)
        print(f"::error::{message}", file=sys.stderr)

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        print(f"::warning::{message}", file=sys.stderr)


@dataclass
class UpdateResult:
    written: list[str]
    problems: Problems
    summary: str


def collect_releases(
    network: Network, policy: Policy, problems: Problems,
) -> dict[str, list[dict[str, Any]]]:
    """Package ID → its newest valid releases, newest first, withdrawals
    applied. APKs are not checked here."""
    candidates = [r for r in network.list_releases() if "release.json" in r.assets]
    candidates.sort(key=lambda r: r.published_at, reverse=True)
    by_package: dict[str, list[dict[str, Any]]] = {p: [] for p in PACKAGES}
    for release in candidates[:SCANNED_RELEASES]:
        if release.tag in policy.withdrawn:
            continue  # Never looked at: a withdrawal also silences a broken release.
        asset = release.assets["release.json"]
        if asset.url != f"{RELEASE_DOWNLOAD_PREFIX}{release.tag}/release.json":
            problems.error(f"{release.tag}: release.json has an unexpected URL {asset.url}")
            continue
        try:
            data = network.fetch(asset.url, MAX_RELEASE_JSON_BYTES)
            package_id, entry = parse_release_json(data, release, problems)
        except Rejected as e:
            problems.error(f"{release.tag}: release.json rejected: {e}")
            continue
        by_package[package_id].append(entry)

    for package_id, releases in by_package.items():
        counts: dict[int, int] = {}
        for r in releases:
            counts[r["logicalReleaseSequence"]] = counts.get(r["logicalReleaseSequence"], 0) + 1
        for seq, n in counts.items():
            if n > 1:
                tags = [r["releaseId"] for r in releases if r["logicalReleaseSequence"] == seq]
                problems.error(f"{package_id}: sequence {seq} claimed by {tags}; all excluded")
        releases[:] = [r for r in releases if counts[r["logicalReleaseSequence"]] == 1]
        releases.sort(key=lambda r: r["logicalReleaseSequence"], reverse=True)
        del releases[RETAINED_RELEASES:]
        for r in releases:
            r["targets"] = [t for t in r["targets"] if t["id"] not in policy.withdrawn]
        releases[:] = [r for r in releases if r["targets"]]
    return by_package


def verify_new_targets(
    package_id: str,
    releases: list[dict[str, Any]],
    head: Catalogue | None,
    network: Network,
    verifier: Callable[[], ApkVerifier],
    problems: Problems,
) -> tuple[list[dict[str, Any]], int]:
    """Drops every release with a GitHub target that fails verification.
    Returns the remaining releases and the number of APKs downloaded."""
    head_targets = head.targets() if head else {}
    downloaded = 0
    kept = []
    for release in releases:
        try:
            for target in release["targets"]:
                if target["distribution"] != "github":
                    continue
                known = head_targets.get(target["id"])
                if known is not None:
                    known_target, known_release = known
                    if known_target.get("artifact") != target["artifact"]:
                        raise Fatal(
                            f"{target['id']}: the verified catalogue has {known_target.get('artifact')}, "
                            f"release.json now says {target['artifact']}. Immutable releases make this "
                            "impossible; find out what happened before publishing anything."
                        )
                    if known_target == target and known_release.get("components") == release["components"]:
                        continue  # Verified when it was first signed; the signed head is the proof.
                with tempfile.TemporaryDirectory() as tmp:
                    apk = Path(tmp, "candidate.apk")
                    artifact = target["artifact"]
                    sha = network.download(artifact["url"], apk, artifact["byteLength"])
                    downloaded += 1
                    if sha != artifact["sha256"]:
                        raise Rejected(f"{target['id']}: SHA-256 {sha}, release.json says {artifact['sha256']}")
                    verifier().check(apk, target, release, package_id)
                print(f"verified {target['id']}")
        except Rejected as e:
            problems.error(f"{release['releaseId']}: excluded: {e}")
            continue
        kept.append(release)
    return kept, downloaded


def build_payload(
    package_id: str,
    releases: list[dict[str, Any]],
    policy: Policy,
    revision: int,
    issued_at: dt.datetime,
) -> dict[str, Any]:
    entries = []
    for index, release in enumerate(releases):
        entry = copy.deepcopy(release)
        entry["security"] = {"classification": policy.security.get(release["releaseId"], "unknown")}
        if index >= SUMMARIZED_RELEASES:
            entry["releaseNotes"].pop("summary", None)
        # Key order as the plan shows it, for readable diffs.
        entries.append({k: entry[k] for k in (
            "releaseId", "appVersion", "logicalReleaseSequence", "targets",
            "components", "security", "releaseNotes")})
    return {
        "schemaVersion": 1,
        "scope": {"packageId": package_id},
        "revision": revision,
        "issuedAt": utc_text(issued_at),
        "expiresAt": utc_text(issued_at + VALIDITY),
        "releases": entries,
        "advisories": policy.advisories_for(package_id),
    }


def run_update(
    site: Path,
    trusted: list[TrustedKey],
    signing_keys: list[SigningKey],
    policy: Policy,
    network: Network,
    verifier: Callable[[], ApkVerifier],
    now: dt.datetime,
    force_refresh: bool = False,
) -> UpdateResult:
    problems = Problems()

    # 1. The catalogues at the branch head are the revision record.
    heads: dict[str, Catalogue | None] = {}
    for package_id in PACKAGES:
        path = catalogue_path(site, package_id)
        if not path.exists():
            heads[package_id] = None
            continue
        try:
            heads[package_id] = read_catalogue(path, package_id, trusted)
        except Rejected as e:
            raise Fatal(f"{path}: the head catalogue does not verify: {e}") from None

    # 2. Releases, policy applied.
    collected = collect_releases(network, policy, problems)
    if not any(collected.values()) and any(h and h.payload["releases"] for h in heads.values()):
        # More likely a glitch in the listing than every release deleted at
        # once. Publishing would withhold every update until the next run.
        raise Fatal("no release found, but the head catalogues list some; not publishing an empty catalogue")

    # 3–5. Per package: verify what is new, decide, sign.
    pending: list[tuple[Path, bytes]] = []
    notes = []
    downloads = 0
    for package_id in PACKAGES:
        head = heads[package_id]
        releases, n = verify_new_targets(
            package_id, collected[package_id], head, network, verifier, problems,
        )
        downloads += n
        issued_at = now.replace(microsecond=0)
        if head:
            issued_at = max(issued_at, head.issued_at)
        candidate = build_payload(package_id, releases, policy, 0, issued_at)
        content = {"releases": candidate["releases"], "advisories": candidate["advisories"]}

        if head is not None and not force_refresh:
            changed = content != head.content()
            stale = now - head.issued_at > REFRESH_AFTER
            if not changed and not stale:
                print(f"{package_id}: unchanged, revision {head.revision} issued {utc_text(head.issued_at)}")
                continue
            reason = "changed" if changed else "weekly refresh"
        else:
            reason = "first catalogue" if head is None else "refresh requested"

        revision = head.revision + 1 if head else 1
        candidate["revision"] = revision
        payload = canonical_payload(candidate)
        envelope = sign_envelope(payload, signing_keys)

        # Self-verify exactly what will be written, with the public keys.
        try:
            verified = verify_envelope(envelope, trusted)
            if set(verified.key_ids) != {k.key_id for k in signing_keys}:
                raise Rejected("not every signing key verified")
            validate_catalogue(verified.payload, package_id)
        except Rejected as e:
            raise Fatal(f"{package_id}: the new catalogue fails its own verification: {e}") from None

        pending.append((catalogue_path(site, package_id), envelope))
        tags = ", ".join(r["releaseId"] for r in releases) or "no releases"
        notes.append(f"{package_id} r{revision} ({reason}): {tags}")

    for path, envelope in pending:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(envelope)

    print(f"downloaded and verified {downloads} APK(s)")
    summary = "; ".join(notes)
    return UpdateResult([str(p) for p, _ in pending], problems, summary)


# --- Commands -----------------------------------------------------------------------


def _signing_keys(args: argparse.Namespace, trusted: list[TrustedKey], keydir: Path) -> list[SigningKey]:
    """Key files from --key (asking for the passphrase of an encrypted one),
    and keys from --key-env written to `keydir` (mode 0600) and removed from
    the environment, so that no child process (openssl, apksigner) inherits
    them."""
    keys: list[tuple[Path, str | None]] = []
    for name in args.key or []:
        path = Path(name)
        passphrase = None
        if b"ENCRYPTED" in path.read_bytes():
            passphrase = getpass.getpass(f"Passphrase for {path}: ")
        keys.append((path, passphrase))
    for index, variable in enumerate(args.key_env or []):
        value = os.environ.pop(variable, None)
        if not value:
            raise Fatal(f"environment variable {variable} is empty")
        path = keydir / f"key{index}.pem"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value if value.endswith("\n") else value + "\n")
        keys.append((path, None))
    if not keys:
        raise Fatal("no signing key: pass --key FILE or --key-env VARIABLE")
    return [SigningKey(key_id_for(p, trusted, pw), p, pw) for p, pw in keys]


def cmd_keygen(args: argparse.Namespace) -> int:
    if not KEY_ID.match(args.key_id):
        raise Fatal(f"key IDs look like wl-meta-2026a, not {args.key_id!r}")
    out = Path(args.out) / f"{args.key_id}.private.pem"
    if out.exists():
        raise Fatal(f"{out} exists; refusing to overwrite a key")
    pem = _openssl("genpkey", "-algorithm", "ed25519")
    public = b64(raw_public_key(pem))
    if args.encrypt:
        passphrase = getpass.getpass("Passphrase for the private key: ")
        if passphrase != getpass.getpass("Repeat the passphrase: "):
            raise Fatal("the passphrases differ")
        if len(passphrase) < 20:
            raise Fatal("use a generated passphrase of at least 20 characters")
        pem = _openssl(
                # scrypt at N=2^14, r=8: 16 MiB, the most every openssl
                # decrypts without raising its memory limit. The passphrase
                # carries the strength: use a long, generated one.
                "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-scrypt",
                "-scrypt_N", "16384", "-scrypt_r", "8", "-scrypt_p", "1",
                stdin=pem, passout=passphrase,
            )
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    del pem
    print(f"private key: {out}" + (" (passphrase-encrypted)" if args.encrypt else " (NOT encrypted)"))
    print("\nkeys/trusted_keys.json entry:")
    print(json.dumps({"keyId": args.key_id, "ed25519PublicKey": public}, indent=2))
    print("\napp (trusted_metadata_keys.dart):")
    print(f"  TrustedMetadataKey(\n    keyId: '{args.key_id}',\n    ed25519PublicKeyBase64: '{public}',\n  ),")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    root = Path(args.root)
    trusted = load_trusted_keys(root / "keys" / "trusted_keys.json")
    policy = load_policy(root / "policy")
    network = Network(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    tools: list[ApkVerifier] = []

    def verifier() -> ApkVerifier:
        if not tools:
            tools.append(ApkVerifier(find_build_tools(args.build_tools)))
        return tools[0]

    now = parse_utc(args.now, "--now") if args.now else dt.datetime.now(dt.timezone.utc)
    with tempfile.TemporaryDirectory() as keydir:
        signing = _signing_keys(args, trusted, Path(keydir))
        result = run_update(
            Path(args.site) if args.site else root / "site",
            trusted, signing, policy, network, verifier, now, args.refresh,
        )

    changed = bool(result.written)
    if args.commit_message and changed:
        Path(args.commit_message).write_text(f"Catalogue: {result.summary}\n")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")
    print(result.summary if changed else "nothing to publish")
    if result.problems.errors:
        print(f"{len(result.problems.errors)} release(s) excluded; see the errors above", file=sys.stderr)
        return 2
    return 0


def _envelope_files(paths: Iterable[str]) -> list[tuple[Path, str | None]]:
    result = []
    for p in map(Path, paths):
        if not p.exists() and p.suffix != ".json":
            continue  # A site directory that has no catalogues yet.
        if p.is_dir():
            for package_id in PACKAGES:
                path = catalogue_path(p, package_id)
                if path.exists():
                    result.append((path, package_id))
        else:
            package = p.parent.name if p.parent.name in PACKAGES else None
            result.append((p, package))
    return result


def cmd_verify(args: argparse.Namespace) -> int:
    trusted = load_trusted_keys(Path(args.keys))
    files = _envelope_files(args.paths)
    if not files:
        print("no catalogues found")
        return 0
    failed = False
    for path, package_id in files:
        try:
            envelope = verify_envelope(path.read_bytes(), trusted)
            if args.require_key and args.require_key not in envelope.key_ids:
                raise Rejected(f"not signed by {args.require_key}")
            if args.only_key and envelope.key_ids != [args.only_key]:
                raise Rejected(f"verified by {envelope.key_ids}, expected {args.only_key} alone")
            package_id = package_id or args.package
            if package_id is None:
                package_id = _obj(strict_json_loads(envelope.payload), "payload").get("scope", {}).get("packageId")
            c = validate_catalogue(envelope.payload, package_id)
            print(f"OK {path}: {package_id} revision {c.revision}, issued {utc_text(c.issued_at)}, "
                  f"expires {utc_text(c.expires_at)}, {len(c.payload['releases'])} release(s), "
                  f"signed by {', '.join(envelope.key_ids)}, payload sha256 {c.digest}")
        except Rejected as e:
            failed = True
            print(f"FAIL {path}: {e}", file=sys.stderr)
    return 1 if failed else 0


def cmd_sign(args: argparse.Namespace) -> int:
    trusted = load_trusted_keys(Path(args.keys))
    source = verify_envelope(Path(args.source).read_bytes(), trusted)
    with tempfile.TemporaryDirectory() as keydir:
        signing = _signing_keys(args, trusted, Path(keydir))
        envelope = sign_envelope(source.payload, signing)
    verify_envelope(envelope, trusted)
    out = Path(args.out)
    if out.exists():
        raise Fatal(f"{out} exists")
    out.write_bytes(envelope)
    print(f"wrote {out}, signed by {', '.join(k.key_id for k in signing)}")
    return 0


def cmd_served(args: argparse.Namespace) -> int:
    site = Path(args.site)
    network = Network(None)
    base = args.base.rstrip("/")
    deadline = time.monotonic() + args.wait
    while True:
        differs = []
        for package_id in PACKAGES:
            local = catalogue_path(site, package_id)
            if not local.exists():
                continue
            url = f"{base}/v1/{package_id}/catalogue.json"
            try:
                served = network.fetch_served(url)
            except Fatal as e:
                if args.require_same:
                    raise
                # Not reachable (no DNS yet, Pages down): deploying is the fix.
                print(f"::warning::{e}", file=sys.stderr)
                served = None
            if served != local.read_bytes():
                differs.append(package_id)
        if not differs or not args.require_same or time.monotonic() > deadline:
            break
        print(f"still serving an older catalogue for {differs}; retrying")
        time.sleep(30)

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as f:
            f.write(f"differs={'true' if differs else 'false'}\n")
    if differs:
        print(f"{base} serves something other than the head for {differs}")
        return 1 if args.require_same else 0
    print(f"{base} serves the head")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create a metadata key pair")
    p.add_argument("--key-id", required=True, help="e.g. wl-meta-2026a")
    p.add_argument("--out", default=".", help="directory for the private key file")
    p.add_argument("--encrypt", action="store_true", help="passphrase-encrypt the private key (scrypt)")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("update", help="the scheduled signing run")
    p.add_argument("--root", default=".", help="repository root")
    p.add_argument("--site", help="write catalogues here instead of <root>/site (for the drill)")
    p.add_argument("--key", action="append", help="private key file (repeatable)")
    p.add_argument("--key-env", action="append", help="environment variable holding a private key PEM")
    p.add_argument("--build-tools", help="Android build-tools directory (default: newest under ANDROID_HOME)")
    p.add_argument("--refresh", action="store_true", help="re-sign even if nothing changed")
    p.add_argument("--now", help="override the current time (tests)")
    p.add_argument("--commit-message", help="write a commit message here when something changed")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("verify", help="verify catalogue envelopes")
    p.add_argument("paths", nargs="+", help="envelope files or site directories")
    p.add_argument("--keys", default="keys/trusted_keys.json")
    p.add_argument("--package", help="package ID, when a file's path doesn't say")
    p.add_argument("--require-key", help="fail unless this key signed")
    p.add_argument("--only-key", help="fail unless this key, and no other, verified")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("sign", help="re-sign an envelope's payload with the given key(s) alone")
    p.add_argument("source", help="a verified envelope")
    p.add_argument("--out", required=True)
    p.add_argument("--keys", default="keys/trusted_keys.json")
    p.add_argument("--key", action="append")
    p.add_argument("--key-env", action="append")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("served", help="compare the live site with the site directory")
    p.add_argument("--site", default="site")
    p.add_argument("--base", default="https://updates.weblibre.eu")
    p.add_argument("--require-same", action="store_true", help="fail unless the live site serves the head")
    p.add_argument("--wait", type=int, default=0, help="with --require-same: keep retrying this many seconds")
    p.set_defaults(func=cmd_served)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Fatal as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    except Rejected as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
