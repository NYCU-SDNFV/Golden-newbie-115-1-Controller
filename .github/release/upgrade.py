#!/usr/bin/env python3
"""Student freshness checks and lossless updates, adapted from Golden-VRouter.

apply_update stages a public tag-to-tag three-way patch on a new branch.
It never commits, pushes, resets, or rewrites the student's original branch.
UpgradeConflict leaves the original HEAD and pending index/worktree available
for manual resolution. Only the CLI's update command commits the reviewed
template update, using the student's Git identity; it never pushes.
Absolute local template paths are supported only by the API for offline tests.
"""

import argparse
import hashlib
import http.client
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
import uuid


MARKER = ".lab-release.json"
MANIFEST = ".github/policy/manifest.sha256"
MAX_METADATA_BYTES = 16 * 1024
NETWORK_TIMEOUT = 10
GIT_TIMEOUT = 120
COAUTHOR = "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
DEVELOPMENT = {"schema": 1, "version": "development"}
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
CHANNEL_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
TAG_RE = re.compile(r"(?P<channel>[a-z0-9]+(?:-[a-z0-9]+)*)-v(?P<version>[0-9.]+)\Z")
PRESERVED = (".classroom50.yaml", ".github/workflows/autograde.yaml")
UPDATE_FLOW = (
    "Commit or stash your work (including untracked files), then run make update. "
    "Review and merge the resulting instructor/update-<tag> branch into your "
    "Classroom default branch, rerun make test, then push that default branch "
    "to resubmit. Pushing only the update branch is not a submission."
)


class UpgradeError(Exception):
    """An explicit, actionable freshness or update failure."""


class UpgradeConflict(UpgradeError):
    """An update needs manual resolution; its branch still has the old HEAD."""


def version_tuple(value):
    if not isinstance(value, str) or len(value) > 128 or not VERSION_RE.fullmatch(value):
        raise UpgradeError("Invalid release version: expected stable semver MAJOR.MINOR.PATCH.")
    return tuple(int(part) for part in value.split("."))


def _validate_tag(tag):
    if isinstance(tag, str) and len(tag) <= 128:
        match = TAG_RE.fullmatch(tag)
        if match and len(match["channel"]) <= 63:
            return match["channel"], version_tuple(match["version"])
    raise UpgradeError("Invalid immutable release tag; expected <channel>-vMAJOR.MINOR.PATCH.")


def validate_metadata(data, *, allow_development=False):
    if not isinstance(data, dict) or type(data.get("schema")) is not int or data["schema"] != 1:
        raise UpgradeError("Invalid release metadata: expected schema 1.")
    if allow_development and data == DEVELOPMENT:
        return data
    required = {"schema", "channel", "version", "tag", "template", "source_sha", "minimum_version"}
    if set(data) != required or not all(isinstance(data[key], str) for key in required - {"schema"}):
        raise UpgradeError("Invalid release metadata: missing, unexpected, or non-string fields.")
    channel = data["channel"]
    if len(channel) > 63 or not CHANNEL_RE.fullmatch(channel):
        raise UpgradeError("Invalid release channel: expected a safe configured channel such as newbie-115-1.")
    version = version_tuple(data["version"])
    if version_tuple(data["minimum_version"]) > version:
        raise UpgradeError("Invalid release metadata: minimum_version exceeds version.")
    if _validate_tag(data["tag"]) != (channel, version):
        raise UpgradeError("Invalid release metadata: tag must match channel and version.")
    if data["template"] != f"NYCU-SDNFV/Golden-{channel}-Controller":
        raise UpgradeError("Invalid release template: expected the public NYCU-SDNFV Controller channel template.")
    if not re.fullmatch(r"[0-9a-f]{40}", data["source_sha"]):
        raise UpgradeError("Invalid release metadata: source_sha must be 40 lowercase hexadecimal digits.")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UpgradeError(f"Invalid release metadata: duplicate field {key!r}.")
        result[key] = value
    return result


def parse_metadata(raw, *, allow_development=False):
    if len(raw) > MAX_METADATA_BYTES:
        raise UpgradeError("Release metadata exceeds the 16 KiB size limit.")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise UpgradeError(f"Cannot parse release metadata: {exc}") from exc
    return validate_metadata(data, allow_development=allow_development)


def _git(repo, *args, check=True, input=None):
    options = ["--no-replace-objects", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
    # Student commits must honor their normal hooks, identity and signing policy.
    if args[:1] != ("commit",):
        options.extend(["-c", "core.hooksPath=/dev/null"])
    try:
        result = subprocess.run(
            ["git", *options, "-C", str(repo), *args],
            input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=GIT_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpgradeError(f"Cannot run Git: {exc}. Inspect git status before retrying.") from exc
    if check and result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise UpgradeError(f"Git {args[0]} failed: {detail}")
    return result


def _blob(repo, revision, path):
    return _git(repo, "show", f"{revision}:{path}").stdout


def _development_tree(repo):
    # These tracked private inputs are stripped from every student template.
    paths = (".release.json", "tools/student-build/strip.py")
    return all(
        (repo / path).is_file()
        and _git(repo, "cat-file", "-e", f"HEAD:{path}", check=False).returncode == 0
        for path in paths
    )


def load_local_metadata(repo):
    try:
        with (repo / MARKER).open("rb") as stream:
            raw = stream.read(MAX_METADATA_BYTES + 1)
    except FileNotFoundError as exc:
        raise UpgradeError(
            "This repository has no .lab-release.json. Ask your instructor to migrate this "
            "legacy repository; do not create a marker or guess a base tag."
        ) from exc
    except OSError as exc:
        raise UpgradeError(f"Cannot read {MARKER}: {exc}") from exc
    data = parse_metadata(raw, allow_development=True)
    if data == DEVELOPMENT and not _development_tree(repo):
        raise UpgradeError(
            "Development metadata is only valid in the instructor development tree. "
            "For an unpublished local student build use make test-offline explicitly; "
            "it cannot establish published freshness or update from public tags."
        )
    return data


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpgradeError("Release metadata redirected unexpectedly; ask your instructor to check the template URL.")


def latest_metadata(current):
    validate_metadata(current)
    url = (f"https://raw.githubusercontent.com/{current['template']}/main/{MARKER}"
           f"?lab1_check={uuid.uuid4().hex}")
    request = urllib.request.Request(url, headers={
        "Accept": "application/json", "User-Agent": "Lab1-upgrade/1", "Cache-Control": "no-cache",
    })
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=NETWORK_TIMEOUT) as response:
            raw = response.read(MAX_METADATA_BYTES + 1)
        latest = parse_metadata(raw)
        if (latest["channel"], latest["template"]) != (current["channel"], current["template"]):
            raise UpgradeError("Latest metadata changed channel or template.")
        if version_tuple(latest["version"]) < version_tuple(current["version"]):
            raise UpgradeError("Latest metadata is older than this checkout; release provenance needs instructor review.")
        if latest["version"] == current["version"] and latest != current:
            raise UpgradeError("An immutable release's metadata changed; ask your instructor to investigate.")
        return latest
    except (OSError, urllib.error.URLError, http.client.HTTPException, UpgradeError, ValueError) as exc:
        raise UpgradeError(
            f"Freshness could not be established: {exc} "
            "Check your connection and retry make check-update; contact your instructor if it persists. "
            "make test-offline is explicit local verification only, not proof of release freshness."
        ) from exc


def check_freshness(repo):
    current = load_local_metadata(repo)
    if current == DEVELOPMENT:
        print("Instructor development tree: release freshness does not apply; no network request made.")
        return True
    latest = latest_metadata(current)
    if version_tuple(current["version"]) < version_tuple(latest["minimum_version"]):
        raise UpgradeError(
            f"Update required: Lab 1 {current['version']} is too old; "
            f"{latest['minimum_version']} or newer is required (latest {latest['version']}). "
            + UPDATE_FLOW
        )
    if version_tuple(current["version"]) < version_tuple(latest["version"]):
        print(f"Lab 1 {current['version']} is supported; optional update {latest['version']} is available via make update.")
    else:
        print(f"Lab 1 {current['version']} is current ({current['channel']}).")
    return True


def _clean_repo(repo):
    top = _git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    if Path(top).resolve() != repo.resolve():
        raise UpgradeError("Updates must run at the root of the student repository.")
    for state in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply", "sequencer", "BISECT_LOG"):
        path = _git(repo, "rev-parse", "--git-path", state).stdout.decode().strip()
        if (repo / path).exists():
            raise UpgradeError("Finish or abort the active merge/rebase/cherry-pick/bisect before make update.")
    flags = _git(repo, "ls-files", "-v", "-z").stdout.split(b"\0")
    if any(entry and (entry[:1].islower() or entry[:1] == b"S") for entry in flags):
        raise UpgradeError(
            "Tracked files have assume-unchanged/skip-worktree flags. Disable sparse checkout "
            "and clear those flags, then inspect git status before updating."
        )
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout:
        raise UpgradeError("Working tree is not clean. Commit or stash all changes, including untracked files, before make update.")
    branch = _git(repo, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    if branch.returncode:
        raise UpgradeError("Check out your student branch before make update; detached HEAD is not supported.")
    return branch.stdout.decode().strip()


def _validate_source(template_url, metadata):
    expected = f"https://github.com/{metadata['template']}.git"
    if template_url == expected:
        return False
    if isinstance(template_url, str) and Path(template_url).is_absolute() and Path(template_url).is_dir():
        return True
    raise UpgradeError(f"Refusing unexpected template source; expected {expected}.")


def _release_at(repo, revision, tag):
    raw = _blob(repo, revision, MARKER)
    metadata = parse_metadata(raw)
    if metadata["tag"] != tag:
        raise UpgradeError(f"Release tag {tag} does not match its metadata.")
    manifest = _blob(repo, revision, MANIFEST)
    expected = hashlib.sha256(raw).hexdigest().encode() + b"  " + MARKER.encode()
    entries = [line for line in manifest.splitlines() if line.endswith(b"  " + MARKER.encode())]
    if entries != [expected]:
        raise UpgradeError(f"Release {tag} does not canonically protect {MARKER} in its integrity manifest.")
    return metadata, raw, manifest


def _github_tree(repo, revision):
    entries = _git(repo, "ls-tree", "-r", "-z", revision, "--", ".github").stdout
    result = {}
    for entry in entries.split(b"\0"):
        if entry:
            identity, path = entry.split(b"\t", 1)
            result[path.decode("utf-8", errors="surrogateescape")] = identity
    return result


def apply_update(repo: Path, template_url: str, old_tag: str, new_tag: str, branch: str) -> bool:
    """Stage the three-way update, preserving answers and Classroom-injected files."""
    repo = Path(repo).resolve()
    old_channel, old_version = _validate_tag(old_tag)
    new_channel, new_version = _validate_tag(new_tag)
    if new_channel != old_channel or new_version < old_version:
        raise UpgradeError("Refusing a cross-channel update or release downgrade.")
    if branch != f"instructor/update-{new_tag}":
        raise UpgradeError(f"Update branch must be instructor/update-{new_tag}.")
    _git(repo, "check-ref-format", "--branch", branch)
    original_branch = _clean_repo(repo)
    current = load_local_metadata(repo)
    if current == DEVELOPMENT:
        raise UpgradeError("The instructor development tree cannot be upgraded as a student release.")
    if current["tag"] not in (old_tag, new_tag):
        raise UpgradeError("Student release metadata does not match the expected old or new tag.")
    local_source = _validate_source(template_url, current)
    resolved_source = _git(repo, "ls-remote", "--get-url", template_url).stdout.decode().strip()
    if resolved_source != template_url:
        raise UpgradeError("Git URL rewriting would change the public template source; remove that rewrite before updating.")
    namespace = f"refs/classroom50/update-{uuid.uuid4().hex}"
    old_ref, new_ref = f"{namespace}/old", f"{namespace}/new"
    try:
        specs = [f"refs/tags/{old_tag}:{old_ref}"]
        if new_tag != old_tag:
            specs.append(f"refs/tags/{new_tag}:{new_ref}")
        _git(repo, "-c", "protocol.allow=never", "-c",
             f"protocol.{'file' if local_source else 'https'}.allow=always",
             "-c", "http.followRedirects=false",
             "fetch", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules",
             "--", template_url, *specs)
        if new_tag == old_tag:
            new_ref = old_ref
        for ref in (old_ref, new_ref):
            _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
        for tag, ref in ((old_tag, old_ref), (new_tag, new_ref)):
            local_tag = _git(repo, "show-ref", "--verify", "--hash", f"refs/tags/{tag}", check=False)
            if local_tag.returncode == 0 and local_tag.stdout != _git(repo, "rev-parse", ref).stdout:
                raise UpgradeError(f"Immutable tag {tag} differs from your existing local tag; ask your instructor to investigate.")
        old, old_raw, old_manifest = _release_at(repo, old_ref, old_tag)
        new, new_raw, new_manifest = _release_at(repo, new_ref, new_tag)
        if (old["channel"], old["template"]) != (new["channel"], new["template"]):
            raise UpgradeError("Immutable tags belong to different channels or templates.")
        _validate_source(template_url, old)
        expected, expected_raw = (new, new_raw) if current["tag"] == new_tag else (old, old_raw)
        if current != expected or _blob(repo, "HEAD", MARKER) != expected_raw:
            raise UpgradeError("Committed release metadata does not match the immutable template tag; ask your instructor to migrate it.")
        valid_manifests = (new_manifest,) if current["tag"] == new_tag else (old_manifest, new_manifest)
        if _blob(repo, "HEAD", MANIFEST) not in valid_manifests:
            raise UpgradeError(
                "Committed integrity manifest does not match the immutable old or target template tag; "
                "ask your instructor before updating."
            )
        if current["tag"] == new_tag:
            return False
        if _git(repo, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0:
            raise UpgradeError(f"Branch {branch} already exists; inspect and merge or rename it before retrying. It was not changed.")
        old_github = _github_tree(repo, old_ref)
        new_github = _github_tree(repo, new_ref)
        head_github = _github_tree(repo, "HEAD")
        # Classroom may have synced exact target .github objects before the root marker.
        already_synced = [
            path for path in old_github.keys() | new_github.keys()
            if old_github.get(path) != new_github.get(path)
            and head_github.get(path) == new_github.get(path)
        ]
        patch = _git(
            repo, "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv",
            "--no-renames", old_ref, new_ref, "--", ".",
            *(f":(top,literal,exclude){path}" for path in (*PRESERVED, *sorted(already_synced))),
        ).stdout
        if not patch:
            return False
        _git(repo, "checkout", "-b", branch)
        result = _git(repo, "apply", "--3way", "--index", "--whitespace=nowarn", "-", input=patch, check=False)
        if result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise UpgradeConflict(
                f"Update needs attention on {branch}; HEAD still points to your original commit. "
                f"Git reported: {detail}\n"
                "Run git status, resolve conflicts without discarding your exercise changes, "
                "then git add the resolved files and git commit. Do not rerun make update over this branch. "
                f"After reviewing, git switch {shlex.quote(original_branch)} and git merge --ff-only {branch}; "
                "rerun make test and push your Classroom default branch to resubmit. "
                "To abandon this pending update, preserve any resolutions first, then run "
                f"git restore --source=HEAD --staged --worktree -- . and git switch {shlex.quote(original_branch)}. "
                "No commit or push was made."
            )
        if _blob(repo, "", MARKER) != new_raw or _blob(repo, "", MANIFEST) != new_manifest:
            raise UpgradeConflict(
                f"Update on {branch} did not produce the exact release metadata/manifest. "
                "HEAD is unchanged; inspect git status and contact your instructor before committing."
            )
        return True
    finally:
        for ref in {old_ref, new_ref}:
            _git(repo, "update-ref", "-d", ref)


def update(repo):
    current = load_local_metadata(repo)
    if current == DEVELOPMENT:
        print("Instructor development tree: student updates do not apply; no network request made.")
        return
    original_branch = _clean_repo(repo)
    latest = latest_metadata(current)
    if latest["tag"] == current["tag"]:
        print(f"Lab 1 {current['version']} is already current; no branch or commit created.")
        return
    _git(repo, "var", "GIT_AUTHOR_IDENT")
    _git(repo, "var", "GIT_COMMITTER_IDENT")
    branch = f"instructor/update-{latest['tag']}"
    if not apply_update(repo, f"https://github.com/{current['template']}.git",
                        current["tag"], latest["tag"], branch):
        print("Release already applied; no commit created.")
        return
    if parse_metadata(_blob(repo, "", MARKER)) != latest:
        raise UpgradeError(
            f"Latest metadata and immutable tag disagree. Changes are staged on {branch}, "
            "but not committed; contact your instructor and inspect git status."
        )
    try:
        _git(repo, "commit", "-m", f"Update Lab 1 to {latest['tag']}\n\n{COAUTHOR}")
    except UpgradeError as exc:
        raise UpgradeError(
            f"{exc}\nChanges remain staged on {branch}; inspect git status, fix your Git "
            "identity, hooks, or signing configuration, and commit before merging the update branch. "
            "No verification or signing bypass was attempted."
        ) from exc
    print(
        f"Updated safely on {branch}; your exercise changes were merged, not replaced. No push was made.\n"
        f"Review git show, then git switch {shlex.quote(original_branch)} && git merge --ff-only {branch}. "
        f"Run make test, then git push origin {shlex.quote(original_branch)} to resubmit. "
        "If your original branch is not the Classroom default branch, merge it into that branch "
        "and push the default branch too; pushing only the update branch is not a submission. "
        "For offline local verification use make test-offline, then reconnect before pushing."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "update"))
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[2]
    try:
        if args.command == "check":
            check_freshness(repo)
        else:
            update(repo)
    except UpgradeError as exc:
        print(f"Lab 1: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
