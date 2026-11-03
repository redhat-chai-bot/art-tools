"""
Pipeline to sign RHCOS container images using Sigstore/cosign.

This pipeline reads RHCOS data (already extracted by the Jenkinsfile)
and signs any container images published to Quay.
"""

import asyncio
import base64
import json
import os
import tempfile
from pathlib import Path

import click
from artcommonlib import exectools

from pyartcd.cli import cli, pass_runtime
from pyartcd.runtime import Runtime
from pyartcd.signatory import SigstoreSignatory  # noqa: F401  # retained for the (skipped) real signing path

# INVESTIGATION BRANCH: investigate/rhcos-sign-cred-probe
# requests is already a dependency of pyartcd; imported lazily-safe here for the probe.
try:
    import requests
except Exception:  # pragma: no cover - defensive, requests is a declared dependency
    requests = None


class SignRhcosContainersPipeline:
    """
    Pipeline to sign RHCOS container images with Sigstore.
    """

    def __init__(
        self,
        runtime: Runtime,
        rhcos_file: str,
        arch: str,
        signing_env: str | None = None,
    ):
        """
        Initialize the pipeline.

        Arg(s):
            runtime (Runtime): The runtime object
            rhcos_file (str): Path to the rhcos json file
            arch (str): Architecture (e.g., x86_64, aarch64)
            signing_env (str | None): Signing environment (stage or prod)
        """
        self.runtime = runtime
        self.rhcos_file = Path(rhcos_file)
        self.arch = arch
        self.signing_env = signing_env or "stage"
        self.logger = self.runtime.logger

        if not self.rhcos_file.exists():
            raise FileNotFoundError(f"RHCOS file not found: {self.rhcos_file}")

        if not self.runtime.dry_run:
            required_vars = ["KMS_CRED_FILE", "KMS_KEY_ID"]
            missing_vars = [var for var in required_vars if not os.environ.get(var)]
            if missing_vars:
                raise ValueError(
                    f"Missing required environment variables for signing: {missing_vars}. "
                    "Please set KMS_CRED_FILE and KMS_KEY_ID."
                )

    def _get_rhcos_container_digests(self) -> dict[str, str]:
        """
        Extract all RHCOS container image digests from the rhcos JSON file.

        Returns container images that are published to Quay (have digest-ref field
        pointing to quay.io).

        Return Value(s):
            dict[str, str]: Dictionary mapping image type to digest-ref pullspec
        """
        self.logger.info(f"Reading RHCOS data from {self.rhcos_file}")
        with open(self.rhcos_file, "r") as f:
            stream_data = json.load(f)

        images = stream_data.get("architectures", {}).get(self.arch, {}).get("images", {})

        # Filter for container images (have digest-ref pointing to quay.io)
        container_images = {}
        for image_type, image_data in images.items():
            if not isinstance(image_data, dict):
                continue

            digest_ref = image_data.get("digest-ref")
            if digest_ref and "quay.io" in digest_ref:
                container_images[image_type] = digest_ref
                self.logger.info(f"Found {image_type} container: {digest_ref}")

        return container_images

    async def _sign_containers(self, container_images: dict[str, str]) -> bool:
        """
        Sign RHCOS container images using SigstoreSignatory.

        Arg(s):
            container_images (dict[str, str]): Dictionary of image type to digest-ref
        Return Value(s):
            bool: True if successful, False otherwise
        """
        if not container_images:
            self.logger.warning(f"No RHCOS container images found for {self.arch}")
            return True

        # ============================================================================
        # INVESTIGATION BRANCH: investigate/rhcos-sign-cred-probe — DO NOT MERGE
        # ----------------------------------------------------------------------------
        # This branch does NOT sign anything. Instead it runs a non-destructive
        # credential probe to discover which of the bound quay credentials actually
        # has PUSH capability on the target RHCOS boot-image repo (the signing path
        # currently fails with UNAUTHORIZED when cosign writes the signature). After
        # probing, we return True WITHOUT invoking the signatory, so no registry is
        # mutated and the normal 413/UNAUTHORIZED signing path is never hit.
        # ============================================================================
        self.logger.info(
            "=== INVESTIGATION BRANCH (investigate/rhcos-sign-cred-probe) — credential probe, NOT signing ==="
        )
        target_pullspecs = sorted(set(container_images.values()))
        try:
            await self._probe_signing_credentials(target_pullspecs)
        except Exception as exc:  # pragma: no cover - probe must never break the pipeline
            # Defensive: the probe is best-effort investigation only and must never raise.
            self.logger.warning("Credential probe raised unexpectedly (ignored): %s", exc)
        self.logger.info("=== INVESTIGATION BRANCH — skipping actual signing (signatory NOT invoked) ===")
        return True

    async def _probe_signing_credentials(self, target_pullspecs: list[str]) -> None:
        """
        INVESTIGATION-ONLY, non-destructive probe.

        Discover which bound quay credential (if any) grants PUSH on the target RHCOS
        boot-image repo(s). This never mutates any registry: it only requests quay
        bearer tokens with a push scope (which does not push anything) and performs a
        read-only ``skopeo inspect``.

        For every candidate auth source it logs whether the env var is set and whether
        the file exists; for every quay auth entry it logs the registry key and the
        decoded USERNAME ONLY (passwords/tokens are always masked — this satisfies the
        No-Sensitive-Data-In-Logs rule). For each target repo it reports, per
        credential, whether quay grants push (``PUSH=YES/NO``) and whether a read
        probe succeeds (``READ=OK/FAIL``), then prints a summary of push-capable creds.

        Arg(s):
            target_pullspecs (list[str]): Full target pullspecs (host/repo@sha256:... or host/repo:tag)
        """
        log = self.logger

        # ---- (a) enumerate candidate auth sources from the environment -------------
        auth_files: dict[str, str] = {}  # label -> resolved file path that exists
        for env_var in ("QUAY_AUTH_FILE", "RHCOS_QUAY_AUTH_FILE", "KONFLUX_OPERATOR_INDEX_AUTH_FILE"):
            value = os.environ.get(env_var)
            if not value:
                log.info("auth source %s: NOT SET", env_var)
                continue
            exists = os.path.isfile(value)
            log.info("auth source %s: set, file_exists=%s", env_var, exists)
            if exists:
                auth_files[env_var] = value

        # DOCKER_CONFIG points at a directory; the auth file is <dir>/config.json.
        docker_config_dir = os.environ.get("DOCKER_CONFIG")
        if not docker_config_dir:
            log.info("auth source DOCKER_CONFIG: NOT SET")
        else:
            docker_config_json = os.path.join(docker_config_dir, "config.json")
            exists = os.path.isfile(docker_config_json)
            log.info("auth source DOCKER_CONFIG: set (%s), config.json_exists=%s", docker_config_dir, exists)
            if exists:
                auth_files["DOCKER_CONFIG/config.json"] = docker_config_json

        if not auth_files:
            log.warning("No readable candidate auth files found — nothing to probe.")
            return

        # ---- parse each auth file into {registry_key: {"username":..., "auth":...}} -
        # Only usernames are retained for logging; the raw auth value is kept in memory
        # solely to drive the probes and is NEVER logged.
        parsed: dict[str, dict[str, dict]] = {}  # label -> {registry_key: entry}
        for label, path in auth_files.items():
            entries = self._parse_auth_file(path)
            parsed[label] = entries
            if not entries:
                log.info("auth file %s (%s): no 'auths' entries parsed", label, path)
                continue
            for registry_key, entry in entries.items():
                log.info(
                    "auth file %s: registry-key=%s username=%s (password masked)",
                    label,
                    registry_key,
                    entry.get("username") or "<none>",
                )

        # ---- (c) per target repo, probe each quay credential -----------------------
        # summary: repo-path -> list of "<label>:<registry-key> (user <username>)" with PUSH=YES
        push_grants: dict[str, list[str]] = {}
        for pullspec in target_pullspecs:
            host, repo_path = self._split_pullspec(pullspec)
            if host != "quay.io":
                log.info("target %s: host=%s is not quay.io — skipping quay token probe", pullspec, host)
                continue
            push_grants.setdefault(repo_path, [])
            log.info("--- probing target repo quay.io/%s (from %s) ---", repo_path, pullspec)

            for label, entries in parsed.items():
                for registry_key, entry in entries.items():
                    # Only quay.io hosts are relevant for this quay repo.
                    if self._registry_key_host(registry_key) != "quay.io":
                        continue
                    cred_id = f"{label}:{registry_key} (user {entry.get('username') or '<none>'})"

                    # WRITE-capability probe: ask quay for a push-scoped bearer token.
                    push_yes = self._probe_quay_push_scope(repo_path, entry, cred_id)
                    if push_yes:
                        push_grants[repo_path].append(cred_id)

                    # READ probe (sanity): skopeo inspect using just this entry.
                    await self._probe_skopeo_read(pullspec, entry, cred_id)

        # ---- (d) summary -----------------------------------------------------------
        log.info("=== INVESTIGATION SUMMARY — push capability per target repo ===")
        for repo_path, grants in push_grants.items():
            if grants:
                log.info("Repo quay.io/%s: PUSH granted by: %s", repo_path, "; ".join(grants))
            else:
                log.info(
                    "No bound credential grants push on quay.io/%s — a push-capable credential "
                    "(e.g. RHCOS_QUAY_AUTH_FILE robot) must be bound.",
                    repo_path,
                )

    @staticmethod
    def _parse_auth_file(path: str) -> dict[str, dict]:
        """
        Parse a docker/podman auth JSON file into {registry_key: {"username":.., "auth":..}}.

        The password/token is intentionally kept out of the returned 'username' and is
        never logged by the caller. Returns {} on any parse failure.
        """
        result: dict[str, dict] = {}
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception:
            return result
        auths = data.get("auths", {}) if isinstance(data, dict) else {}
        if not isinstance(auths, dict):
            return result
        for registry_key, value in auths.items():
            if not isinstance(value, dict):
                continue
            username = None
            password = None
            raw_auth = value.get("auth")
            if raw_auth:
                try:
                    decoded = base64.b64decode(raw_auth).decode("utf-8", "replace")
                    username, _, password = decoded.partition(":")
                except Exception:
                    username = None
                    password = None
            # Fall back to explicit username/password fields if present.
            if username is None:
                username = value.get("username")
            if password is None:
                password = value.get("password")
            result[registry_key] = {"username": username, "password": password}
        return result

    @staticmethod
    def _split_pullspec(pullspec: str) -> tuple[str, str]:
        """
        Split a pullspec into (registry_host, repo_path).

        e.g. ``quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:abc`` ->
             ("quay.io", "openshift-release-dev/ocp-v4.0-art-dev")
        and  ``quay.io/foo/bar:tag`` -> ("quay.io", "foo/bar").
        """
        ref = pullspec
        # strip digest first, then tag (tag only applies to the last path segment)
        if "@" in ref:
            ref = ref.split("@", 1)[0]
        host, _, remainder = ref.partition("/")
        # A trailing ":tag" lives in the last path segment, not in the host.
        if ":" in remainder:
            remainder = remainder.rsplit(":", 1)[0]
        return host, remainder

    @staticmethod
    def _registry_key_host(registry_key: str) -> str:
        """Return the host portion of an auth registry key (e.g. 'quay.io/foo' -> 'quay.io')."""
        return registry_key.split("/", 1)[0]

    def _probe_quay_push_scope(self, repo_path: str, entry: dict, cred_id: str) -> bool:
        """
        Non-destructive WRITE-capability probe against quay's token endpoint.

        Requests a bearer token scoped to ``repository:<repo_path>:pull,push`` using the
        credential's HTTP Basic auth, decodes the (unverified) JWT payload, and inspects
        its ``access`` claim to see which actions quay actually granted. Requesting a
        push scope does NOT push anything.

        Logs ``PUSH=YES`` / ``PUSH=NO`` and returns True iff push was granted.
        Never raises.
        """
        log = self.logger
        if requests is None:
            log.warning("cred %s: requests unavailable — cannot run quay push-scope probe", cred_id)
            return False
        username = entry.get("username")
        password = entry.get("password")
        if not username or not password:
            log.info("cred %s: no usable username/password — PUSH=UNKNOWN (skipped)", cred_id)
            return False
        try:
            resp = requests.get(
                "https://quay.io/v2/auth",
                params={"service": "quay.io", "scope": f"repository:{repo_path}:pull,push"},
                auth=(username, password),
                timeout=30,
            )
        except Exception as exc:
            log.info("cred %s: quay token request failed (%s) — PUSH=NO", cred_id, exc)
            return False
        if resp.status_code != 200:
            log.info(
                "cred %s: quay token endpoint returned HTTP %s — PUSH=NO (%s)",
                cred_id,
                resp.status_code,
                resp.status_code,
            )
            return False
        try:
            token = resp.json().get("token", "")
        except Exception as exc:
            log.info("cred %s: could not parse quay token response (%s) — PUSH=NO", cred_id, exc)
            return False
        actions = self._decode_jwt_actions(token, repo_path)
        push_yes = "push" in actions
        log.info(
            "cred %s: quay granted actions=%s PUSH=%s",
            cred_id,
            sorted(actions),
            "YES" if push_yes else "NO",
        )
        return push_yes

    @staticmethod
    def _decode_jwt_actions(token: str, repo_path: str) -> set:
        """
        Base64url-decode the (unverified) JWT payload and return the set of actions
        granted for ``repo_path`` across its ``access`` claim. Returns an empty set on
        any failure. No signature verification is performed — this is a read of the
        granted-scope claim only.
        """
        actions: set = set()
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return actions
            payload_b64 = parts[1]
            padding = "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8", "replace"))
        except Exception:
            return actions
        for access in payload.get("access", []) or []:
            if not isinstance(access, dict):
                continue
            if access.get("type") == "repository" and access.get("name") == repo_path:
                for action in access.get("actions", []) or []:
                    actions.add(action)
        return actions

    async def _probe_skopeo_read(self, pullspec: str, entry: dict, cred_id: str) -> None:
        """
        Read-only sanity probe: write this single credential to a temp auth file and run
        ``skopeo inspect --raw --authfile <tmp> docker://<pullspec>``. Logs READ=OK/FAIL.
        Never raises. The temp auth file is removed afterward.
        """
        log = self.logger
        username = entry.get("username")
        password = entry.get("password")
        host, _ = self._split_pullspec(pullspec)
        tmp_path = None
        try:
            if not entry.get("username") and not entry.get("password"):
                log.info("cred %s: no credentials for skopeo read probe — READ=SKIPPED", cred_id)
                return
            # Build a minimal single-entry auth file for skopeo.
            raw_auth = base64.b64encode(f"{username or ''}:{password or ''}".encode("utf-8")).decode("ascii")
            auth_doc = {"auths": {host: {"auth": raw_auth}}}
            fd, tmp_path = tempfile.mkstemp(prefix="cred-probe-", suffix=".json")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(auth_doc, f)
                os.chmod(tmp_path, 0o600)
            except Exception:
                pass
            cmd = ["skopeo", "inspect", "--raw", "--authfile", tmp_path, f"docker://{pullspec}"]
            try:
                rc, _out, err = await exectools.cmd_gather_async(cmd, check=False)
            except Exception as exc:
                log.info("cred %s: skopeo read probe errored (%s) — READ=FAIL", cred_id, exc)
                return
            if rc == 0:
                log.info("cred %s: READ=OK", cred_id)
            else:
                # Only log a short, non-sensitive tail of stderr.
                snippet = (err or "").strip().splitlines()[-1:] or [""]
                log.info("cred %s: READ=FAIL (rc=%s) %s", cred_id, rc, snippet[0][:200])
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    async def async_run(self):
        """Run the pipeline asynchronously.

        Use this method when calling from an already-running async event loop
        (e.g. from rhcos_sync). The sync ``run()`` method wraps this with
        ``asyncio.run()`` for use from synchronous CLI entry points.
        """
        self.logger.info(f"Signing RHCOS containers from {self.rhcos_file} ({self.arch})")
        self.logger.info(f"Signing environment: {self.signing_env}")
        self.logger.info(f"Dry run: {self.runtime.dry_run}")

        self.logger.info("Extracting RHCOS container digests from stream data...")
        container_images = self._get_rhcos_container_digests()

        if not container_images:
            self.logger.warning(
                f"No RHCOS container images found for {self.arch} in stream file. "
                "This is expected for older releases or architectures without container images."
            )
            return

        success = await self._sign_containers(container_images)

        if not success:
            raise RuntimeError("Failed to sign one or more RHCOS container images")

        self.logger.info("RHCOS container signing complete")

    def run(self):
        """Run the pipeline synchronously (CLI entry point).

        Wraps ``async_run()`` with ``asyncio.run()`` for use from the
        synchronous ``sign-rhcos-containers`` CLI command.
        """
        asyncio.run(self.async_run())


@cli.command("sign-rhcos-containers", help="Sign RHCOS container images with Sigstore/cosign")
@click.option("--rhcos-file", required=True, help="Path to rhcos JSON file")
@click.option("--arch", required=True, help="Architecture (e.g., x86_64, aarch64, s390x, ppc64le)")
@click.option(
    "--signing-env",
    type=click.Choice(["stage", "prod"]),
    default="stage",
    help="Signing environment (determines which KMS key to use)",
)
@pass_runtime
def sign_rhcos_containers(
    runtime: Runtime,
    rhcos_file: str,
    arch: str,
    signing_env: str,
):
    """
    Sign RHCOS container images for a release.

    This command reads RHCOS stream data from a JSON file and signs all container
    images published to Quay. It handles kubevirt containers and any other RHCOS
    images with digest-ref fields.

    The rhcos.json file is extracted by the Jenkins job using:
        cat coreos-bootimages.yaml | yq -r .data.stream > rhcos.json

    For OCP 5.x and later, coreos-bootimages.yaml also contains a .data.streams map
    with one entry per RHCOS variant (e.g. rhel-10).  The Jenkins job extracts each
    entry to a separate file (rhcos-<arch>-<stream>.json) and calls this command once
    per file so that images in every variant are signed.

    Required environment variables:
    - KMS_CRED_FILE: Path to AWS credentials file for KMS signing
    - KMS_KEY_ID: AWS KMS key ID(s) for signing (comma-separated for multiple keys)
    - REKOR_URL: Rekor transparency log URL (optional, defaults to no tlog upload)

    Example:
        artcd -v --dry-run sign-rhcos-containers \\
            --rhcos-file /path/to/rhcos.json \\
            --arch x86_64 \\
            --signing-env prod
    """
    pipeline = SignRhcosContainersPipeline(
        runtime=runtime,
        rhcos_file=rhcos_file,
        arch=arch,
        signing_env=signing_env,
    )
    pipeline.run()
