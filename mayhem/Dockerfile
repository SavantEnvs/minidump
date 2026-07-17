# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer + Python 3 + the
# identities + the build-contract ENV. minidump is a PURE-PYTHON package (a Windows minidump
# parser with no native code), so this image installs the Atheris harness's Python deps (atheris +
# the minidump package) into the base's system Python as root, then (as the non-root `mayhem`
# user) compiles the ELF launcher shims and runs the known-answer suite via build.sh / test.sh.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t minidump-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Declared for parity with the build contract; minidump has no native code to sanitize.
ARG SANITIZER_FLAGS

# Atheris (the libFuzzer harness engine — builds a native module against the base's clang/libFuzzer)
# goes into the base's SYSTEM Python. PEP 668 marks that interpreter externally-managed, so
# --break-system-packages. This is the (networked) install step; build.sh deliberately does NOT
# pip-install, so its offline PATCH-tier re-run stays air-gapped.
USER root
RUN pip install --no-cache-dir --break-system-packages atheris==3.1.0

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem as `mayhem`; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Install minidump itself so the harness/oracle can `import minidump` (pure-Python, no deps).
# setuptools does this build IN THE SOURCE TREE, so it leaves `build/` and `minidump.egg-info/`
# behind in /mayhem owned by root (this RUN is the only root-in-/mayhem step). Both are matched by
# the repo's .gitignore, so rlenv's patch grader — and the `git clean -ffdX` conformance check —
# try to delete them as the non-root `mayhem` user, hit EACCES on every file inside, and the clean
# ERRORS OUT before the graded build can even start. Drop the install residue and re-assert
# ownership of the tree in the same layer so nothing root-owned survives into the image. Neither
# path is a build input: build.sh only compiles mayhem/launcher.c, and the installed package lives
# in site-packages, not here.
RUN pip install --no-cache-dir --break-system-packages . \
 && rm -rf /mayhem/build /mayhem/dist /mayhem/minidump.egg-info \
 && find /mayhem -name '__pycache__' -type d -prune -exec rm -rf {} + \
 && chown -R 2000:2000 /mayhem

USER mayhem

# Compile the ELF launcher shims (Mayhem needs an ELF target, not a .py).
RUN bash mayhem/build.sh

# Run minidump's known-answer suite at build time; a failing suite fails the build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
