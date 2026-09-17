# Render's native Python runtime does not include cmake, so liboqs-python's
# automatic liboqs build (triggered on first `import oqs`, at runtime) fails
# with "cmake: not found" -- see CHANGES.md for the full incident writeup.
# Render's own docs say the fix for a missing build tool is to deploy with
# Docker instead of the native runtime, so this Dockerfile installs the real
# build toolchain liboqs needs (cmake, a C compiler, git) and then forces the
# liboqs build to happen once, HERE, at image-build time -- not on every
# container start on Render's servers.

FROM python:3.11-slim

# Build tools required by liboqs (C library behind liboqs-python / ML-KEM).
# cmake + a C compiler + git are what the "cmake: not found" runtime error
# was missing; libssl-dev is liboqs's optional OpenSSL backend.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Force liboqs-python's one-time build/install of the liboqs C library to
# happen now, while cmake/git/gcc are guaranteed to be present, instead of
# lazily on first request in the running container. This bakes the built
# liboqs shared library into the image layer, so container startup on Render
# is just "load the already-built library" -- no network clone, no compile.
# Exercises the exact three parameter sets the three profiles use (see
# app/crypto/profiles.py), so a missing/misbuilt variant fails the Docker
# build loudly instead of failing a real doctor/patient session later.
RUN python -c "\
import oqs; \
[oqs.KeyEncapsulation(alg).generate_keypair() for alg in ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024')]; \
print('liboqs build OK for ML-KEM-512/768/1024')"

COPY . .

# Render sets $PORT at runtime; sh -c lets that env var expand into the
# command (a plain exec-form CMD would pass the literal string "$PORT").
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port $PORT"]
