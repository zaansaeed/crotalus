# The crotalus image: Python, crotalus and its dependencies, and the migrations.
# One image for every crotalus process; docker-compose.yml picks which one each
# container runs (`command:`), so there's no default command here.
#
# Build:  docker compose build   (or `docker compose up --build`)

# Small Debian with Python. Matches requires-python in pyproject.toml.
FROM python:3.12-slim

# print() goes straight to `docker compose logs` instead of sitting in a buffer.

#environmetn varaibles
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # See db.py: an installed package can't find migrations/ relative to itself.
    MIGRATIONS_DIR=/app/migrations

# create and move to /app
WORKDIR /app

# Install crotalus (and its dependencies) from the source, like `pip install .`.
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install .

COPY migrations/ migrations/

# Don't run as root: crotalus downloads and parses hostile archives, so if anything
# in that ever went wrong, it shouldn't have the container's full permissions.
USER nobody
