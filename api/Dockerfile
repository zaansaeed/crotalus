# The crotalus API image. Multi-stage: the first stage compiles the program, the
# second holds only the compiled binary. Only the last stage becomes the image.
#
# Build:  docker compose build api   (or `docker compose up --build`)

# --- Stage 1: build --------------------------------------------------------------
# The Go toolchain. Matches the go line in go.mod.
FROM golang:1.27 AS build

WORKDIR /src

# Dependencies first, on their own: this layer is only redone when go.mod or go.sum
# change, not on every code change.
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
# CGO_ENABLED=0: a fully static binary that needs no C libraries, so it runs on the
# empty base image below.
RUN CGO_ENABLED=0 go build -o /crotalus-api .

# --- Stage 2: run ----------------------------------------------------------------
# Distroless: no shell, no package manager, nothing but what a static binary needs
# (CA certificates, timezone data). :nonroot runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /crotalus-api /crotalus-api

EXPOSE 8080
ENTRYPOINT ["/crotalus-api"]
