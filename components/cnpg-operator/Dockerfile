# syntax=docker/dockerfile:1
# Rebuild both shipped manager architectures: the operator injects these binaries
# into PostgreSQL pods. Retain the exact upstream runtime, entrypoint and licenses.
ARG CNPG_OPERATOR_BASE=ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1@sha256:923c267ec29636db3bee20f993d0ec4973fa22998e1adad37da79e4d32b5bc07
FROM docker.io/library/golang:1.27.3-alpine@sha256:bff16a94c0b4b6d9642581e2a3aa81beb3edb940b2f5a3aac1d22c6a68cb7747 AS backend
ENV GOTOOLCHAIN=local GOSUMDB=sum.golang.org CGO_ENABLED=0 GOOS=linux SOURCE_DATE_EPOCH=1790170481
ADD https://github.com/cloudnative-pg/cloudnative-pg.git#2a35abb4628f209d149825ef3c38011e0701ff2f /src/cloudnative-pg
WORKDIR /src/cloudnative-pg
COPY go.sum /tmp/security.sum
# Bind the genuine patched module and its required x/text upgrade to published
# checksum-database records. Keep the full upstream dependency graph and features.
RUN cat /tmp/security.sum >> go.sum && \
    go mod edit -require=golang.org/x/net@v0.60.0 && \
    go mod tidy && \
    go mod download && \
    go mod verify && \
    GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags='-X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildVersion=1.30.1-h1w1 -X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildCommit=2a35abb4628f209d149825ef3c38011e0701ff2f -X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildDate=2026-09-23T13:34:41Z' \
      -o /out/manager_amd64 ./cmd/manager && \
    GOARCH=arm64 go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags='-X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildVersion=1.30.1-h1w1 -X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildCommit=2a35abb4628f209d149825ef3c38011e0701ff2f -X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildDate=2026-09-23T13:34:41Z' \
      -o /out/manager_arm64 ./cmd/manager
COPY healthcheck.go /src/healthcheck.go
RUN GOWORK=off GOARCH=amd64 go build -trimpath -buildvcs=false -o /out/cnpg-healthcheck /src/healthcheck.go

FROM scratch AS source-output
COPY --from=backend /src/cloudnative-pg /cloudnative-pg
COPY --from=backend /go/pkg/mod /dependencies
COPY Dockerfile /build/Dockerfile
COPY go.sum /build/go.sum
COPY --from=backend /src/healthcheck.go /healthcheck.go

# DSA-6572-1: use Debian's real trust-store installer and original package control
# metadata in the distroless inventory, without copying unrelated builder packages.
FROM docker.io/library/debian:trixie-slim@sha256:4876fdea29cac1a33a3195f1eb1952feb1fca7dd6dd00be3e2f1879cf20d34d2 AS certificates
ADD --checksum=sha256:c10585ac22c7f617a73d394eea29ba71d0356f350ae973b19043d1b017f80f54 https://deb.debian.org/debian-security/pool/updates/main/c/ca-certificates/ca-certificates_20250419+deb13u1_all.deb /tmp/ca-certificates.deb
RUN apt-get update && \
    apt-get install -y --no-install-recommends /tmp/ca-certificates.deb && \
    dpkg-deb --control /tmp/ca-certificates.deb /package-control && \
    test "$(dpkg-query --show --showformat='${Version}' ca-certificates)" = '20250419+deb13u1'

FROM ${CNPG_OPERATOR_BASE}
LABEL org.opencontainers.image.source="https://github.com/h1wtest/platform-infra" \
      org.opencontainers.image.version="1.30.1-h1w1" \
      org.opencontainers.image.revision="2a35abb4628f209d149825ef3c38011e0701ff2f" \
      io.h1wtest.security.go="1.27.3" \
      io.h1wtest.security.x-net="0.60.0"
COPY --from=backend --chown=65532:65532 --chmod=0755 /out/manager_amd64 /operator/manager_amd64
COPY --from=backend --chown=65532:65532 --chmod=0755 /out/manager_arm64 /operator/manager_arm64
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certificates /package-control/control /var/lib/dpkg/status.d/ca-certificates
COPY --from=certificates /package-control/md5sums /var/lib/dpkg/status.d/ca-certificates.md5sums
COPY --from=backend --chmod=0555 /out/cnpg-healthcheck /usr/local/bin/cnpg-healthcheck
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/cnpg-healthcheck"]
