# syntax=docker/dockerfile:1
# Security rebuild: retain the exact official UI, runtime configuration, user
# and entrypoint. Backend and CA bundle updates retain genuine package metadata.
FROM docker.io/library/golang:1.26.10-alpine@sha256:d1f3216ef30257c850cc136ba42a359ccd9d3e75f19b2c276e520c0b4ef327ce AS backend
ENV GOTOOLCHAIN=local GOSUMDB=sum.golang.org CGO_ENABLED=0 GOOS=linux GOARCH=amd64
ADD https://github.com/grafana/grafana.git#af4a33e3786594ad72f72d97e6744010330c2977 /src/grafana
WORKDIR /src/grafana
COPY go.sum /tmp/kin-openapi.sum
# A workspace replacement covers every workspace module, not only the root go.mod.
# These authenticated public checksum-database values also bind the replacement.
RUN go work edit -replace=github.com/getkin/kin-openapi=github.com/getkin/kin-openapi@v0.149.0 && \
    cat /tmp/kin-openapi.sum >> go.work.sum && \
    go work sync && \
    go mod verify && \
    go build -trimpath -buildvcs=false -tags=oss \
      -ldflags='-X main.version=13.2.4-h1w1 -X main.commit=af4a33e3786594ad72f72d97e6744010330c2977 -X main.buildBranch=h1w-security-rebuild' \
      -o /out/grafana ./pkg/cmd/grafana && \
    printf '%s\n' '13.2.4-h1w1' > /out/grafana-version

# Export alongside a distributed rebuild for AGPL corresponding-source access.
FROM scratch AS source-output
COPY --from=backend /src/grafana /grafana
COPY --from=backend /go/pkg/mod /dependencies

# DSA-6572-1 removes compromised trust anchors. Generate the bundle through the
# real Debian package installer, then retain its unmodified control/md5 metadata
# in distroless's existing status.d format (not the builder's unrelated packages).
FROM docker.io/library/debian:trixie-slim@sha256:4876fdea29cac1a33a3195f1eb1952feb1fca7dd6dd00be3e2f1879cf20d34d2 AS certificates
ADD --checksum=sha256:c10585ac22c7f617a73d394eea29ba71d0356f350ae973b19043d1b017f80f54 https://deb.debian.org/debian-security/pool/updates/main/c/ca-certificates/ca-certificates_20250419+deb13u1_all.deb /tmp/ca-certificates.deb
RUN apt-get update && \
    apt-get install -y --no-install-recommends /tmp/ca-certificates.deb && \
    dpkg-deb --control /tmp/ca-certificates.deb /package-control && \
    test "$(dpkg-query --show --showformat='${Version}' ca-certificates)" = '20250419+deb13u1'

FROM docker.io/grafana/grafana:13.2.4-distroless-slim@sha256:3838fe4d1cb7fef51a91b9a72011a7a68736b6052785594d437ec65d441acd8b
LABEL org.opencontainers.image.source="https://github.com/h1wtest/platform-infra" \
      org.opencontainers.image.version="13.2.4-h1w1" \
      org.opencontainers.image.revision="af4a33e3786594ad72f72d97e6744010330c2977" \
      io.h1wtest.security.go="1.26.10" \
      io.h1wtest.security.kin-openapi="0.149.0"
COPY --from=backend /out/grafana /usr/share/grafana/bin/grafana
COPY --from=backend /out/grafana-version /.grafana-version
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certificates /package-control/control /var/lib/dpkg/status.d/ca-certificates
COPY --from=certificates /package-control/md5sums /var/lib/dpkg/status.d/ca-certificates.md5sums
USER 472
