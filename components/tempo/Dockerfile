# syntax=docker/dockerfile:1
# DLA-4792-1: retain Tempo's exact upstream executable/runtime and update only
# Debian's architecture-independent timezone data, with its original inventory.
ARG TEMPO_BASE=docker.io/grafana/tempo:3.1.1@sha256:64e2fbd56d9c2b3412a4b430a58ea59e91a670b1e75f920a0c702213ad145044
FROM docker.io/library/golang:1.26.10-alpine@sha256:d1f3216ef30257c850cc136ba42a359ccd9d3e75f19b2c276e520c0b4ef327ce AS healthcheck
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /src
COPY healthcheck.go /src/healthcheck.go
RUN GOWORK=off go build -trimpath -buildvcs=false -o /out/tempo-healthcheck /src/healthcheck.go

FROM docker.io/library/debian:bookworm-slim@sha256:ec31d744f83f4a73447ba045aaab9409997efe5cc706eca4890c1be36cc1606a AS timezone
ADD --checksum=sha256:c6bdac9aa03e89a112c8d900cb60321889cfec535e0397b74383bd10c8b3cb44 https://deb.debian.org/debian-security/pool/updates/main/t/tzdata/tzdata_2026c-0+deb12u1_all.deb /tmp/tzdata.deb
# Extract the complete genuine package payload, not selected zones. No timezone
# reconfiguration is needed: preserve the upstream runtime's UTC configuration.
RUN test "$(dpkg-deb --field /tmp/tzdata.deb Version)" = '2026c-0+deb12u1' && \
    dpkg-deb --extract /tmp/tzdata.deb /payload && \
    dpkg-deb --control /tmp/tzdata.deb /package-control

FROM ${TEMPO_BASE}
LABEL org.opencontainers.image.source="https://github.com/h1wtest/platform-infra" \
      org.opencontainers.image.version="3.1.1-h1w1" \
      io.h1wtest.security.tzdata="2026c-0+deb12u1"
COPY --from=timezone /payload/ /
COPY --from=timezone /package-control/control /var/lib/dpkg/status.d/tzdata
COPY --from=timezone /package-control/md5sums /var/lib/dpkg/status.d/tzdata.md5sums
COPY --from=healthcheck --chmod=0555 /out/tempo-healthcheck /usr/local/bin/tempo-healthcheck
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/tempo-healthcheck"]
