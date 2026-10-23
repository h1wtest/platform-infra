# syntax=docker/dockerfile:1
# Security rebuild: retain the exact official UI, runtime configuration, user
# and entrypoint. Backend and CA bundle updates retain genuine package metadata.
ARG GRAFANA_BASE=docker.io/grafana/grafana:13.2.4-distroless-slim@sha256:3838fe4d1cb7fef51a91b9a72011a7a68736b6052785594d437ec65d441acd8b
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
COPY healthcheck.go /src/healthcheck.go
RUN GOWORK=off go build -trimpath -buildvcs=false -o /out/grafana-healthcheck /src/healthcheck.go

# Grafana 13 detached these datasources from the server binary. Slim upstream
# images leave this directory empty and otherwise download them at runtime.
# Preserve complete signed official archives; verification remains enabled.
FROM docker.io/library/golang:1.26.10-alpine@sha256:d1f3216ef30257c850cc136ba42a359ccd9d3e75f19b2c276e520c0b4ef327ce AS plugins
ADD --checksum=sha256:117edd789f96f4dc6f2e79bef6be3ea10e9ffec775e81e05c16954bcc10cc3a0 https://grafana.com/api/plugins/prometheus/versions/13.2.4/download?os=linux&arch=amd64 /tmp/prometheus.zip
ADD --checksum=sha256:692135f83a7430e54dd2aeaf89da7c3f7b7561ea7826582294910d7c59842bd1 https://grafana.com/api/plugins/tempo/versions/13.3.0/download?os=linux&arch=amd64 /tmp/tempo.zip
RUN mkdir -p /plugins && \
    unzip -q /tmp/prometheus.zip -d /plugins && \
    unzip -q /tmp/tempo.zip -d /plugins && \
    test -s /plugins/prometheus/MANIFEST.txt && \
    test -s /plugins/tempo/MANIFEST.txt && \
    chmod 0555 /plugins/prometheus/gpx_grafana-prometheus-datasource_linux_amd64 /plugins/tempo/gpx_grafana-tempo-datasource_linux_amd64

# Source-only stages: the signed plugin backends have distinct module graphs
# from the Grafana server. Download each exact graph into its own verified cache.
FROM docker.io/library/golang:1.27.3-alpine@sha256:bff16a94c0b4b6d9642581e2a3aa81beb3edb940b2f5a3aac1d22c6a68cb7747 AS prometheus-source
ENV GOTOOLCHAIN=local GOSUMDB=sum.golang.org CGO_ENABLED=0
ADD https://github.com/grafana/grafana-prometheus-datasource.git#7d5bbc86bd38f95ca5143c8490d1204787cc391b /src/prometheus
WORKDIR /src/prometheus
RUN go mod download && go mod verify
WORKDIR /src/prometheus/pkg/promlib
RUN go mod download && go mod verify

FROM docker.io/library/golang:1.27.3-alpine@sha256:bff16a94c0b4b6d9642581e2a3aa81beb3edb940b2f5a3aac1d22c6a68cb7747 AS tempo-source
ENV GOTOOLCHAIN=local GOSUMDB=sum.golang.org CGO_ENABLED=0
ADD https://github.com/grafana/grafana-tempo-datasource.git#7bbc067f7b950057beebcaeeb910f16e98f2dacb /src/tempo
WORKDIR /src/tempo
RUN go mod download && go mod verify

# Keep frontend dependency sources, exact lockfiles and original build scripts,
# not just the compiled JavaScript. Do not execute third-party lifecycle scripts.
FROM docker.io/library/node:24-alpine@sha256:1200d815de24f8dcca745fbf7651d166034a35adbcad8860a8538ffff44f1420 AS prometheus-frontend-source
ADD --checksum=sha256:31e9770f7dc71119a58509353b27917557aaf0ac9b5ef1a0465ee7d8ec67ae75 https://registry.npmjs.org/npm/-/npm-11.19.0.tgz /tmp/npm.tgz
RUN mkdir -p /opt/npm && tar -xzf /tmp/npm.tgz --strip-components=1 -C /opt/npm
COPY --from=prometheus-source /src/prometheus /src/prometheus
WORKDIR /src/prometheus
RUN node /opt/npm/bin/npm-cli.js ci --ignore-scripts --include=dev --include=optional --no-audit --no-fund

FROM docker.io/library/node:24-alpine@sha256:1200d815de24f8dcca745fbf7651d166034a35adbcad8860a8538ffff44f1420 AS tempo-frontend-source
ADD --checksum=sha256:9f58bff01604cb1b14008fef14dceb14d836a49225e45c6c2e37de3be3e707f0 https://registry.npmjs.org/npm/-/npm-11.19.1.tgz /tmp/npm.tgz
RUN mkdir -p /opt/npm && tar -xzf /tmp/npm.tgz --strip-components=1 -C /opt/npm
COPY --from=tempo-source /src/tempo /src/tempo
WORKDIR /src/tempo
RUN node /opt/npm/bin/npm-cli.js ci --ignore-scripts --include=dev --include=optional --no-audit --no-fund

# Export alongside a distributed rebuild for AGPL corresponding-source access.
FROM scratch AS source-output
COPY --from=backend /src/grafana /grafana
COPY --from=backend /go/pkg/mod /dependencies
COPY --from=backend /src/healthcheck.go /healthcheck.go
COPY Dockerfile /build/Dockerfile
COPY go.sum /build/go.sum
COPY --from=prometheus-frontend-source /src/prometheus /plugin-sources/prometheus
COPY --from=tempo-frontend-source /src/tempo /plugin-sources/tempo
COPY --from=prometheus-source /go/pkg/mod /plugin-dependencies/prometheus/go
COPY --from=tempo-source /go/pkg/mod /plugin-dependencies/tempo/go
COPY --from=prometheus-frontend-source /root/.npm /plugin-dependencies/prometheus/npm-cache
COPY --from=tempo-frontend-source /root/.npm /plugin-dependencies/tempo/npm-cache
COPY --from=prometheus-frontend-source /opt/npm /plugin-build-tools/prometheus/npm
COPY --from=tempo-frontend-source /opt/npm /plugin-build-tools/tempo/npm
COPY --from=plugins /tmp/prometheus.zip /plugin-artifacts/prometheus-13.2.4-linux-amd64.zip
COPY --from=plugins /tmp/tempo.zip /plugin-artifacts/tempo-13.3.0-linux-amd64.zip
COPY --from=plugins /plugins /plugin-artifacts/extracted

# DSA-6572-1 removes compromised trust anchors. Generate the bundle through the
# real Debian package installer, then retain its unmodified control/md5 metadata
# in distroless's existing status.d format (not the builder's unrelated packages).
FROM docker.io/library/debian:trixie-slim@sha256:4876fdea29cac1a33a3195f1eb1952feb1fca7dd6dd00be3e2f1879cf20d34d2 AS certificates
ADD --checksum=sha256:c10585ac22c7f617a73d394eea29ba71d0356f350ae973b19043d1b017f80f54 https://deb.debian.org/debian-security/pool/updates/main/c/ca-certificates/ca-certificates_20250419+deb13u1_all.deb /tmp/ca-certificates.deb
RUN apt-get update && \
    apt-get install -y --no-install-recommends /tmp/ca-certificates.deb && \
    dpkg-deb --control /tmp/ca-certificates.deb /package-control && \
    test "$(dpkg-query --show --showformat='${Version}' ca-certificates)" = '20250419+deb13u1'

FROM ${GRAFANA_BASE}
# Never unload a working pinned plugin for an online startup update. Required
# datasources are shipped read-only in this image, independent of any data PVC.
ENV GF_PLUGINS_PREINSTALL_DISABLED=true GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false
LABEL org.opencontainers.image.source="https://github.com/h1wtest/platform-infra" \
      org.opencontainers.image.version="13.2.4-h1w1" \
      org.opencontainers.image.revision="af4a33e3786594ad72f72d97e6744010330c2977" \
      io.h1wtest.security.go="1.26.10" \
      io.h1wtest.security.kin-openapi="0.149.0"
COPY --from=backend /out/grafana /usr/share/grafana/bin/grafana
COPY --from=backend /out/grafana-version /.grafana-version
COPY --from=backend --chown=472:472 --chmod=0555 /out/grafana-healthcheck /usr/local/bin/grafana-healthcheck
COPY --from=plugins --chown=472:472 /plugins/ /usr/share/grafana/data/plugins-bundled/
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certificates /package-control/control /var/lib/dpkg/status.d/ca-certificates
COPY --from=certificates /package-control/md5sums /var/lib/dpkg/status.d/ca-certificates.md5sums
USER 472
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/grafana-healthcheck"]
