ARG GATEWAY_BASE=docker.io/nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
FROM ${GATEWAY_BASE}
USER 0:0
# Exact signed Alpine v3.24 security revisions; retain complete APK inventory.
RUN apk add --no-cache --upgrade musl=1.2.6-r3 musl-utils=1.2.6-r3 zlib=1.3.2-r1
USER 101:101
