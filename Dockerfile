# syntax=docker/dockerfile:1.7
# Multi-arch image: linux/amd64, linux/arm64, linux/arm/v7. Final image = one static binary.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w -X draypulse/internal/app.Version=$VERSION" -o /out/draypulse . \
 && mkdir -p /out/data && chown 1000:1000 /out/data

FROM scratch
# RUN_USER=0 is used only for the Home Assistant add-on, whose /data is root-owned.
ARG RUN_USER=1000
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/draypulse /draypulse
COPY --from=build --chown=1000:1000 /out/data /data
ENV DRAYPULSE_DATA=/data DRAYPULSE_LISTEN=:8080
USER ${RUN_USER}
VOLUME ["/data"]
EXPOSE 8080 5514/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/draypulse", "healthcheck"]
ENTRYPOINT ["/draypulse"]
