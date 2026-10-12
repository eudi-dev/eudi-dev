FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w -X github.com/eudi-dev/eudi-dev/v2/cmd.Version=${VERSION}" -o eudi .

FROM alpine:3.21
# The state directory exists and belongs to app, so a named volume mounted
# there is writable.
RUN adduser -D -h /home/app app && mkdir /home/app/.eudi-dev && chown app /home/app/.eudi-dev
COPY --from=build /app/eudi /usr/local/bin/
# Legacy binary name
RUN ln -s /usr/local/bin/eudi /usr/local/bin/oid4vc-dev
USER app
# wallet serve reads each flag from EUDI_DEV_<FLAG>. A flag on the command wins.
# --demo ignores EUDI_DEV_AUTO_ACCEPT and auto-accepts only with --auto-accept.
ENV EUDI_DEV_PORT=8085 EUDI_DEV_AUTO_ACCEPT=true EUDI_DEV_PID=true
# Memory storage and a public seed give each restart the same keys. For persistence,
# select file or Postgres storage and clear EUDI_DEV_SEED to generate random keys.
ENV EUDI_DEV_STORAGE=memory
ENV EUDI_DEV_SEED=eudi-dev
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -q --spider http://localhost:${PORT:-$EUDI_DEV_PORT}/healthz || exit 1
ENTRYPOINT ["eudi"]
CMD ["wallet", "serve"]
