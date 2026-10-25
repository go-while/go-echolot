# go-echolot and the yamn binary it runs, in one small image (README,
# "Docker").  Both are static Go binaries on an empty base: no shell, and
# only Docker Hub images are pulled.
#
#   docker build --build-arg VERSION="$(git describe --always --dirty)" -t go-echolot .
#
# The daemon runs as user nonroot (65532) unless you give --user.  It needs:
#   /etc/go-echolot/config.ini   the config, read-only
#   /var/lib/go-echolot          paths.state_dir: state, Maildir, results
# and mail.method = smtp, since the image has no sendmail.

ARG GO_IMAGE=docker.io/library/golang:1.27.3

# yamn is a separate program, not a Go dependency (design §3): build it
# from a fixed commit of go-while/yamn.  f1a0b1f has PR #72 (signature
# checks), #73 (yamn refuses to run as root, -V and --version excepted,
# so the image runs as nonroot and --user must not be 0), #74 and #78.
FROM ${GO_IMAGE} AS yamn
ARG YAMN_REPO=https://github.com/go-while/yamn
ARG YAMN_REF=f1a0b1f68ebc01c1f327f7d8980a0613d28044a8
WORKDIR /src
RUN git init -q . \
 && git fetch -q --depth 1 "$YAMN_REPO" "$YAMN_REF" \
 && git checkout -q FETCH_HEAD \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/yamn . \
 && /out/yamn -V

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/go-echolot ./cmd/go-echolot \
 && /out/go-echolot version

# The rest of the image: CA certificates (peer checks, SMTP TLS), /tmp for
# yamn's work dirs, a user "nonroot" (65532), and the state dir owned by
# it, so a new named volume is writable.
RUN mkdir -p /rootfs/etc/ssl/certs /rootfs/etc/go-echolot /rootfs/var/lib/go-echolot \
 && mkdir -m 1777 /rootfs/tmp \
 && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ \
 && echo 'nonroot:x:65532:65532:nonroot:/var/lib/go-echolot:/sbin/nologin' > /rootfs/etc/passwd \
 && echo 'nonroot:x:65532:' > /rootfs/etc/group \
 && chown 65532:65532 /rootfs/var/lib/go-echolot

FROM scratch
COPY --from=build /rootfs/ /
COPY --from=yamn /out/yamn /usr/local/bin/yamn
COPY --from=build /out/go-echolot /usr/local/bin/go-echolot
USER 65532:65532
VOLUME /var/lib/go-echolot
ENTRYPOINT ["/usr/local/bin/go-echolot"]
CMD ["run"]
