# Build from source. Releases use Dockerfile.goreleaser, which copies a
# prebuilt binary instead.
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies are layered separately so a source-only change does not
# re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# CGO is off so the result runs on a scratch-like base with no libc.
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/scm-bench/azure-devops-bench/internal/cli.Version=${VERSION} \
      -X github.com/scm-bench/azure-devops-bench/internal/cli.Commit=${COMMIT} \
      -X github.com/scm-bench/azure-devops-bench/internal/cli.Date=${DATE}" \
    -o /out/azure-devops-bench ./cmd/azure-devops-bench

FROM alpine:3.24

# Certificates are the only runtime dependency: azure-devops-bench talks HTTPS to
# Azure DevOps and nothing else.
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 scmbench

COPY --from=build /out/azure-devops-bench /usr/local/bin/azure-devops-bench

USER 10001
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/azure-devops-bench"]
CMD ["--help"]
