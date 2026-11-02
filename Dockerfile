# wpsbom as a container image, for the Kubernetes CronJob (deploy/kubernetes.yaml) and CI.
# Static binary on scratch: CA certificates for the registry and Watchpost, nothing else.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/ice-s/wpsbom/pkg/wpsbom.Version=${VERSION}" -o /wpsbom ./cmd/wpsbom

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /wpsbom /wpsbom
USER 65534:65534
ENTRYPOINT ["/wpsbom"]
