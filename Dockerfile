FROM golang:1.27.4-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o /out/peak-auth \
    .

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder --chown=65532:65532 /out/peak-auth ./peak-auth
COPY --from=builder --chown=65532:65532 /src/web/templates ./web/templates
COPY --from=builder --chown=65532:65532 /src/web/static ./web/static

ENV TZ=America/Argentina/Buenos_Aires

EXPOSE 8080

USER 65532:65532

ENTRYPOINT ["./peak-auth"]
