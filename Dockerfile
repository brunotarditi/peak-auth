FROM golang:1.27-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o peak-auth

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/peak-auth .
COPY --from=builder /app/web/templates ./web/templates
COPY --from=builder /app/web/static ./web/static
ENV TZ=America/Argentina/Buenos_Aires
EXPOSE 8080
USER nonroot:nonroot
CMD ["./peak-auth"]
