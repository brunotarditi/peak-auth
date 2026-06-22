FROM node:22-alpine AS assets
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/static ./static
COPY web/templates ./templates
RUN npm run build:css

FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=assets /app/web/static/css/output.css ./web/static/css/output.css
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o peak-auth

FROM alpine:latest
# Certificados CA (para llamadas HTTPS salientes, p. ej. Resend) y zona horaria.
RUN apk add --no-cache tzdata ca-certificates && \
    adduser -D -H -u 10001 appuser
ENV TZ=America/Argentina/Buenos_Aires

WORKDIR /app
COPY --from=builder /app/peak-auth ./peak-auth
COPY --from=builder /app/web/templates ./web/templates
COPY --from=builder /app/web/static ./web/static

# Ejecutar como usuario sin privilegios.
USER appuser

EXPOSE 8080
CMD ["./peak-auth"]
