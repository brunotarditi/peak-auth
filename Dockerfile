FROM node:22-alpine AS assets
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/static ./static
COPY web/templates ./templates
RUN npm run build:css

FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
COPY --from=assets /app/web/static/css/output.css ./web/static/css/output.css
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o peak-auth

FROM alpine:latest
RUN apk add --no-cache tzdata
ENV TZ=America/Argentina/Buenos_Aires
WORKDIR /root/
COPY --from=builder /app/peak-auth .
COPY --from=builder /app/web/templates /root/web/templates
COPY --from=builder /app/web/static /root/web/static
EXPOSE 8080
CMD ["./peak-auth"]
