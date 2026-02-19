FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o peak-auth

FROM alpine:latest
RUN apk add --no-cache tzdata
ENV TZ=America/Argentina/Buenos_Aires
WORKDIR /root/
COPY --from=builder /app/peak-auth .
COPY --from=builder /app/templates /root/templates
EXPOSE 8080
CMD ["./peak-auth"]