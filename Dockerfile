FROM golang:1.23-alpine

WORKDIR /app

COPY . .

ENV GOPROXY=https://goproxy.io,direct

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/dns-resolver-cli

CMD [ "./server" ]