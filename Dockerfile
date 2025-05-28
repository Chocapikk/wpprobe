FROM golang:1.23-alpine

RUN go install github.com/Chocapikk/wpprobe@latest
RUN wpprobe update
RUN wpprobe update-db

ENTRYPOINT ["/go/bin/wpprobe"]