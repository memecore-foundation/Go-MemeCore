# Support setting various labels on the final image
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

# Build Gmeme in a stock Go builder container
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev linux-headers git

# Get dependencies - will also be cached if we won't change go.mod/go.sum
COPY go.mod /go-memecore/
COPY go.sum /go-memecore/
RUN cd /go-memecore && go mod download

ADD . /go-memecore
RUN cd /go-memecore && go run build/ci.go install -static ./cmd/gmeme

# Pull Gmeme into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /go-memecore/build/bin/gmeme /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["gmeme"]

# Add some metadata labels to help programmatic image consumption
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

LABEL commit="$COMMIT" version="$VERSION" buildnum="$BUILDNUM"
