# Stage 1:
# Build kntrl binary
FROM golang:bookworm AS build
# Install and update dependencies
RUN apt-get update && \
    apt-get install -y build-essential git cmake \
                       zlib1g-dev libevent-dev \
                       libelf-dev llvm \
                       clang libc6-dev-i386
# Create a directory and copy all the files from the base to the created directory
RUN mkdir /kntrl-build
WORKDIR /kntrl-build
COPY . .
# Build kntrl as a binary
RUN make
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o binary main.go
# Stage 2:
# Run kntrl binary in the latest golang image
FROM golang:latest
WORKDIR /
COPY --from=build kntrl-build/binary kntrl-binary
COPY --from=build kntrl-build/kntrl/ kntrl/
ENTRYPOINT ["./kntrl-binary"]
