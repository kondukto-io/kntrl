FROM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d
COPY kntrl /usr/bin/kntrl
ENTRYPOINT ["/usr/bin/kntrl"]
