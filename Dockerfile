FROM golang:1.25-bookworm
COPY kntrl /usr/bin/kntrl
ENTRYPOINT ["/usr/bin/kntrl"]
