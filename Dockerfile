FROM golang:1.26.8-bookworm
COPY kntrl /usr/bin/kntrl
ENTRYPOINT ["/usr/bin/kntrl"]
