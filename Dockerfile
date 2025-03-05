FROM golang:latest
COPY kntrl /usr/bin/kntrl
ENTRYPOINT ["/usr/bin/kntrl"]
