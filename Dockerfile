# Used by goreleaser (dockers_v2): the build context contains pre-built
# binaries under $TARGETPLATFORM — never build Go code in here.
# iproute2/tcpdump are included for debugging inside containerlab topologies.
FROM alpine:3.22
ARG TARGETPLATFORM
RUN apk add --no-cache iproute2 tcpdump
COPY $TARGETPLATFORM/goisisd /usr/local/bin/goisisd
COPY $TARGETPLATFORM/goisis /usr/local/bin/goisis
ENTRYPOINT ["/usr/local/bin/goisisd"]
