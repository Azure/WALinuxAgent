FROM debian:jessie
RUN apt-get update && apt-get upgrade --no-install-recommends -y
RUN apt-get install -y --no-install-recommends \
    openssl ca-certificates ssh parted sudo net-tools ifupdown python python-pyasn1 python-rpm
COPY waagent /usr/sbin/
COPY config/docker-waagent.conf /etc/waagent.conf
RUN chmod +x /usr/sbin/waagent && \
    rm -rf /etc/skel && \
    ln -sf /dev/stdout /var/log/waagent.log
ENTRYPOINT ["/usr/sbin/waagent"]
