FROM ubuntu:14.04.2
RUN apt-get update && apt-get upgrade --no-install-recommends -y
RUN apt-get install -y --no-install-recommends \
    openssl ca-certificates ssh parted sudo net-tools python python-pyasn1 python-rpm
COPY waagent /usr/sbin/
COPY config/docker-waagent.conf /etc/waagent.conf
RUN chmod +x /usr/sbin/waagent
ENTRYPOINT ["/usr/sbin/waagent"]
