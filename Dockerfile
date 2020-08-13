FROM alpine:3.7
ARG arch

RUN apk --no-cache add \
    ca-certificates \
    iptables

COPY build/bin/linux/kube2iam-${arch} /bin/kube2iam

ENTRYPOINT ["kube2iam"]
