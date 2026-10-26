# The deliberately malicious demo server (demo/evil-server), on an empty
# base: no OS, no shell, nothing pulled. "make sandbox-evil" cross-compiles
# it and the probe on the host, and builds this with a context holding only
# those two static binaries. See sandbox/run.sh for how it's run.
FROM scratch
COPY evil-server probe /
# An unprivileged user; scratch has no /etc/passwd, so a number.
USER 65532:65532
ENTRYPOINT ["/evil-server"]
