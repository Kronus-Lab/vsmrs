# Packaging only: the binary is produced by scripts/build-image.sh, which
# compiles the static musl binary in a pinned builder container. The build
# context contains only dist/vsm (see .dockerignore).
FROM scratch
COPY dist/vsm /vsm
WORKDIR /app
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/vsm"]
