FROM scratch AS web
COPY --chmod=0555 build/web /web
COPY --chmod=0555 build/healthprobe /healthprobe
COPY frontend/dist /app/static
COPY configs/topology /app/config/topology
COPY --chown=65532:65532 data /var/lib/airqso-assets
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/web"]

FROM scratch AS radiod
COPY --chmod=0555 build/radiod /radiod
COPY --chmod=0555 build/radioctl /radioctl
COPY --chown=65532:65532 data /var/lib/airqso
USER 65532:65532
EXPOSE 9000 9001
ENTRYPOINT ["/radiod"]

FROM scratch AS migrate
COPY --chmod=0555 build/migrate /migrate
COPY migrations /app/migrations
USER 65532:65532
ENTRYPOINT ["/migrate"]
