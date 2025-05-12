# This is a renovate-friendly source of Docker images.
FROM python:3.13.3-slim-bullseye@sha256:9e3f9243e06fd68eb9519074b49878eda20ad39a855fac51aaffb741de20726e AS python
FROM otel/weaver:v0.13.2@sha256:ae7346b992e477f629ea327e0979e8a416a97f7956ab1f7e95ac1f44edf1a893 AS weaver
