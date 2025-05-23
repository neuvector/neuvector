# This is a renovate-friendly source of Docker images.
FROM python:3.13.3-slim-bullseye@sha256:f0acec66ba3578f142b7efc6a3e5ce62a5f51639ea430df576f9249c7baf6ef2 AS python
FROM otel/weaver:v0.13.2@sha256:ae7346b992e477f629ea327e0979e8a416a97f7956ab1f7e95ac1f44edf1a893 AS weaver
