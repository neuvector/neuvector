# This is a renovate-friendly source of Docker images.
FROM python:3.13.3-slim-bullseye@sha256:d3f1e48b3e62e0e24b8ed20937d052662906c16e53013f32be88e2eb4f1b3532 AS python
FROM otel/weaver:v0.13.2@sha256:ae7346b992e477f629ea327e0979e8a416a97f7956ab1f7e95ac1f44edf1a893 AS weaver
