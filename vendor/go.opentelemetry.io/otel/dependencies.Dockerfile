# This is a renovate-friendly source of Docker images.
FROM python:3.13.5-slim-bullseye@sha256:846d391e752027be4a490ac42f8bba40b54b8271fd57d18d5304698a02a4efb0 AS python
FROM otel/weaver:v0.13.2@sha256:ae7346b992e477f629ea327e0979e8a416a97f7956ab1f7e95ac1f44edf1a893 AS weaver
