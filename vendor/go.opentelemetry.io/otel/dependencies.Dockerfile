# This is a renovate-friendly source of Docker images.
FROM python:3.13.4-slim-bullseye@sha256:ec7d08e0f8ab4865a386f922cc20c61ec62a6172e3b0a4bb8b74ea3056070b97 AS python
FROM otel/weaver:v0.13.2@sha256:ae7346b992e477f629ea327e0979e8a416a97f7956ab1f7e95ac1f44edf1a893 AS weaver
