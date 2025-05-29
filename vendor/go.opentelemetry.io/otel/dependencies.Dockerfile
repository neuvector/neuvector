# This is a renovate-friendly source of Docker images.
FROM python:3.13.2-slim-bullseye@sha256:31b581c8218e1f3c58672481b3b7dba8e898852866b408c6a984c22832523935 AS python
FROM otel/weaver:v0.15.1@sha256:95c0aaa493d84ac72a1188756bd46eec1ead8e82004e7778ff5779736be8d578 AS weaver
