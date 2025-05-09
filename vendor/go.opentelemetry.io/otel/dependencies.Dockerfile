# This is a renovate-friendly source of Docker images.
FROM python:3.13.2-slim-bullseye@sha256:31b581c8218e1f3c58672481b3b7dba8e898852866b408c6a984c22832523935 AS python
FROM otel/weaver:v0.15.0@sha256:1cf1c72eaed57dad813c2e359133b8a15bd4facf305aae5b13bdca6d3eccff56 AS weaver
