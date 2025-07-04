# This is a renovate-friendly source of Docker images.
FROM python:3.13.2-slim-bullseye@sha256:31b581c8218e1f3c58672481b3b7dba8e898852866b408c6a984c22832523935 AS python
FROM otel/weaver:v0.16.0@sha256:ee6eefd8cd8f4d2cfb7763b8a0fd613cfdf7dfbfda97e0e9b49d1a00dd01f7d6 AS weaver
