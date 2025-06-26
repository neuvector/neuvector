# This is a renovate-friendly source of Docker images.
FROM python:3.13.2-slim-bullseye@sha256:31b581c8218e1f3c58672481b3b7dba8e898852866b408c6a984c22832523935 AS python
FROM otel/weaver:v0.15.3@sha256:a84032d6eb95b81972d19de61f6ddc394a26976c1c1697cf9318bef4b4106976 AS weaver
