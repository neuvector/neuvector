# This is a renovate-friendly source of Docker images.
FROM python:3.13.3-slim-bullseye@sha256:9e3f9243e06fd68eb9519074b49878eda20ad39a855fac51aaffb741de20726e AS python
FROM otel/weaver:v0.21.2@sha256:2401de985c38bdb98b43918e2f43aa36b2afed4aa5669ac1c1de0a17301cd36d AS weaver
FROM avtodev/markdown-lint:v1@sha256:6aeedc2f49138ce7a1cd0adffc1b1c0321b841dc2102408967d9301c031949ee AS markdown
