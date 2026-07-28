FROM jupyterhub/jupyterhub:5.5.0
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.authors="Ouranosinc"
LABEL org.opencontainers.image.created="2026-07-28T19:31:13Z"
LABEL org.opencontainers.image.source="https://github.com/Ouranosinc/jupyterhub"
LABEL org.opencontainers.image.version="5.5.0-20260728"
LABEL Description="JupyterHub"

RUN apt-get update \
 && apt-get install -yq --no-install-recommends patch \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install dockerspawner
