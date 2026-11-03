FROM jupyterhub/jupyterhub:6.1.1
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.authors="Ouranosinc"
LABEL org.opencontainers.image.created="2026-11-03T15:20:33Z"
LABEL org.opencontainers.image.source="https://github.com/Ouranosinc/jupyterhub"
LABEL org.opencontainers.image.version="6.1.1-20261103"
LABEL Description="JupyterHub"

RUN apt-get update \
 && apt-get install -yq --no-install-recommends patch \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install dockerspawner
