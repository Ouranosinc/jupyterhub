FROM jupyterhub/jupyterhub:5.5.0
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.authors="https://github.com/Ouranosinc/jupyterhub"
LABEL Description="JupyterHub" Vendor="Ouranosinc" Version="5.5.0-20260710"

RUN apt-get update \
 && apt-get install -yq --no-install-recommends patch \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install dockerspawner
