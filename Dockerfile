FROM jupyterhub/jupyterhub:4.1.5

COPY jupyterhub_magpie_authenticator /jupyterhub_magpie_authenticator

RUN apt-get update \
 && apt-get install -yq --no-install-recommends \
    patch \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install dockerspawner /jupyterhub_magpie_authenticator
