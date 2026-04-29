FROM jupyterhub/jupyterhub:5.4.5

RUN apt-get update \
 && apt-get install -yq --no-install-recommends \
    patch \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install dockerspawner
