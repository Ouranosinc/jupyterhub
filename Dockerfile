FROM jupyterhub/jupyterhub:4.0.2

COPY jupyterhub_magpie_authenticator /jupyterhub_magpie_authenticator
COPY requirements.txt /tmp/requirements.txt

RUN apt-get update \
 && apt-get install -yq --no-install-recommends \
    patch \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install -r /tmp/requirements.txt \
    && pip install /jupyterhub_magpie_authenticator
