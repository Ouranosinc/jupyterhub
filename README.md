# jupyterhub
Jupyterhub with extra required packages.

Based on upstream
[`jupyterhub/jupyterhub`](https://hub.docker.com/r/jupyterhub/jupyterhub) image
with extra required packages, see
[`Dockerfile`](https://github.com/Ouranosinc/jupyterhub/blob/master/Dockerfile)

## Release instructions

1. Open a pull request to make desired Dockerfile configuration changes.
1. Install `bump-my-version`: `$ pip install -r .github/requirements.txt`.
1. Run `$ bump-my-version {major | minor | patch | date | build}`.
    * Be sure to match the same original upstream `jupyterhub/jupyterhub` version in the tag so we know what version our image is based on.
    * If changes do not modify the `jupyterhub/jupyterhub` image, run `$ bump-my-version bump date`.
    * If multiple releases are made on the same date, run `$ bump-my-version bump build`.
    * If you wish to arbitrarily set the version string, run `$ bump-my-version bump --new-version {#.#.#-YYYYmmdd | #.#.#-YYYYmmdd.b}`.
1. Merge the Pull Request to the `master` branch.

Once merged to `master`, GitHub Workflows will automatically tag a new version, build a Docker image, and push the image to Docker Hub ([`pavics/jupyterhub`](https://hub.docker.com/r/pavics/jupyterhub)).

For more `bump-my-version` options, see the [bump-my-version documentation](https://callowayproject.github.io/bump-my-version/reference/cli/)
