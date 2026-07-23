# jupyterhub
Jupyterhub with extra required packages.

Based on upstream
[`jupyterhub/jupyterhub`](https://hub.docker.com/r/jupyterhub/jupyterhub) image
with extra required packages, see
[`Dockerfile`](https://github.com/Ouranosinc/jupyterhub/blob/master/Dockerfile)

## Release instructions

1. Open a pull request to make desired Dockerfile configuration changes.
1. Install `bump-my-version`: `$ pip install -r requirements.txt`.
1. Run `$ bump-my-version {major | minor | patch | date | build}`.
    * Be sure to match the same original upstream `jupyterhub/jupyterhub` version in the tag so we know what version our image is based on.
    * If changes do not modify the `jupyterhub/jupyterhub` image, one can simply run `$ bump-my-version bump date`.
    * For multiple releases on the same date, one can simply run `$ bump-my-version bump build`.
1. If the last bump was not a `build` bump, run `$ bump-my-version bump release`.
1. Merge the Pull Request to the `master` branch and switch to `master` branch.
1. Create a tag matching the new version string (`{jupyterhub/jupyterhub version}-{YYYY}{0M}{0D}`) and push to the repository.

A new [`pavics/jupyterhub`](https://hub.docker.com/r/pavics/jupyterhub) image will be built on GitHub Workflows and pushed to Docker Hub.
