from traitlets import Unicode
from jupyterhub.auth import Authenticator
from jupyterhub.handlers.login import LogoutHandler
import requests


class MagpieLogoutHandler(LogoutHandler):
    """
    Logout Handler that also logs the user out of magpie when logging out of jupyterhub.
    """

    async def handle_logout(self):
        cookies = {key: morsel.coded_value for key, morsel in self.request.cookies.items()}
        signout_url = self.authenticator.magpie_url.rstrip("/") + "/signout"
        response = requests.get(signout_url, cookies=cookies, headers={"Host": self.authenticator.public_fqdn})
        if response.ok and 'Set-Cookie' in response.headers:
            self.set_header("Set-Cookie", response.headers["Set-Cookie"])


class MagpieAuthenticator(Authenticator):
    """Authenticate to JupyterHub using Magpie.

    To use this authenticator, set the following parameters in the `jupyterhub_config.py` file:
     - c.JupyterHub.authenticator_class = 'jupyterhub_magpie_authenticator.MagpieAuthenticator'
     - c.MagpieAuthenticator.magpie_url = "magpie:2000" # url where magpie is running (does not need to be public)
     - c.MagpieAuthenticator.public_fqdn = "www.example.com"  # fqdn of server where magpie is running

    You may also optionally choose to set an `authorization_url` which is a URL that can be used to check whether the
    user logged in to Magpie has permission to access jupyterhub:
     - c.MagpieAuthenticator.authorization_url = "http://twitcher:8000/ows/verify/jupyterhub"

    If `authorization_url` is set, then setting `enable_auth_state` will enable jupyterhub to store the user's magpie
    cookies. This will allow the `refresh_user` method to periodically check whether the user is still authorized and
    will attempt to log them out of jupyterhub if not.

    If `authorization_url` and `enable_auth_state` are set, then you may also be interested in setting the
    `refresh_pre_spawn` and `auth_refresh_age` variables. See the jupyterhub documentation for more details.
    """
    default_provider = "ziggurat"
    magpie_url = Unicode(
        default_value="https://www.example.com/magpie",
        config=True,
        help="Magpie endpoint to signin to"
    )
    public_fqdn = Unicode(
        config=True,
        help="Public fully qualified domain name. Used to set the magpie login cookie."
    )
    authorization_url = Unicode(
        default=None,
        config=True,
        help="optional URL that can be used to check whether the user logged in to Magpie has permission to access "
             "jupyterhub"
    )

    def get_handlers(self, app):
        return [
            ('/logout', MagpieLogoutHandler)
        ]

    def normalize_username(self, username):
        """
        Do not normalize username but still apply username_map if set.

        This ensures that mounted directories on the host machine are discovered properly
        since we expect the username to match the username set by Magpie.
        """
        username = self.username_map.get(username, username)
        return username

    async def authenticate(self, handler, data):
        signin_url = self.magpie_url.rstrip('/') + '/signin'

        post_data = {
            "user_name": data["username"],
            "password": data["password"],
            "provider_name": self.default_provider,
        }
        response = requests.post(signin_url, data=post_data)

        if response.ok:
            if self.authorization_url:
                auth_response = requests.get(self.authorization_url, cookies=response.cookies.get_dict())
                if not auth_response.ok:
                    return None
            for cookie in response.cookies:
                handler.set_cookie(name=cookie.name,
                                   value=cookie.value,
                                   domain=self.public_fqdn,
                                   expires=cookie.expires,
                                   path=cookie.path,
                                   secure=cookie.secure)
            if self.enable_auth_state:
                return {"name": data['username'], "auth_state": {"magpie_cookies": response.cookies.get_dict()}}
            else:
                return data['username']

    async def refresh_user(self, user, handler=None):
        if not (self.authorization_url and self.enable_auth_state):
            # MagpieAuthenticator is not configured to re-check user authorization
            return True
        auth_state = await user.get_auth_state()
        cookies = auth_state.get("magpie_cookies")
        if cookies:
            auth_response = requests.get(self.authorization_url, cookies=cookies)
            if auth_response.ok:
                return True
        if handler:
            handler.clear_login_cookie()
        return False
