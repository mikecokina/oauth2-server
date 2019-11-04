from authlib.flask.oauth2 import AuthorizationServer, ResourceProtector
from authlib.flask.oauth2.sqla import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7009 import RevocationEndpoint

from .models import db, User
from .models import OAuth2Client, OAuth2Token


RevocationEndpoint.CLIENT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
grants.ClientCredentialsGrant.TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def __init__(self, *args, **kwargs):
        self.TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
        super().__init__(*args, **kwargs)

    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):
            return user


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    def create_token_response(self):
        self.request.user = self.request.client.user
        return super().create_token_response()


class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


query_client = create_query_client_func(db.session, OAuth2Client)
save_token = create_save_token_func(db.session, OAuth2Token)
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
require_oauth = ResourceProtector()


def config_oauth(app):
    authorization.init_app(app)

    # support all grants
    # authorization.register_grant(grants.ImplicitGrant)
    authorization.register_grant(ClientCredentialsGrant)
    # authorization.register_grant(grants.AuthorizationCodeGrant)
    authorization.register_grant(PasswordGrant)
    authorization.register_grant(RefreshTokenGrant)

    # support revocation
    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
