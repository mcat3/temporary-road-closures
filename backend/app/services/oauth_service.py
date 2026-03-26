"""
OAuth service for handling authentication with external providers.

This module centralizes:
- OAuth authorization URL generation (with optional PKCE + OIDC nonce)
- Token exchange (with optional PKCE verifier)
- Provider-specific user info normalization
- Google OIDC ID token verification using JWKS
"""

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from typing import Optional, Dict, Any, Tuple
import httpx
import jwt

from app.config import settings
from app.core.exceptions import AuthenticationException, ExternalServiceException
from app.schemas.user import OAuthUser


class OAuthService:
    """
    Service for handling OAuth authentication flows.
    """

    def __init__(self):
        # Provider registry (each provider encapsulates its OAuth specifics)
        self.providers = {
            "google": GoogleOAuthProvider(),
            "github": GitHubOAuthProvider(),
            "osm": OSMOAuthProvider(),
        }

    def get_authorization_url(
        self, provider: str, redirect_uri: Optional[str] = None
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        """
        Get authorization URL for OAuth flow.

        Args:
            provider: OAuth provider name
            redirect_uri: Optional custom redirect URI

        Returns:
            tuple: (authorization_url, state, code_verifier, nonce)
                - code_verifier/nonce are generated per attempt when supported

        Raises:
            AuthenticationException: If provider is not supported
        """
        if provider not in self.providers:
            raise AuthenticationException(
                f"OAuth provider '{provider}' is not supported"
            )

        # Generate secure random state (CSRF protection)
        state = secrets.token_urlsafe(32)

        oauth_provider = self.providers[provider]
        code_verifier = None
        code_challenge = None
        nonce = None

        if oauth_provider.supports_pkce:
            # PKCE: generate a verifier/challenge per auth attempt
            code_verifier = self._generate_code_verifier()
            code_challenge = self._generate_code_challenge(code_verifier)

        if oauth_provider.supports_nonce:
            # OIDC: nonce binds ID token to this auth request
            nonce = secrets.token_urlsafe(32)

        # Build provider-specific authorization URL
        auth_url = oauth_provider.get_authorization_url(
            state, redirect_uri, code_challenge=code_challenge, nonce=nonce
        )

        return auth_url, state, code_verifier, nonce

    async def exchange_code_for_token(
        self, provider: str, code: str, code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.

        Args:
            provider: OAuth provider name
            code: Authorization code from OAuth callback
        Returns:
            dict: Token response data (access_token, id_token, etc.)
                - For Google, includes id_token for OIDC verification

        Raises:
            AuthenticationException: If token exchange fails
        """
        if provider not in self.providers:
            raise AuthenticationException(
                f"OAuth provider '{provider}' is not supported"
            )

        oauth_provider = self.providers[provider]
        # Include PKCE verifier when present
        return await oauth_provider.exchange_code_for_token(
            code, code_verifier=code_verifier
        )

    async def get_user_info(
        self, provider: str, token_data: Dict[str, Any], nonce: Optional[str] = None
    ) -> OAuthUser:
        """
        Get user information from OAuth provider.

        Args:
            provider: OAuth provider name
            token_data: Token response data from OAuth provider

        Returns:
            OAuthUser: User information from provider
                - Google: derived from verified ID token claims
                - GitHub/OSM: derived from provider API

        Raises:
            AuthenticationException: If user info retrieval fails
        """
        if provider not in self.providers:
            raise AuthenticationException(
                f"OAuth provider '{provider}' is not supported"
            )

        oauth_provider = self.providers[provider]
        # Providers may verify ID tokens and return normalized user data
        user_data = await oauth_provider.get_user_info(token_data, nonce=nonce)

        return OAuthUser(
            provider=provider,
            provider_id=user_data["id"],
            email=user_data["email"],
            name=user_data.get("name"),
            username=user_data.get("username"),
            avatar_url=user_data.get("avatar_url"),
        )

    def _generate_code_verifier(self) -> str:
        """
        Generate a PKCE code verifier.
        """
        # RFC 7636: high-entropy, URL-safe string
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=")
        return verifier.decode("ascii")

    def _generate_code_challenge(self, verifier: str) -> str:
        """
        Generate a PKCE S256 code challenge.
        """
        # RFC 7636: BASE64URL-ENCODE(SHA256(verifier))
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=")
        return challenge.decode("ascii")


class BaseOAuthProvider:
    """
    Base class for OAuth providers.
    """

    def __init__(self):
        self.client_id = None
        self.client_secret = None
        self.redirect_uri = None
        self.scope = []
        self.auth_url = None
        self.token_url = None
        self.user_info_url = None
        self.supports_pkce = False
        self.supports_nonce = False

    def get_authorization_url(
        self,
        state: str,
        redirect_uri: Optional[str] = None,
        code_challenge: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> str:
        """
        Generate authorization URL for OAuth flow.

        Args:
            state: State parameter for CSRF protection
            redirect_uri: Optional custom redirect URI
            code_challenge: PKCE S256 challenge (optional)
            nonce: OIDC nonce (optional)

        Returns:
            str: Authorization URL
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri or self.redirect_uri,
            "scope": " ".join(self.scope),
            "response_type": "code",
            "state": state,
        }

        if code_challenge:
            # RFC 7636 S256 code challenge
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        if nonce:
            # OIDC nonce to bind ID token
            params["nonce"] = nonce

        # Add provider-specific parameters
        params.update(self.get_additional_auth_params())

        query_string = urllib.parse.urlencode(params)
        return f"{self.auth_url}?{query_string}"

    def get_additional_auth_params(self) -> Dict[str, str]:
        """
        Get additional provider-specific authorization parameters.

        Returns:
            dict: Additional parameters
        """
        return {}

    async def exchange_code_for_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code
            code_verifier: PKCE verifier (optional)

        Returns:
            dict: Token response data

        Raises:
            ExternalServiceException: If token exchange fails
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }

        if code_verifier:
            # PKCE: send verifier during token exchange
            data["code_verifier"] = code_verifier

        headers = {"Accept": "application/json"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.token_url, data=data, headers=headers, timeout=10.0
                )
                response.raise_for_status()

                token_data = response.json()

                if "access_token" not in token_data:
                    raise ExternalServiceException(
                        self.__class__.__name__, "Access token not found in response"
                    )

                return token_data

        except httpx.HTTPError as e:
            raise ExternalServiceException(
                self.__class__.__name__, f"Token exchange failed: {str(e)}"
            )

    async def get_user_info(
        self, token_data: Dict[str, Any], nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get user information from OAuth provider.

        Args:
            token_data: Token response data
            nonce: OIDC nonce if provider validates ID tokens

        Returns:
            dict: User information

        Raises:
            ExternalServiceException: If user info retrieval fails
        """
        access_token = token_data.get("access_token")
        if not access_token:
            raise ExternalServiceException(
                self.__class__.__name__, "Access token missing from token response"
            )

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.user_info_url, headers=headers, timeout=10.0
                )
                response.raise_for_status()

                return response.json()

        except httpx.HTTPError as e:
            raise ExternalServiceException(
                self.__class__.__name__, f"User info retrieval failed: {str(e)}"
            )


class GoogleOAuthProvider(BaseOAuthProvider):
    """
    Google OAuth provider implementation.
    """

    def __init__(self):
        super().__init__()
        self.client_id = settings.GOOGLE_CLIENT_ID
        self.client_secret = settings.GOOGLE_CLIENT_SECRET
        self.redirect_uri = settings.GOOGLE_REDIRECT_URI
        self.scope = ["openid", "email", "profile"]
        self.auth_url = settings.GOOGLE_OAUTH_URL
        self.token_url = settings.GOOGLE_TOKEN_URL
        self.user_info_url = settings.GOOGLE_USER_INFO_URL
        self.supports_pkce = True
        self.supports_nonce = True
        self.allowed_issuers = {
            "https://accounts.google.com",
            "accounts.google.com",
        }

    def get_additional_auth_params(self) -> Dict[str, str]:
        """Get Google-specific authorization parameters."""
        return {"access_type": "offline", "prompt": "consent"}

    async def get_user_info(
        self, token_data: Dict[str, Any], nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get user information from Google.

        Args:
            token_data: Token response data (must include id_token)
            nonce: OIDC nonce expected in the ID token

        Returns:
            dict: Normalized user information
                - id: Google subject (sub)
                - email: only if email_verified=true
        """
        # Google returns an ID token we must verify (OIDC)
        id_token = token_data.get("id_token")
        if not id_token:
            raise ExternalServiceException("Google", "ID token not found in response")

        claims = await self._verify_id_token(id_token, nonce=nonce)

        # Only trust email if explicitly verified by Google
        email_verified = claims.get("email_verified") is True
        email = claims.get("email") if email_verified else None
        username = email.split("@")[0] if email else None

        return {
            "id": claims["sub"],
            "email": email,
            "name": claims.get("name"),
            "username": username,
            "avatar_url": claims.get("picture"),
        }

    async def _fetch_jwks(self) -> Dict[str, Any]:
        """
        Fetch Google's JSON Web Key Set for ID token signature validation.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    settings.GOOGLE_JWKS_URL, timeout=10.0
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            raise ExternalServiceException("Google", f"JWKS fetch failed: {str(e)}")

    async def _verify_id_token(
        self, id_token: str, nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify Google ID token signature and required OIDC claims.

        Validates:
        - signature using JWKS
        - issuer and audience
        - exp/iat presence
        - nonce match
        """
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError as e:
            raise AuthenticationException(f"Invalid ID token header: {str(e)}")

        kid = header.get("kid")
        if not kid:
            raise AuthenticationException("ID token header missing 'kid'")

        # Resolve the signing key from Google's JWKS
        jwks = await self._fetch_jwks()
        jwk = next((key for key in jwks.get("keys", []) if key.get("kid") == kid), None)
        if not jwk:
            raise AuthenticationException("No matching JWKS key for ID token")

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

        try:
            # Verify signature, issuer, audience, and required claims
            claims = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=60,
            )
        except jwt.PyJWTError as e:
            raise AuthenticationException(f"Invalid ID token signature: {str(e)}")

        # Enforce issuer
        issuer = claims.get("iss")
        if issuer not in self.allowed_issuers:
            raise AuthenticationException("Invalid ID token issuer")

        # Enforce presence of required OIDC claims
        required_claims = ["exp", "iat", "iss", "aud", "sub", "nonce"]
        missing_claims = [claim for claim in required_claims if claim not in claims]
        if missing_claims:
            raise AuthenticationException(
                f"ID token missing required claims: {', '.join(missing_claims)}"
            )

        # Nonce must match the initiating auth request
        if nonce is None or claims.get("nonce") != nonce:
            raise AuthenticationException("Invalid ID token nonce")

        # Basic sanity check: issued-at should not be far in the future
        iat = claims.get("iat")
        now = int(time.time())
        if not isinstance(iat, (int, float)) or iat > now + 300:
            raise AuthenticationException("Invalid ID token issued-at time")

        return claims


class GitHubOAuthProvider(BaseOAuthProvider):
    """
    GitHub OAuth provider implementation.
    """

    def __init__(self):
        super().__init__()
        self.client_id = settings.GITHUB_CLIENT_ID
        self.client_secret = settings.GITHUB_CLIENT_SECRET
        self.redirect_uri = settings.GITHUB_REDIRECT_URI
        self.scope = ["user:email"]
        self.auth_url = settings.GITHUB_OAUTH_URL
        self.token_url = settings.GITHUB_TOKEN_URL
        self.user_info_url = settings.GITHUB_USER_INFO_URL

    async def get_user_info(
        self, token_data: Dict[str, Any], nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get user information from GitHub.

        Args:
            token_data: Token response data (must include access_token)

        Returns:
            dict: Normalized user information
        """
        # Get basic user info from GitHub user endpoint
        user_data = await super().get_user_info(token_data, nonce=nonce)

        # Get user email (GitHub requires separate API call for emails)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ExternalServiceException(
                "GitHub", "Access token missing from token response"
            )
        email = await self._get_user_email(access_token)

        # Normalize GitHub user data
        return {
            "id": str(user_data["id"]),
            "email": email,
            "name": user_data.get("name"),
            "username": user_data.get("login"),
            "avatar_url": user_data.get("avatar_url"),
        }

    async def _get_user_email(self, access_token: str) -> str:
        """
        Get user's primary email from GitHub.

        Args:
            access_token: GitHub access token

        Returns:
            str: User's primary email
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/user/emails", headers=headers, timeout=10.0
                )
                response.raise_for_status()

                emails = response.json()

                # Find primary email
                for email_data in emails:
                    if email_data.get("primary", False):
                        return email_data["email"]

                # Fallback to first email if no primary
                if emails:
                    return emails[0]["email"]

                raise ExternalServiceException("GitHub", "No email found for user")

        except httpx.HTTPError as e:
            raise ExternalServiceException(
                "GitHub", f"Email retrieval failed: {str(e)}"
            )


class OSMOAuthProvider(BaseOAuthProvider):
    """
    OpenStreetMap OAuth provider implementation.
    """

    def __init__(self):
        super().__init__()
        self.client_id = settings.OSM_CLIENT_ID
        self.client_secret = settings.OSM_CLIENT_SECRET
        self.redirect_uri = settings.OSM_REDIRECT_URI
        self.scope = ["read_prefs"]
        self.auth_url = settings.OSM_OAUTH_URL
        self.token_url = settings.OSM_TOKEN_URL
        self.user_info_url = settings.OSM_USER_INFO_URL

    async def get_user_info(
        self, token_data: Dict[str, Any], nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get user information from OpenStreetMap.

        Args:
            token_data: Token response data (must include access_token)

        Returns:
            dict: Normalized user information
        """
        access_token = token_data.get("access_token")
        if not access_token:
            raise ExternalServiceException(
                "OpenStreetMap", "Access token missing from token response"
            )

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.user_info_url, headers=headers, timeout=10.0
                )
                response.raise_for_status()

                data = response.json()

                # OSM returns data in a nested structure
                user_data = data.get("user", {})

                # Normalize OSM user data
                return {
                    "id": str(user_data.get("id")),
                    "email": user_data.get("email"),  # May be None if user hasn't shared it
                    "name": user_data.get("display_name"),
                    "username": user_data.get("display_name"),
                    "avatar_url": user_data.get("img", {}).get("href"),  # OSM avatar
                }

        except httpx.HTTPError as e:
            raise ExternalServiceException(
                "OpenStreetMap", f"User info retrieval failed: {str(e)}"
            )
