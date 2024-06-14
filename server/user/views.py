from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from rest_framework import (
    exceptions as rest_exceptions,
    response,
    decorators as rest_decorators,
    permissions as rest_permissions,
)
from rest_framework_simplejwt import (
    tokens,
    views as jwt_views,
    serializers as jwt_serializers,
    exceptions as jwt_exceptions,
)
from user import serializers, models
import stripe

stripe.api_key = settings.STRIPE_SECRET_KEY
prices = {
    settings.WORLD_INDIVIDUAL: "world_individual",
    settings.WORLD_GROUP: "world_group",
    settings.WORLD_BUSINESS: "world_business",
    settings.UNIVERSE_INDIVIDUAL: "universe_individual",
    settings.UNIVERSE_GROUP: "universe_group",
    settings.UNIVERSE_BUSINESS: "universe_business",
}


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {"refresh_token": str(refresh), "access_token": str(refresh.access_token)}


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def loginView(request):
    """
    User Login.

    This endpoint allows users to log in with their email and password. If authentication is successful,
    access and refresh tokens are returned in the response and set as cookies.

    **Example request**:

        POST /auth/login

    **Request body example**:

        {
            "email": "user@example.com",
            "password": "securepassword"
        }

    **Response**:

    - `200 OK`: Authentication was successful and tokens are returned.

    **Response body example**:

        {
            "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
        }

    **Cookies set**:

    - `access_token`
    - `refresh_token`

    **Response headers**:

    - `X-CSRFToken`: CSRF token for subsequent requests.
    """
    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.data = tokens
        res["X-CSRFToken"] = csrf.get_token(request)
        return res
    raise rest_exceptions.AuthenticationFailed("Email or Password is incorrect!")


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def registerView(request):
    """
    User Registration.

    This endpoint allows users to register with their email and password. Upon successful registration,
    a confirmation message is returned.

    **Example request**:

        POST /auth/register

    **Request body example**:

        {
            "email": "user@example.com",
            "password": "securepassword",
            "confirm_password": "securepassword"
        }

    **Response**:

    - `200 OK`: Registration was successful.

    **Response body example**:

        {
            "msg": "Registered!"
        }

    **Error response**:

    - `400 Bad Request`: Invalid data provided.
    """
    serializer = serializers.RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response("Registered!")
    return rest_exceptions.AuthenticationFailed("Invalid credentials!")


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    """
    User Logout.

    This endpoint allows authenticated users to log out by invalidating their refresh tokens and clearing the
    relevant cookies.

    **Example request**:

        POST /auth/logout

    **Response**:

    - `200 OK`: Logout was successful and cookies are cleared.

    **Error response**:

    - `400 Bad Request`: Invalid token.
    """
    try:
        refreshToken = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        token = tokens.RefreshToken(refreshToken)
        token.blacklist()

        res = response.Response()
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"])
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        res.delete_cookie("X-CSRFToken")
        res.delete_cookie("csrftoken")
        res["X-CSRFToken"] = None

        return res
    except:
        raise rest_exceptions.ParseError("Invalid token")


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs["refresh"] = self.context["request"].COOKIES.get("refresh")
        if attrs["refresh"]:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                "No valid token found in cookie 'refresh'"
            )


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    """
    Refresh JWT Token.

    This view allows authenticated users to refresh their JWT access token using a refresh token stored in cookies.
    If the refresh token is valid, a new access token is returned, and the refresh token cookie is updated.

    **Example request**:

        POST /auth/token/refresh

    **Request body example**:

        {
            "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
        }

    **Response**:

    - `200 OK`: Token refreshed successfully.

    **Response body example**:

        {
            "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
        }

    **Cookies set**:

    - `refresh_token`: The refresh token cookie is updated.

    **Response headers**:

    - `X-CSRFToken`: CSRF token for subsequent requests.
    """
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                value=response.data["refresh"],
                expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
                secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
                httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    """
    Retrieve User Information.

    This endpoint allows authenticated users to retrieve their user profile information.

    **Example request**:

        GET /auth/user

    **Response**:

    - `200 OK`: User information retrieved successfully.

    **Response body example**:

        {
            "id": 1,
            "email": "user@example.com",
            "name": "John Doe"
        }

    **Error response**:

    - `404 Not Found`: User does not exist.
    """
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    serializer = serializers.UserSerializer(user)
    return response.Response(serializer.data)


@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def getSubscriptions(request):
    """
    Retrieve User Subscriptions.

    This endpoint allows authenticated users to retrieve their active Stripe subscriptions.

    **Example request**:

        GET /auth/subscriptions

    **Response**:

    - `200 OK`: Subscriptions retrieved successfully.

    **Response body example**:

        {
            "subscriptions": [
                {
                    "id": "sub_12345",
                    "start_date": "2023-01-01",
                    "plan": "world_individual"
                }
            ]
        }

    **Error response**:

    - `404 Not Found`: User or subscriptions not found.
    """
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    subscriptions = []
    customer = stripe.Customer.search(query=f'email:"{user.email}"')
    if "data" in customer:
        if len(customer["data"]) > 0:
            for _customer in customer["data"]:
                subscription = stripe.Subscription.list(customer=_customer["id"])
                if "data" in subscription:
                    if len(subscription["data"]) > 0:
                        for _subscription in subscription["data"]:
                            if _subscription["status"] == "active":
                                subscriptions.append(
                                    {
                                        "id": _subscription["id"],
                                        "start_date": str(_subscription["start_date"]),
                                        "plan": prices[_subscription["plan"]["id"]],
                                    }
                                )

    return response.Response({"subscriptions": subscriptions}, 200)
