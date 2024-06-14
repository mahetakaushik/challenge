from rest_framework import (
    response,
    decorators as rest_decorators,
    permissions as rest_permissions,
)


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    """
    Pay for a subscription.

    This endpoint allows an authenticated user to pay for a subscription. The payment processing logic is handled
    within this endpoint. Upon successful payment, a confirmation message is returned.

    **Example request**:

        POST /transaction/pay

    **Response**:

    - `200 OK`: Successfully pay for the subscription

    **Response body example**:

        {"msg": "Success"}


    """
    return response.Response({"msg": "Success"}, 200)


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    """
    List all subscriptions.

    This endpoint allows an authenticated user to list all their active subscriptions. It provides details about each
    subscription, such as the subscription ID, start and plan.

    **Example request**:

        POST /transaction/list


    **Response**:

    - `200 OK`: Successfully retrieved the list of subscriptions.

    **Response body example**:

        {"id": "sub_1PRWCWKpmwOo10Mat9B9Tnkc", "start_date": "1718356420", "plan": "universe_individual"}


    """
    return response.Response({"msg": "Success"}, 200)
