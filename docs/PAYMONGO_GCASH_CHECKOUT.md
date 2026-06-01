# PayMongo GCash Checkout

This document covers the active PayMongo checkout foundation for captive portal Product Items.

## Purpose

Customers can choose a Product Item in the captive portal and pay through PayMongo hosted checkout, starting with GCash. The system creates a local payment order before redirecting the customer to PayMongo.

## Required Settings

Configure System Settings -> Payments:

- Enable payments.
- Select active mode: Test or Live.
- Save the matching PayMongo public key and secret key.
- Enable GCash in payment methods.
- Set success and cancel URLs back to the portal.
- Create a PayMongo webhook endpoint for `/api/payments/paymongo/webhook` and save the webhook signing secret under the matching Test Keys or Live Keys tab.

Test and live keys are stored separately. Secret keys and webhook signing secrets are never returned to the frontend in plain text.

## Checkout Flow

1. Captive portal loads active Product Items.
2. Customer clicks BUY on a Product Item.
3. The API creates a `payment_orders` row.
4. The API creates a PayMongo hosted checkout session.
5. Customer completes or cancels payment at PayMongo.
6. PayMongo redirects the browser back to the portal.
7. The portal shows order status.
8. Actual access is granted after a verified PayMongo paid status is confirmed by webhook or order reconciliation.

Redirect success alone does not grant internet access unless the backend confirms the PayMongo checkout is paid.

If the customer has saved a verified portal profile, the local payment order stores profile name, email, and contact number. Those values are also sent to PayMongo as sanitized checkout metadata. PayMongo-hosted checkout can still ask for customer information depending on PayMongo's hosted form behavior.

## Webhook Fulfillment

The webhook handler verifies:

- `Paymongo-Signature` is valid for the configured test/live webhook secret.
- Timestamp is within the accepted window.
- Event type is `payment.paid`.
- Paid amount matches the local order amount.

After verification, the system creates a system voucher for the Product Item duration, redeems it for the portal user, and uses the existing Omada/MikroTik authorization path to activate access.

For valid signed webhook requests, the API acknowledges PayMongo with HTTP 200 after recording the event. If local fulfillment fails, the event is saved as `FAILED` for operator review instead of returning HTTP 500 to PayMongo. Invalid or unsigned webhook requests are still rejected.

## Failure Behavior

- Missing webhook secret: checkout can start, but fulfillment cannot complete.
- Signature mismatch: webhook is rejected.
- Amount mismatch: fulfillment is blocked.
- Omada authorization failure: payment remains paid, but fulfillment is marked failed for operator review.
- Valid webhook received but local fulfillment failed: the failure is recorded and the webhook is still acknowledged to prevent PayMongo from disabling delivery.

## Next Phase

Add admin payment order review, reconciliation, manual retry/resolution, refund notes, and live-mode operational checks.
