#coding:utf-8
import os
import hashlib
import hmac
import logging

import flask
import util


SIGNING_KEY_ENV_VAR = "SIGNING_KEY"
VALIDATION_TOKEN_ENV_VAR = "VALIDATION_TOKEN"


app = flask.Flask(__name__)
app.config.update(
    signing_key=os.environ.get(SIGNING_KEY_ENV_VAR, ""),
    validation_token=os.environ.get(VALIDATION_TOKEN_ENV_VAR, "")
)

# Logging configuration
stderr_log_handler = logging.StreamHandler()
app.logger.addHandler(stderr_log_handler)
app.logger.setLevel(logging.DEBUG)


@app.route("/", methods=("GET",))
def webhook_get_handler():
    return flask.Response(status=200)


@app.route("/", methods=("POST",))
def webhook_post_handler():
    payload = flask.request.json
    app.logger.info("Received Notification '%s' for: '%s' on '%s'", payload["eventId"],
                    payload["eventName"], payload["data"]["SCALR_SERVER_ID"])

    # Here, you should do whatever you feel like doing with the payload

    return flask.Response(status=202)


@app.before_request
def log_request():
    app.logger.debug("Received request: %s %s", flask.request.method, flask.request.url)


@app.before_request
def validate_request_signature():
    if flask.request.method == "GET":
        return

    signing_key = app.config["signing_key"]
    if signing_key is None:
        app.logger.warning("No signing key found. Request will not be checked for authenticity.")
        return

    payload = flask.request.get_data()
    date = flask.request.headers.get("Date", "")
    message_hmac = hmac.HMAC(signing_key, payload + date, hashlib.sha1)

    local_signature = message_hmac.hexdigest()
    remote_signature = flask.request.headers.get("X-Signature", "")

    if not util.constant_time_compare(local_signature, remote_signature):
        app.logger.warning("Detected invalid signature, aborting.")
        return flask.Response(status=403)


@app.before_request
def validate_json_payload():
    if flask.request.method == "GET":
        return
    if flask.request.json is None:
        return flask.Response(status=400)


@app.after_request
def add_webhook_token(response):
    validation_token = app.config.get("validation_token")
    if validation_token is not None:
        response.headers["X-Validation-Token"] = validation_token
    return response


if __name__ == '__main__':
    app.run(debug=True)
