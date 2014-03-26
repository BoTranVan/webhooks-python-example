#coding:utf-8
import os
import hashlib
import hmac

import unittest

import app



class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()

        app.app.config.update(
            validation_token=None,
            signing_key=None
        )

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data", "webhook.json")) as f:
            self.webhook_payload = f.read()

    def test_no_token(self):
        r = self.client.get("/")
        self.assertEqual(r.headers.get("X-Validation-Token"), None)
        self.assertEqual(r.status_code, 200)

    def test_return_token(self):
        app.app.config.update(validation_token="Hello World!")

        r = self.client.get("/")
        self.assertEqual(r.headers["X-Validation-Token"], "Hello World!")
        self.assertEqual(r.status_code, 200)

    def test_no_json(self):
        r = self.client.post("/")
        self.assertEqual(r.status_code, 400)

    def test_no_signature(self):
        r = self.client.post("/", content_type="application/json", data=self.webhook_payload)
        self.assertEqual(r.status_code, 202)

    def test_invalid_signature(self):
        app.app.config.update(signing_key="k")

        r = self.client.post("/", content_type="application/json", data=self.webhook_payload)
        self.assertEqual(r.status_code, 403)

        r = self.client.post("/", content_type="application/json", headers={"X-Signature": "k", "Date": "d"},
                             data=self.webhook_payload)
        self.assertEqual(r.status_code, 403)

    def test_valid_signature(self):
        key = "k"
        date = "123"
        signature = hmac.HMAC(key, self.webhook_payload + date, hashlib.sha1).hexdigest()

        app.app.config.update(signing_key=key)


        r = self.client.post("/", content_type="application/json", headers={"X-Signature": signature, "Date": date},
                             data=self.webhook_payload)
        self.assertEqual(r.status_code, 202)



if __name__ == '__main__':
    unittest.main()
