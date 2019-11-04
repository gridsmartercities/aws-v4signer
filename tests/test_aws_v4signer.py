import json
import unittest
from aws_v4signer.aws_v4signer import AWSV4Signer, ENCODING, get_v4_headers


class AWSV4SignerTests(unittest.TestCase):

    def test_can_create_signer_with_parameters(self):
        key = "YOUR_AWS_KEY_ID"
        secret = "YOUR_AWS_KEY_SECRET"  # nosec
        region = "YOUR_AWS_REGION"
        service = "YOUR_AWS_SERVICE"
        host = "YOUR_AWS_HOST"

        v4_signer = AWSV4Signer(key, secret, region, service, host)

        self.assertEqual(v4_signer.key, key)
        self.assertEqual(v4_signer.secret, secret)
        self.assertEqual(v4_signer.region, region)
        self.assertEqual(v4_signer.service, service)
        self.assertEqual(v4_signer.host, host)

    def test_can_sign_message_with_a_key(self):
        key = "test"
        message = "test message"

        signed_message = AWSV4Signer.sign(key.encode(ENCODING), message)

        self.assertEqual(signed_message, b"nv\xe21\x0b\xcd\n\xed{\xa4\xef\x80\x007\x9e\xae\x0f\xe0\x8b\x05*\x90\xdd"
                                         b"\t\xac\x0b\x12\xb4f\xc024")

    def test_can_return_signature_key(self):
        key = "YOUR_AWS_KEY_ID"
        date = "20190322"
        region = "YOUR_AWS_REGION"
        service = "YOUR_AWS_SERVICE"

        signature_key = AWSV4Signer.get_signature_key(key, date, region, service)

        self.assertEqual(signature_key, b"\x02\xad\x17$\x9bPV\x1f\xeed\xc9\xc9\x16wk\xfa|\xcaC\xca\x8a\x9eW\xb9\x9b"
                                        b"\xdc2\x80h\t\x80\xcb")

    def test_can_return_headers(self):
        key = "YOUR_AWS_KEY_ID"
        secret = "YOUR_AWS_KEY_SECRET"  # nosec
        region = "YOUR_AWS_REGION"
        service = "YOUR_AWS_SERVICE"
        host = "YOUR_AWS_HOST"

        v4_signer = AWSV4Signer(key, secret, region, service, host)

        uri = ""
        method = ""
        querystring = ""
        body = json.dumps({})

        headers = v4_signer.get_headers(uri, method, querystring, body)

        self.assertTrue(headers["Authorization"])
        self.assertTrue(headers["x-amz-date"])

    def test_can_return_headers_without_optionals(self):
        key = "YOUR_AWS_KEY_ID"
        secret = "YOUR_AWS_KEY_SECRET"  # nosec
        region = "YOUR_AWS_REGION"
        service = "YOUR_AWS_SERVICE"
        host = "YOUR_AWS_HOST"

        v4_signer = AWSV4Signer(key, secret, region, service, host)
        headers = v4_signer.get_headers("", "")

        self.assertTrue(headers["Authorization"])
        self.assertTrue(headers["x-amz-date"])

    def test_can_use_method_to_get_headers(self):
        headers = get_v4_headers("", "", "", "", "", "", "", "", "")
        self.assertTrue(headers["Authorization"])
        self.assertTrue(headers["x-amz-date"])

    def test_can_use_method_to_get_headers_no_optionals(self):
        headers = get_v4_headers("", "", "", "", "", "", "")
        self.assertTrue(headers["Authorization"])
        self.assertTrue(headers["x-amz-date"])