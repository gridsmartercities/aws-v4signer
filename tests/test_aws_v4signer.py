import datetime
import unittest
from aws_v4signer.aws_v4signer import AWSV4Signer, ENCODING, DATE_STAMP_FORMAT


class AWSV4SignerTests(unittest.TestCase):

    def test_class_exists(self):
        v4_signer = AWSV4Signer
        self.assertTrue(v4_signer.__name__ == 'AWSV4Signer')

    def test_can_sign_message_with_a_key(self):
        key = 'test'
        message = 'test message'

        signed_message = AWSV4Signer.sign(key.encode(ENCODING), message)

        self.assertEqual(signed_message, b'nv\xe21\x0b\xcd\n\xed{\xa4\xef\x80\x007\x9e\xae\x0f\xe0\x8b\x05*\x90\xdd'
                                         b'\t\xac\x0b\x12\xb4f\xc024')

    def test_can_return_signature_key(self):
        key = 'YOUR_AWS_SECRET_KEY'
        date = datetime.datetime.utcnow().strftime(DATE_STAMP_FORMAT)
        region = 'YOUR_AWS_REGION'
        service = 'YOUR_AWS_SERVICE'

        signature_key = AWSV4Signer.get_signature_key(key, date, region, service)

        self.assertEqual(signature_key, b'k\x92t\xd3\xea>\x9b\xf0\x8f\xe9\xc7:\x0f\xa2\xec\xed!\x91\x19\xf4\x05\xaa'
                                        b'\xde\xc1H\x14.\xd1\x02\xf9h\x1b')
