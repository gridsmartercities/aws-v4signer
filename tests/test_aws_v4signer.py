import unittest
from aws_v4signer.aws_v4signer import AWSV4Signer, ENCODING


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
