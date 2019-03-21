import unittest
from aws_v4signer.aws_v4signer import AWSV4Signer


class AWSV4SignerTests(unittest.TestCase):

    def test_class_exists(self):
        v4_signer = AWSV4Signer
        self.assertTrue(v4_signer.__name__ == 'AWSV4Signer')
