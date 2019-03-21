import hashlib
import hmac

ENCODING = 'utf-8'


class AWSV4Signer:  # pylint:disable=too-few-public-methods

    @staticmethod
    def sign(key, message):
        return hmac.new(key, message.encode(ENCODING), hashlib.sha256).digest()


# if __name__ == '__main__':
#
#     print(AWSV4Signer.sign(''.encode(ENCODING), ''))
