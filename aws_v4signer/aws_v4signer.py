import datetime
import hashlib
import hmac

ENCODING = 'utf-8'
VERSION = 'AWS4'
AWS4_REQUEST = 'aws4_request'
DATE_STAMP_FORMAT = '%Y%m%d'


class AWSV4Signer:

    @staticmethod
    def sign(key, message):
        return hmac.new(key, message.encode(ENCODING), hashlib.sha256).digest()

    @staticmethod
    def get_signature_key(key, date, region, service):
        k_date = AWSV4Signer.sign((VERSION + key).encode(ENCODING), date)
        k_region = AWSV4Signer.sign(k_date, region)
        k_service = AWSV4Signer.sign(k_region, service)
        k_signing = AWSV4Signer.sign(k_service, AWS4_REQUEST)
        return k_signing


if __name__ == '__main__':

    print(AWSV4Signer.sign(''.encode(ENCODING), ''))

    print(AWSV4Signer.get_signature_key('YOUR_AWS_SECRET_KEY',
                                        datetime.datetime.utcnow().strftime(DATE_STAMP_FORMAT),
                                        'YOUR_AWS_REGION',
                                        'YOUR_AWS_SERVICE'))
