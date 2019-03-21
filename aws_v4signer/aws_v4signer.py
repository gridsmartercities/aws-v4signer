import datetime
import hashlib
import hmac

VERSION = 'AWS4'
ALGORITHM = 'AWS4-HMAC-SHA256'
SIGNED_HEADERS = 'host;x-amz-date'
AWS4_REQUEST = 'aws4_request'
ENCODING = 'utf-8'
AMZ_DATE_FORMAT = '%Y%m%dT%H%M%SZ'
DATE_STAMP_FORMAT = '%Y%m%d'


class AWSV4Signer:

    def __init__(self, aws_key, aws_secret, aws_region, aws_service, aws_host):  # pylint:disable=too-many-arguments
        self._key = aws_key
        self._secret = aws_secret
        self._region = aws_region
        self._service = aws_service
        self._host = aws_host

    @property
    def key(self):
        return self._key

    @property
    def secret(self):
        return self._secret

    @property
    def region(self):
        return self._region

    @property
    def service(self):
        return self._service

    @property
    def host(self):
        return self._host

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

    def get_headers(self, uri, method, querystring, body):
        now = datetime.datetime.utcnow()
        amz_date = now.strftime(AMZ_DATE_FORMAT)
        date_stamp = now.strftime(DATE_STAMP_FORMAT)

        canonical_request = method + '\n' \
            + uri + '\n' \
            + querystring + '\n' \
            + 'host:' + self._host + '\n' \
            + 'x-amz-date:' + amz_date + '\n' \
            + '\n' \
            + SIGNED_HEADERS + '\n' \
            + hashlib.sha256(body.encode(ENCODING)).hexdigest()

        credential_scope = date_stamp + '/' + self._region + '/' + self._service + '/' + AWS4_REQUEST

        string_to_sign = ALGORITHM + '\n' \
            + amz_date + '\n' \
            + credential_scope + '\n' \
            + hashlib.sha256(canonical_request.encode(ENCODING)).hexdigest()

        signing_key = AWSV4Signer.get_signature_key(self._secret, date_stamp, self._region, self._service)

        authorization_header = ALGORITHM + ' ' \
            + 'Credential=' + self._key + '/' + credential_scope + ', ' \
            + 'SignedHeaders=' + SIGNED_HEADERS + ', ' \
            + 'Signature=' + hmac.new(signing_key, string_to_sign.encode(ENCODING), hashlib.sha256).hexdigest()

        return {
            'x-amz-date': amz_date,
            'Authorization': authorization_header
        }
