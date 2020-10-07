import os
import re
import base64
import datetime
import json
import logging
import requests
from retry import retry
import config

from google.cloud import storage, kms_v1, secretmanager_v1
from requests_oauthlib import OAuth1

logging.basicConfig(level=logging.INFO)


class Surveys:
    """
    Get surveys
    """

    def __init__(self, bucket, consumer_key):
        self.bucket = bucket
        self.consumer_secret = self.get_secret()
        self.storage_client = storage.Client()
        self.storage_bucket = storage.Client().get_bucket(bucket)
        self.bucket_name = bucket
        self.oauth_1 = OAuth1(
            consumer_key,
            self.consumer_secret,
            signature_method='HMAC-SHA1'
        )
        self.headers = {}
        self.folders = {}
        self.folder_forms = {}

    def store_blob(self, path, data, content_type):
        """
        Store blob into Cloud Storage
        :param content_type: e.g application/json
        :param path: Prefix where data will be stored e.g registrations
        :param data: Data to be stored
        """
        logging.debug(
            f"Storing to Google Storage [{self.bucket_name,}:{path}]]"
        )
        blob = self.storage_bucket.blob(path)
        blob.upload_from_string(data, content_type)

    @staticmethod
    def get_authentication_secret():
        """
        Get authentication secret
        :return:
        """
        authentication_secret_encrypted = base64.b64decode(
            os.environ['AUTHENTICATION_SECRET_ENCRYPTED']
        )
        kms_client = kms_v1.KeyManagementServiceClient()
        crypto_key_name = kms_client.crypto_key_path_path(os.environ['PROJECT_ID'], os.environ['KMS_REGION'],
                                                          os.environ['KMS_KEYRING'],
                                                          os.environ['KMS_KEY'])
        decrypt_response = kms_client.decrypt(crypto_key_name, authentication_secret_encrypted)
        return decrypt_response.plaintext.decode("utf-8").replace('\n', '')

    @staticmethod
    def get_secret():
        """
        Get secret from secret manager
        :return:
        """

        client = secretmanager_v1.SecretManagerServiceClient()

        secret_name = client.secret_version_path(
            os.environ['PROJECT_ID'],
            os.environ['SECRET_NAME'],
            'latest')

        response = client.access_secret_version(secret_name)
        payload = response.payload.data.decode('UTF-8')

        return payload

    def get_api_data(self, url):
        """
        Get request with OAUTH 1 Authentication
        :param url:
        :return:
        """
        return requests.get(url, auth=self.oauth_1, headers=self.headers)

    def retrieve_api_data(self, url):
        """
        Get request with OAUTH 1 Authentication
        :param url: API Url to post to
        :return:
        """
        data = {
            "sort": [
                {
                    "key": "info.date",
                    "direction": -1
                }
            ],
            "pageSize": 500,
            "query": []
        }
        self.headers['Content-Type'] = 'application/json'
        return requests.post(
            url,
            auth=self.oauth_1,
            data=json.dumps(data),
            json=json.dumps(data),
            headers=self.headers
        )

    @staticmethod
    def get_dashed_string(text):
        """
        Return a lower case string without special characters. e.g
        'TSSR T-Mobile (standard) Kopieer' =>> 'tssr_t_mobile_standard_kopieer'
        :param text:
        :return:
        """
        text = re.sub(r"[^\w\s]", '', text)
        text = re.sub(r"\s+", '_', text)
        return text.lower()

    def get_destination_path(self, form_prefix, content_description):
        """
        Get destination path
        :param content_description: Filled or Non field form content
        :param form_prefix: Folder name
        :return:
        """
        now = datetime.datetime.utcnow()
        dated_directory = '%04d/%02d/%02d' % (now.year, now.month, now.day)
        timestamp = '%04d%02d%02dT%02d%02d%02dZ' % (now.year, now.month, now.day,
                                                    now.hour, now.minute, now.second)
        destination_path = \
            f'source/{content_description}/' \
            f'{self.get_dashed_string(form_prefix)}/{dated_directory}/{timestamp}.json'

        return destination_path

    @retry(ConnectionError, tries=3, delay=2, logging=None)
    def get_folders(self):
        """
        Get all folders details e.g Folder forms and extra information
        >> applicationId -> form_id, >> properties[folder] -> name and id

        """
        for customer_id in config.CUSTOMER_IDS:
            folders_data_response = self.get_api_data(
                f"{config.MORE_APP_API}/forms/customer/{customer_id}/folders?expand=forms",
            )

            if not 200 <= folders_data_response.status_code <= 299:
                raise ConnectionError(f"An error occured when retrieving the surveys: {folders_data_response.json()}")

            # Folder Form Properties
            try:
                for item in folders_data_response.json():
                    self.folders[item['id']] = item['forms']
            except ValueError:
                logging.error(f'Not a valid json response [{folders_data_response.text}]')
                pass
        self.store_blob(
            self.get_destination_path('folders', 'surveys'), json.dumps(self.folders), content_type='application/json')

    def get_surveys_registrations(self):
        """
        Retrieve all folders and their contents of a requested customer
        """
        self.get_folders()

        for key, value in self.folders.items():
            for form in value:
                for customer_id in config.CUSTOMER_IDS:
                    form_data_response = None
                    current_page = 0
                    current_result = None

                    error_occurred = False

                    while current_page == 0 or current_result.get("elements", []):
                        url = \
                            f"{config.MORE_APP_API}/customers/" \
                            f"{customer_id}/forms/{form['id']}" \
                            f"/submissions/filter/{current_page}"

                        response = self.retrieve_api_data(url)
                        if not 200 <= response.status_code <= 299:
                            error_occurred = True
                            logging.info(
                                f"An error occurred when retrieving page {current_page} from {url} with response {response.json()}.")
                        else:
                            current_result = response.json()
                            logging.info(f"Retrieved page {current_page} with " +
                                         f"{len(current_result.get('elements', []))} elements from {url}")

                            if not form_data_response:
                                form_data_response = current_result
                            elif current_result.get("elements", []):
                                form_data_response["elements"].extend(current_result["elements"])

                            current_page += 1
                    if error_occurred:
                        pass
                    else:
                        self.store_blob(
                            path=self.get_destination_path(form['id'], 'registrations'),
                            data=json.dumps(form_data_response),
                            content_type='application/json'
                        )


surveys = Surveys(
    bucket=config.GOOGLE_STORAGE_BUCKET,
    consumer_key=config.CONSUMER_KEY,
)


def get_surveys_registrations(request):
    """
    Get all surveys for all customers and their contents into storage
    :return:
    """
    logging.info(request)
    return surveys.get_surveys_registrations()


if __name__ == "__main__":
    logging.info("Running local test")
    surveys.get_surveys_registrations()
