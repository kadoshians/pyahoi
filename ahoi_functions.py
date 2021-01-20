import time
import threading
import time
from ahoi_connector import APIConnector
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import  RSA
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss
from Crypto import Random
from Crypto.Util.Padding import unpad
import base64
import binascii


class APIFunctions():

    def __init__(self, config):
        general = config['GENERAL']
        self.username = general['username']
        self.pin = general['pin']
        self.url = general['url']

        oauth = config['OAUTH']
        self.client_id = oauth['clientID']
        self.client_secret = oauth['clientSecret']
        self.app_secret = oauth['appSecret']
        self.app_secret_key = oauth['appSecretKey']
        self.session_key = self.__gen_symmetric_key()

        self.api_connector = APIConnector(self.url)

        # get the reg_token for the first time
        res_dict = self.api_connector.generate_registration_token(self.client_id, self.client_secret)
        self.reg_token = res_dict['access_token']
        reg_interval = int(res_dict['expires_in'])

        # start a daemon to check the validity of the reg_token
        thread = threading.Thread(target=self.__gen_reg_token, args=([reg_interval]))
        thread.daemon = True
        thread.start()

        # get the installation_id for the application
        self.installation_id = self.api_connector.user_registration(self.reg_token)

        # get the bank_token for the first time
        res_dict = self.api_connector.get_banking_token(self.installation_id, self.client_id, self.client_secret)
        self.bank_token = res_dict['access_token']
        bank_interval = int(res_dict['expires_in'])

        # start a daemon to check the validity of the bank_token
        thread2 = threading.Thread(target=self.__gen_bank_token, args=([bank_interval]))
        thread2.daemon = True
        thread2.start()

    def __gen_reg_token(self, interval):
        while True:
            time.sleep(interval)
            res_dict = self.api_connector.generate_registration_token(self.client_id, self.client_secret)
            self.reg_token = res_dict['access_token']
            interval = int(res_dict['expires_in'])
            print("New reg_token generated")

    def __gen_bank_token(self, interval):
        while True:
            time.sleep(interval)
            res_dict = self.api_connector.get_banking_token(self.installation_id, self.client_id, self.client_secret)
            self.bank_token = res_dict['access_token']
            interval = int(res_dict['expires_in'])
            print("New bank_token generated")

    def __gen_symmetric_key(self):
        # Generate a simple symmetricKey (AES)
        symmetric_key = get_random_bytes(32)
        return symmetric_key


    def get_transactions(self):
        providers_list = self.api_connector.get_providers(self.bank_token)
        provider_id = providers_list[0]['id']
        print(f"providerId: {provider_id}")

        in_progress = True
        while in_progress:
            task_id, state = self.api_connector.create_new_access(self.bank_token, self.username, self.pin, provider_id)
            in_progress = (state == 'IN_PROGRESS')
        print(f"taskId: {task_id}, state: {state}")

        in_progress = True
        while in_progress:
            response = self.api_connector.fetch_state_of_task(self.bank_token, task_id)
            in_progress = (response['state'] == 'IN_PROGRESS')
            time.sleep(2)
        access_id = response['accessId']
        print(f"accessId: {access_id}")

        accounts = self.api_connector.list_accounts(self.bank_token, access_id)
        print(accounts)

        transactions = dict()
        for account in accounts:
            account_id = account['id']
            iban = account['iban']

            # use iban for identification because account_id is not static
            transactions[iban] = self.api_connector.get_transactions(self.bank_token, access_id, account_id)

        return transactions

    def test_x_auth(self):

        # Get public_key
        response = self.api_connector.request_api_public_key(self.reg_token)

        api_public_key = response['publicKey']['value']
        public_key_id = response['keyId']

        # Decode and parse public_key
        public_key = base64.urlsafe_b64decode(api_public_key)

        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)

        # Encrypt symmetric_key with the received public_key
        enc_symmetric_key = cipher_rsa.encrypt(self.session_key)


        # Encode Base64 url-safe
        session_key = base64.urlsafe_b64encode(enc_symmetric_key)

        # Encode JSON to create header value
        header_template = "{\"publicKeyId\":\"%s\",\"sessionKey\":\"%s\",\"keySpecification\":\"AES\"}" % (public_key_id,
                                                                                                          session_key)
        base64_encoded_json_header = base64.urlsafe_b64encode(header_template.encode())

        enc_installation_id = self.api_connector.user_registration_x_auth(self.reg_token, base64_encoded_json_header)

        #enc_installation_id = base64.urlsafe_b64decode(enc_installation_id + "==")

        #iv = 16 * b'\00'
        #cipher_aes = AES.new(self.session_key, AES.MODE_CBC, iv=iv)
        #i_installation_id = cipher_aes.decrypt(enc_installation_id[:-4])

        res_dict = self.api_connector.get_banking_token_x_auth(enc_installation_id, self.client_id, self.client_secret,
                                                              self.app_secret, self.app_secret_key, base64_encoded_json_header)
        print(res_dict)
        sec_bank_token = res_dict['access_token']

        providers_list = self.api_connector.get_providers(self.bank_token)
        print(providers_list)
        provider_id = providers_list[0]['id']
        print(sec_bank_token)
        print(self.bank_token)

        self.api_connector.create_new_access_x_auth(sec_bank_token, self.username, self.pin, provider_id, enc_installation_id, self.session_key, base64_encoded_json_header)
