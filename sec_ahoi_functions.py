import threading
import time
from ahoi_connector import APIConnector
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import base64
from flask import Flask, request
import configparser

app = Flask(__name__)

class SecAPIFunctions():

    def __init__(self, config):
        general = config['GENERAL']
        #self.username = general['username']
        #self.pin = general['pin']
        self.url = general['url']

        oauth = config['OAUTH']
        self.client_id = oauth['clientID']
        self.client_secret = oauth['clientSecret']
        self.app_secret_iv = oauth['appSecret']
        self.app_secret_key = oauth['appSecretKey']
        self.symmetric_key = self.__gen_symmetric_key()

        self.api_connector = APIConnector(self.url)

        # Get the reg_token for the first time
        res_dict = self.api_connector.generate_registration_token(self.client_id, self.client_secret)
        self.reg_token = res_dict['access_token']
        reg_interval = int(res_dict['expires_in'])

        # Start a daemon to check the validity of the reg_token
        thread = threading.Thread(target=self.__gen_reg_token, args=([reg_interval]))
        thread.daemon = True
        thread.start()

        # Get public_api_key and id as well as X-Ahoi-Session-Security header
        self.public_api_key, self.public_api_key_id = self.__get_public_key_and_id()
        self.enc_json_header_base64 = self.__get_session_security_header()

        # Get the installation_id for the application
        self.installation_id = self.get_installation_id()

        # Get the bank_token for the first time
        res_dict = self.api_connector.get_banking_token_x_auth(self.installation_id, self.client_id, self.client_secret, self.app_secret_iv, self.app_secret_key, self.enc_json_header_base64)
        self.banking_token = res_dict['access_token']
        bank_interval = int(res_dict['expires_in'])

        # Start a daemon to check the validity of the bank_token
        thread2 = threading.Thread(target=self.__gen_bank_token, args=([bank_interval]))
        thread2.daemon = True
        thread2.start()

    def __gen_reg_token(self, interval):
        while True:
            time.sleep(interval-20)
            res_dict = self.api_connector.generate_registration_token(self.client_id, self.client_secret)
            self.reg_token = res_dict['access_token']
            interval = int(res_dict['expires_in'])
            print("New reg_token generated")

    def __gen_bank_token(self, interval):
        while True:
            time.sleep(interval-20)
            res_dict = self.api_connector.get_banking_token_x_auth(self.installation_id, self.client_id,
                                                                   self.client_secret, self.app_secret_iv,
                                                                   self.app_secret_key, self.enc_json_header_base64)
            self.banking_token = res_dict['access_token']
            interval = int(res_dict['expires_in'])
            print("New bank_token generated")

    def __get_public_key_and_id(self):
        # Get public_key
        response = self.api_connector.request_api_public_key(self.reg_token)
        api_public_key = response['publicKey']['value']
        public_key_id = response['keyId']

        return api_public_key, public_key_id

    def __gen_symmetric_key(self):
        # Generate a simple symmetricKey (AES)
        symmetric_key = get_random_bytes(32)
        return symmetric_key

    def __encrypt_symmetric_key(self, public_api_key):
        # Decode and parse public_key
        public_key = base64.urlsafe_b64decode(public_api_key)
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)

        # encrypt symmetric_key with the received public_key
        enc_session_key = cipher_rsa.encrypt(self.symmetric_key)

        # Encode Base64 url-safe
        enc_session_key_base64 = base64.urlsafe_b64encode(enc_session_key).decode()

        return enc_session_key_base64

    def __get_session_security_header(self):
        # Get an X-Ahoi-Session-Security header
        enc_session_key = self.__encrypt_symmetric_key(self.public_api_key)

        # Encode JSON to create header value
        header_template = "{\"publicKeyId\":\"%s\",\"sessionKey\":\"%s\",\"keySpecification\":\"AES\"}" % (self.public_api_key_id,
                                                                                                          enc_session_key)
        enc_json_header_base64 = base64.urlsafe_b64encode(header_template.encode()).decode()

        return enc_json_header_base64

    def x_auth(self):
        self.public_api_key, self.public_api_key_id = self.__get_public_key_and_id()
        self.symmetric_key = self.__gen_symmetric_key()
        self.enc_json_header_base64 = self.__get_session_security_header()

    def get_installation_id(self):
        # Get and extract installation ID with session key
        enc_installation_id = self.api_connector.user_registration_x_auth(self.reg_token, self.enc_json_header_base64)
        enc_installation_id = base64.urlsafe_b64decode(enc_installation_id + "==")

        iv = 16 * b'\00'
        cipher_aes = AES.new(self.symmetric_key, AES.MODE_CBC, iv=iv)
        installation_id = unpad(cipher_aes.decrypt(enc_installation_id), AES.block_size)

        return installation_id

    def get_transactions_x_auth(self, iban, username, pin, start, end):
        # Refresh all x_auth dependencies
        self.x_auth()

        # Get providerID
        providers_list = self.api_connector.get_providers(self.banking_token)
        provider_id = providers_list[0]['id']

        # Create an access
        in_progress = True
        while in_progress:
            task_id, state = self.api_connector.create_new_access_x_auth(self.banking_token, username,
                                                                         pin, provider_id, self.symmetric_key,
                                                                         self.enc_json_header_base64)
            in_progress = (state == 'IN_PROGRESS')
        print(f"taskId: {task_id}, state: {state}")

        # Fetch state
        in_progress = True
        while in_progress:
            response = self.api_connector.fetch_state_of_task(self.banking_token, task_id)
            in_progress = (response['state'] == 'IN_PROGRESS')
            time.sleep(2)
        access_id = response['accessId']
        print(f"accessId: {access_id}")

        # Fetch transactions for specific iban and time range
        accounts = self.api_connector.list_accounts(self.banking_token, access_id)

        transactions = dict()
        for account in accounts:
            account_id = account['id']
            iban_tmp = account['iban']

            if iban_tmp == iban:
                # Refresh account to get the newest transactions
                self.api_connector.refresh_account(self.banking_token, access_id, account_id)

                # Use iban for identification because account_id is not static
                transactions[iban] = self.api_connector.list_transactions_for_account(self.banking_token, access_id,
                                                                                      account_id, 1000, 0, start, end)
        return transactions

@app.route('/ahoi-sec/transactions/<string:iban>', methods=['GET'])
def get_transactions(iban):
    if request.method == 'GET':
        username = request.args.get('username')
        pin = request.args.get('pin')
        start = request.args.get('start')
        end = request.args.get('end')
        transactions = api_functions.get_transactions_x_auth(iban, username, pin, start, end)
        return transactions

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('conf.ini')
    api_functions = SecAPIFunctions(config)
    app.debug = True
    app.run(host='0.0.0.0', port=4996)