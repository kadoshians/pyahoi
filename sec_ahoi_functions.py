import threading
import time
from ahoi_connector import APIConnector
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import base64


class SecAPIFunctions():

    def __init__(self, config):
        general = config['GENERAL']
        self.username = general['username']
        self.pin = general['pin']
        self.url = general['url']

        oauth = config['OAUTH']
        self.client_id = oauth['clientID']
        self.client_secret = oauth['clientSecret']
        self.app_secret_iv = oauth['appSecret']
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

    def __gen_reg_token(self, interval):
        while True:
            time.sleep(interval)
            res_dict = self.api_connector.generate_registration_token(self.client_id, self.client_secret)
            self.reg_token = res_dict['access_token']
            interval = int(res_dict['expires_in'])
            print("New reg_token generated")

    def __gen_symmetric_key(self):
        # Generate a simple symmetricKey (AES)
        symmetric_key = get_random_bytes(32)
        return symmetric_key


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
        session_key = base64.urlsafe_b64encode(enc_symmetric_key).decode()

        # Encode JSON to create header value
        header_template = "{\"publicKeyId\":\"%s\",\"sessionKey\":\"%s\",\"keySpecification\":\"AES\"}" % (public_key_id,
                                                                                                          session_key)
        base64_encoded_json_header = base64.urlsafe_b64encode(header_template.encode()).decode()

        # Get and extract installation ID with session key
        enc_installation_id = self.api_connector.user_registration_x_auth(self.reg_token, base64_encoded_json_header)
        enc_installation_id = base64.urlsafe_b64decode(enc_installation_id + "==")

        iv = 16 * b'\00'
        cipher_aes = AES.new(self.session_key, AES.MODE_CBC, iv=iv)
        installation_id = unpad(cipher_aes.decrypt(enc_installation_id), AES.block_size)

        # Fetch and decrypt banking token
        res_dict = self.api_connector.get_banking_token_x_auth(installation_id, self.client_id, self.client_secret, self.app_secret_iv, self.app_secret_key, base64_encoded_json_header)
        banking_token = res_dict['access_token']

        # Get providerID
        providers_list = self.api_connector.get_providers(banking_token)
        provider_id = providers_list[0]['id']

        # Create an access
        self.api_connector.create_new_access_x_auth(banking_token, self.username, self.pin, provider_id, self.session_key, base64_encoded_json_header)
