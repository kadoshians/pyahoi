import requests
import base64
import json
from datetime import datetime
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import os
import hashlib

class APIConnector:

    def __init__(self, url):
        self.url = url

    # Access
    def list_accesses(self):
        headers = {
            'accept': "application/json"
        }

        res = requests.get(self.url + "/ahoi/api/v2/accesses", headers=headers)

        res_dict = json.loads(res.text)
        return res_dict

    def create_new_access(self, bank_token, username, pin, provider_id):
        headers = {
            'Authorization': 'Bearer ' + bank_token,
            'Content-Type': 'application/json'
        }
        data = "{\"providerId\":\"%s\",\"type\":\"BankAccess\",\"accessFields\":{\"USERNAME\":\"%s\",\"PIN\":\"%s\"}}" %(provider_id, username, pin)

        res = requests.post(self.url + '/ahoi/api/v2/accesses/async', headers=headers, data=data)
        res_dict = json.loads(res.text)
        return res_dict['id'], res_dict['state']

    def create_new_access_x_auth(self, bank_token, username, pin, provider_id, session_key, base64_encoded_json_header):
        iv = 16 * b'\x00'
        cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)

        username = username.encode('UTF-8')
        pin = pin.encode('UTF-8')
        print(pin)
        print('username len ' + str(len(username)))
        username_padded = username + (AES.block_size - (len(username) % AES.block_size)) * b'\x00'
        print(username_padded)
        pin_padded = pin + (AES.block_size - (len(pin) % AES.block_size)) * b'\x00'
        print(pin_padded)
        enc_username = cipher.encrypt(username_padded)
        ## Anschauen
        enc_pin = cipher.encrypt(pin_padded)

        enc_username_base64 = base64.urlsafe_b64encode(enc_username).decode()
        enc_pin_base64 = base64.urlsafe_b64encode(enc_pin).decode()
        print(len(enc_pin_base64))
        print(enc_pin_base64)
        print(enc_pin_base64[:5])

        headers = {
            'Authorization': 'Bearer ' + bank_token,
            'X-Ahoi-Session-Security': base64_encoded_json_header,
            'Content-Type': 'application/json'

        }
        data = "{\"type\":\"BankAccess\",\"providerId\":\"%s\",\"accessFields\":{\"USERNAME\":\"%s\",\"PIN\":\"%s\"}}" %(provider_id, enc_username_base64, enc_pin_base64[:5])

        res = requests.post(self.url + '/ahoi/api/v2/accesses/async', headers=headers, data=data)
        res_dict = json.loads(res.text)
        print(res_dict)
        print("Access created " + str(res))
        #return res_dict['id'], res_dict['state']

    def get_access(self, bank_token, access_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + "/ahoi/api/v2/accesses/" + access_id, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def delete_access(self, bank_token, access_id):
        headers = {'authorization': "Bearer " + bank_token}

        res = requests.delete(self.url + "/ahoi/api/v2/accesses/" + access_id, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def update_access(self, bank_token, access_id, username, pin):
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        data = {
            'grant_type': 'client_credentials',
            'username': username,
            'password': pin
        }

        res = requests.put(self.url + f"/ahoi/api/v2/accesses/{access_id}/async", data=data, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Account
    def list_accounts(self, bank_token, access_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_account(self, bank_token, account_id, access_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def delete_account(self, bank_token, access_id, account_id):
        headers = {
            'authorization': "Bearer " + bank_token
            }

        res = requests.delete(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def refresh_account(self, bank_token, access_id, account_id):
        headers = {
            'authorization': "Bearer " + bank_token
        }

        res = requests.put(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/refresh", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def update_account_name(self, access_id, account_id, account_name):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer <BEARER_TOKEN>"
        }

        res = requests.put(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/userdefinedname/{account_name}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Authorization methods
    def list_all_authorization_method(self, bank_token, access_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/authorizationmethods", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_default_authorization_method(self, bank_token, access_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/authorizationmethods/default", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def set_default_authorization_method(self, bank_token, access_id, method_id, method_type, version, name):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        data = "{\"methodId\":\"%s\",\"type\":\"%s\",\"version\":\"%s\",\"name\":\"%s\",\"explanation\":\"\"}" %(method_id, method_type, version, name)

        res = requests.put(self.url + f"/ahoi/api/v2/accesses/{access_id}/authorizationmethods/default", data=data, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def refresh_authorization_method(self, bank_token, access_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.put(self.url + f"/ahoi/api/v2/accesses/{access_id}/authorizationmethods/refresh", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Forecast
    def get_balance_forecast(self, bank_token, access_id, account_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/%{account_id}/forecast", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_forecast_transactions(self, bank_token, access_id, account_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/forecast/transactions",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Provider
    def get_provider(self, bank_token, provider_id):

        headers = {
            'authorization': 'Bearer ' + bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/providers/' + provider_id, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_providers(self, bank_token):
        headers = {
            'authorization': 'Bearer ' + bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/providers/', headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Registration
    def get_banking_token(self, install_id, client_id, client_secret):
        nonce = uuid.uuid4().hex

        current_time = datetime.now().utcnow()
        current_time_string = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4]+'Z'

        x_auth_ahoi_json = "{\"installationId\":\"%s\",\"nonce\":\"%s\",\"timestamp\":\"%s\"}" % (
        install_id, nonce, current_time_string)

        credentials = client_id + ":" + client_secret

        credentials_base64 = base64.b64encode(credentials.encode()).decode()
        x_auth_base64 = base64.urlsafe_b64encode(str(x_auth_ahoi_json).encode()).decode()

        headers = {
            'Authorization': 'Basic ' + credentials_base64,
            'X-Authorization-Ahoi': x_auth_base64,
        }

        res = requests.post(self.url + '/auth/v1/oauth/token?grant_type=client_credentials', headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_banking_token_x_auth(self, install_id, client_id, client_secret, app_secret, app_secret_key, base64_encoded_session_header, session_key):
        nonce = uuid.uuid4().hex

        current_time = datetime.now().utcnow()
        current_time_string = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4]+'Z'

        x_auth_ahoi_json = "{\"installationId\":\"%s\",\"nonce\":\"%s\",\"timestamp\":\"%s\"}" % (
        install_id, nonce, current_time_string)

        credentials = client_id + ":" + client_secret
        credentials_base64 = base64.b64encode(credentials.encode()).decode()

        #key = (app_secret_key.encode()).decode()

        #iv = (app_secret.encode()).decode()

        IV_SIZE = 16  # 128 bit, fixed for the AES algorithm
        KEY_SIZE = 32  # 256 bit meaning AES-256, can also be 128 or 192 bits
        SALT_SIZE = 16  # This size is arbitrary

        #password = app_secret_key.encode()
        #salt = os.urandom(SALT_SIZE)
        #derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
        #                              dklen=IV_SIZE + KEY_SIZE)
        iv = base64.urlsafe_b64decode(app_secret + '==')
        key = base64.urlsafe_b64decode(app_secret_key + '==')
        #key = derived[IV_SIZE:]

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        x_auth_ahoi_json = x_auth_ahoi_json.encode()

        x_auth_ahoi_json_pad = x_auth_ahoi_json + (AES.block_size - (len(x_auth_ahoi_json) % AES.block_size)) * b'\x00'

        enc_x_auth_ahoi_json = cipher.encrypt(x_auth_ahoi_json_pad)

        x_auth_base64 = base64.urlsafe_b64encode(enc_x_auth_ahoi_json).decode()
        print(x_auth_base64[:-2])
        headers = {
            'Authorization': 'Basic ' + credentials_base64,
            'X-Authorization-Ahoi': x_auth_base64,
            'X-Ahoi_Session_Security': base64_encoded_session_header
        }

        res = requests.post(self.url + '/auth/v1/oauth/token?grant_type=client_credentials', headers=headers)
        res_dict = json.loads(res.text)
        print(res_dict)
        print("get banking token " + str(res))
        return res_dict


    def user_registration(self, reg_token):
        headers = {
            'authorization': 'Bearer ' + reg_token
        }

        res = requests.post(self.url + '/ahoi/api/v2/registration', headers=headers)
        res_dict = json.loads(res.text)
        install_id = res_dict['installation']
        return install_id

    def user_registration_x_auth(self, reg_token, base64_encoded_session_header):
        headers = {
            'authorization': 'Bearer ' + reg_token,
            'X-Ahoi-Session-security': base64_encoded_session_header
        }

        res = requests.post(self.url + '/ahoi/api/v2/registration', headers=headers)
        res_dict = json.loads(res.text)
        print("user registered " + str(res))
        print(res_dict)
        install_id = res_dict['installation']
        return install_id

    def delete_user_context_for_token(self, bank_token):
        headers = {'authorization': "Bearer " + bank_token

        }

        res = requests.delete(self.url + "/ahoi/api/v2/registration", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def request_api_jwk_public_key(self, reg_token):
        headers = {
            'authorization': "Bearer " + reg_token
        }

        res = requests.get(self.url + "/ahoi/api/v2/registration/jwk", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def request_api_public_key(self, reg_token):
        headers = {
            'authorization': "Bearer " + reg_token
        }

        res = requests.get(self.url + "/ahoi/api/v2/registration/keys", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def generate_registration_token(self, client_id, client_secret):
        credentials = client_id + ":" + client_secret

        credentials_base64 = base64.b64encode(credentials.encode()).decode()

        headers = {
            'authorization': 'Basic ' + credentials_base64
        }

        res = requests.post(self.url + '/auth/v1/oauth/token?grant_type=client_credentials', headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Security
    def list_securities_for_account(self, bank_token, access_id, account_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/securities", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_security(self, bank_token, access_id, account_id, security_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/securities/{security_id}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Task
    def fetch_state_of_task(self, bank_token, task_id):
        headers = {
            'Authorization': 'Bearer ' + bank_token,
        }

        res = requests.get(self.url + '/ahoi/api/v2/tasks/' + task_id, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def fetch_task_challenge(self, bank_token, task_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/tasks/{task_id}/authorizations/challenges" + bank_token, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def authorize_task(self, bank_token, task_id):
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        data = "{\"response\":\"%s\"}" % (task_id)

        res = requests.put(self.url + f"/ahoi/api/v2/tasks/{task_id}/authorizations/challenges", data=data, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def fetch_authorization_methods(self, bank_token, task_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/tasks/{task_id}/authorizations/methods", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def select_authorization_method(self, bank_token, task_id, method_id, type, version, name, explanation):
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        data = "{\"methodId\":\"%s\",\"type\":\"%s\",\"version\":\"%s\",\"name\":\"%s\",\"explanation\":\"%s\"}" % (
        method_id, type, version, name, explanation)

        res = requests.put(self.url + f"/ahoi/api/v2/tasks/{task_id}/authorizations/methods", data=data, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def fetch_login_information(self, bank_token, task_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/tasks/{task_id}/login", headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def provider_login_information(self, bank_token, task_id, username, pin):
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        data = {
            'grant_type': 'client_credentials',
            'username': username,
            'password': pin
        }

        res = requests.put(self.url + f"/ahoi/api/v2/tasks/{task_id}/login", data=data, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Transaction
    def list_transactions_for_pattern(self, bank_token, access_id, account_id, pattern_id, transaction_limit, offset, start, end):
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactionpatterns/{pattern_id}/transactions?limit={transaction_limit}&offset={offset}&from={start}to={end}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def list_transactions_for_account(self, bank_token, access_id, account_id, transaction_limit, offset, start, end):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactions?limit={transaction_limit}&offset={offset}&from={start}&to={end}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_transactions(self, bank_token, access_id, account_id):
        headers = {
            'authorization': 'Bearer ' + bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/accesses/' + access_id + '/accounts/' + account_id + '/transactions', headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Transaction pattern
    def list_transaction_patterns_for_account(self, bank_token, access_id, account_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactionpatterns",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def create_new_pattern(self, bank_token, access_id, cycle, day, owner, value, currency, account_id, bak_code, kind):
        payload = "{\"id\":\"\",\"state\":\"ACTIVE\",\"cycle\":\"%s\",\"origin\":\"FINDER\",\"day\":\"%s\",\"relatedAccountOwner\":\"%s\",\"amount\":{\"value\":%s\",\"currency\":\"%s\"},\"accountNumber\":\"%s\",\"bankCode\":\"%s\",\"kind\":\"%s\"}" %(cycle, day, owner, value, currency, account_id, bak_code, kind)

        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.post(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactionpatterns",
                     payload, headers)
        res_dict = json.loads(res.text)
        return res_dict

    def get_transaction_pattern(self, bank_token, access_id, account_id, pattern_id):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactionpatterns/{pattern_id}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def delete_transaction_pattern(self, bank_token, access_id, account_id, pattern_id):
        headers = {
            'authorization': "Bearer " + bank_token
        }

        res = requests.delete(self.url +
                     f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactionpatterns/{pattern_id}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    def enable_transaction_pattern(self, bank_token, access_id, account_id, pattern_id, activated):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.put(self.url +
                     f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactionpatterns/{pattern_id}/active/{activated}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Transaction summary
    def list_account_summaries(self, bank_token, access_id, account_id, limit, offset, start, end):
        headers = {
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url +
                     f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transactionsummaries?limit={limit}&offset={offset}&from={start}&to={end}",
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Transfer
    def create_new_transfer(self, bank_token, access_id, account_id, iban, bic, name, value, currency, purpose):
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }
        data = "{\"iban\":\"%s\",\"bic\":\"%s\",\"name\":\"%s\",\"amount\":{\"value\":%s\",\"currency\":\"%s\"},\"purpose\":\"%s\"}" %(iban, bic, name, value, currency, purpose)

        res = requests.post(self.url + f"/ahoi/api/v2/accesses/{access_id}/accounts/{account_id}/transfers", data=data,
                     headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # Collective Transfer
    def create_new_collective_transfer(self, bank_token, access_id, account_id, transfers, is_single_booking):
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "Bearer " + bank_token
        }

        data = "{\"transfers\":%s,\"singleBookingRequested\":%s}" %(transfers, is_single_booking)

        res = requests.post(self.url + f"/ahoi/api/v2/api/v2/accesses/{access_id}/accounts/{account_id}/collectivetransfers",
                     data=data, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict














