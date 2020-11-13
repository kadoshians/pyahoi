import requests
import base64
import json
from datetime import datetime
import uuid


class APIConnector:

    def __init__(self, url):
        self.url = url

    # ACCESS
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

        res = requests.put(self.url + f"/ahoi/api/v2/accesses/{access_id}/async", payload=data, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # From Quick Start Basics
    def get_access_state(self, task_id, bank_token):
        headers = {
            'Authorization': 'Bearer ' + bank_token,
        }
        res = requests.get(self.url + '/ahoi/api/v2/tasks/' + task_id, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict

    # ACCOUNT
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

    #def set_default_authorization_method(self, bank_token, access_id):
    #    data = "{\"methodId\":\"%s\",\"type\":\"\",\"version\":\"\",\"name\":\"\",\"explanation\":\"\"}"
    #    data = "{\"providerId\":\"%s\",\"type\":\"BankAccess\",\"accessFields\":{\"USERNAME\":\"%s\",\"PIN\":\"%s\"}}" % (
    #    provider_id, username, pin)
    #    headers = {
    #        'content-type': "application/json",
    #        'authorization': "Bearer " + bank_token
    #    }

     #   res = requests.put(self.url + f"/ahoi/api/v2/accesses/{access_id}/authorizationmethods/default", data=data, headers=headers)
     #   res_dict = json.loads(res.text)
     #   return res_dict

    def generate_registration_token(self, client_id, client_secret, username, pin):
            credentials = client_id + ":" + client_secret

            credentials_base64 = base64.b64encode(credentials.encode()).decode()

            headers = {
                'authorization': 'Basic ' + credentials_base64
            }

            data = {
                'grant_type': 'client_credentials',
                'username': username,
                'password': pin
            }
            res = requests.post(self.url + '/auth/v1/oauth/token?', headers=headers, data=data)

            res_dict = json.loads(res.text)
            reg_token = res_dict['access_token']
            return reg_token

    def user_registration(self, reg_token):
        headers = {
            'authorization': 'Bearer ' + reg_token
        }

        res = requests.post(self.url + '/ahoi/api/v2/registration', headers=headers)
        res_dict = json.loads(res.text)
        install_id = res_dict['installation']
        return install_id

    def get_banking_token(self, install_id, client_id, client_secret, username, pin):
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
            'X-Authorization-Ahoi': x_auth_base64
        }

        data = {
            'grant_type': 'client_credentials',
            'username': username,
            'password': pin
        }

        res = requests.post(self.url + '/auth/v1/oauth/token', headers=headers, data=data)
        res_dict = json.loads(res.text)

        bank_token = res_dict['access_token']
        return bank_token

    def get_all_provider(self, bank_token):

        headers = {
            'authorization': 'Bearer ' + bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/providers', headers=headers)
        res_dict = json.loads(res.text)

        print('providers: {}'.format(len(res_dict)))
        return res_dict

    def get_provider_access_data(self, provider_id, bank_token):
        headers = {
            'authorization': "Bearer " + bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/providers/' + provider_id, headers=headers)
        res_dict = json.loads(res.text)
        return res_dict['accessDescription']







# TRANSACTIONS
    def get_all_transactions(self, access_id, account_id, bank_token):
        headers = {
            'authorization': 'Bearer ' + bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/accesses/' + access_id + '/accounts/' + account_id + '/transactions', headers=headers)

        res_dict = json.loads(res.text)
        return res_dict


