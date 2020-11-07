import configparser
import requests
import base64
import json
import http.client
from datetime import datetime
import uuid

class APIConnector:

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

        token = config['TOKEN']
        self.reg_token = token['regToken']
        self.install_token = token['installToken']
        self.bank_token = token['bankToken']

        if self.reg_token is None or self.reg_token == "":
            self.generate_registration_token()


    def generate_registration_token(self):
        credentials = self.client_id + ":" + self.client_secret

        credentials_base64 = base64.b64encode(credentials.encode()).decode()

        headers = {
            'Authorization': 'Basic ' + credentials_base64
        }

        data = {
            'grant_type': 'client_credentials',
            'username': self.username,
            'password': self.pin
        }
        res = requests.post(self.url + '/auth/v1/oauth/token?', headers=headers, data=data)
        res_dict = json.loads(res.text)
        self.reg_token = res_dict["access_token"]

    def user_registration(self):
        headers = {
            'authorization': "Bearer " + self.reg_token
        }

        res = requests.post(self.url + '/ahoi/api/v2/registration', headers=headers)
        res_dict = json.loads(res.text)
        self.install_token = res_dict['installation']


    def get_banking_token(self):
        credentials = self.client_id + ":" + self.client_secret

        credentials_base64 = base64.b64encode(credentials.encode()).decode()

        current_time = datetime.now().isoformat()

        nonce = uuid.uuid1().hex
        nonce_base64 = base64.b64encode(nonce[:15].encode()).decode()

        x_auth_ahoi_json = "{\"installationId\":\"%s\",\"nonce\":\"%s\",\"timestamp\":\"%s\"}" % (self.install_token, nonce_base64, current_time)

        #x_auth_ahoi_json = {
        #    'installationId':  self.install_token,
        #    'nonce': nonce_base64,
        #    'timestamp':  current_time
        #}

        x_auth_base64 = base64.urlsafe_b64encode(str(x_auth_ahoi_json).encode()).decode()

        headers = {
            'Authorization': 'Basic ' + credentials_base64,
            'X-Authorization-Ahoi': x_auth_base64
        }

        data = {
            'grant_type': 'client_credentials',
            'username': self.username,
            'password': self.pin
        }

        res = requests.post(self.url + '/auth/v1/oauth/token', headers=headers, data=data)
        res_dict = json.loads(res.text)
        print(res_dict)
        #self.bank_token = res_dict['installation']

    def get_all_provider(self):
        headers = {
            'authorization': "Bearer " + self.bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/providers', headers=headers)
        res_dict = json.loads(res.text)
        return(res_dict)

    def get_provider_access_data(self, provider_id):
        headers = {
            'authorization': "Bearer " + self.bank_token
        }

        res = requests.get(self.url + '/ahoi/api/v2/providers/' + provider_id, headers=headers)
        res_dict = json.loads(res.text)
        #print(res_dict)

    def create_new_access(self, provider_id):
        headers = {
            'Authorization': "Bearer " + self.bank_token,
            'Content-Type': 'application/json'
        }
        data = {
            "providerId": provider_id,
            "type": "BankAccess",
            "accessFields": {
                "USERNAME": self.username,
                "PIN": self.pin
            }
        }
        res = requests.post(self.url + '/ahoi/api/v2/accesses/async', headers=headers, data=data)
        res_dict = json.loads(res.text)
        print(res_dict)

    def get_task_response(self):
        headers = {
            'authorization': "Bearer " + self.bank_token
        }

        res = requests.post(self.url + '/ahoi/api/v2/accesses/async', headers=headers)
        res_dict = json.loads(res.text)
        print(res_dict)

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('conf.ini')

    api_connector = APIConnector(config)
    #api_connector.user_registration()
    #api_connector.get_banking_token()
    providers_list = api_connector.get_all_provider()
    provider_id = providers_list[0]['id']
    api_connector.get_provider_access_data(provider_id=provider_id)
    api_connector.create_new_access(provider_id=provider_id)
