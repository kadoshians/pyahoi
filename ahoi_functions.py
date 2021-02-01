import threading
import time
from ahoi_connector import APIConnector
from flask import Flask, request
import configparser

app = Flask(__name__)

class APIFunctions():
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

    def get_transactions(self, iban, username, pin, start, end):
        providers_list = self.api_connector.get_providers(self.bank_token)
        provider_id = providers_list[0]['id']
        print(f"providerId: {provider_id}")

        in_progress = True
        while in_progress:
            task_id, state = self.api_connector.create_new_access(self.bank_token, username, pin, provider_id)
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
            iban_tmp = account['iban']

            if iban_tmp == iban:
                # use iban for identification because account_id is not static
                transactions[iban] = self.api_connector.list_transactions_for_account(self.bank_token, access_id, account_id, 1000, 0, start, end)

        return transactions

@app.route('/ahoi/transactions/<string:iban>', methods=['GET'])
def get_transactions(iban):
    if request.method == 'GET':
        username = request.args.get('username')
        pin = request.args.get('pin')
        start = request.args.get('start')
        end = request.args.get('end')
        transactions = api_functions.get_transactions(iban, username, pin, start, end)
        return transactions

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('conf.ini')
    api_functions = APIFunctions(config)
    app.debug = True
    app.run(host='0.0.0.0', port=4996)