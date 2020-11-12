import time

from ahoi_connector import APIConnector


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

        token = config['TOKEN']
        self.reg_token = token['regToken']
        self.install_token = token['installToken']
        self.bank_token = token['bankToken']

        self.api_connector = APIConnector(self.url)

        if self.reg_token is None or self.reg_token == "":
            self.reg_token = self.api_connector.generate_registration_token(self.client_id, self.client_secret, self.username, self.pin)

    def get_transactions(self):
        api_connector = APIConnector()
        api_connector.user_registration(self.reg_token)
        #self.bank_token = api_connector.get_banking_token(self.url, self.install_token, self.client_id, self.client_secret, self.username, self.pin)
        providers_list = api_connector.get_all_provider(self.bank_token)

        provider_id = providers_list[0]['id']

        access_description_dict = api_connector.get_provider_access_data(provider_id, self.bank_token)

        in_progress = True
        while in_progress:
            task_id, state = api_connector.create_new_access(self.username, self.pin, provider_id, self.bank_token)
            in_progress = (state == 'IN_PROGRESS')
        print('taskId: {}, state: {}'.format(task_id, state))

        in_progress = True
        while in_progress:
            response = api_connector.get_access_state(task_id, self.bank_token)
            in_progress = (response['state'] == 'IN_PROGRESS')
            time.sleep(2)
        access_id = response['accessId']
        print('accessId: {}'.format(access_id))

        accounts = api_connector.get_all_accounts(access_id, self.bank_token)
        print(accounts)

        transactions = dict()
        for account in accounts:
            account_id = account['id']
            transactions[account_id] = api_connector.get_all_transactions(access_id, account_id, self.bank_token)

        return transactions
