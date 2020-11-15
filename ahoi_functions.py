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
        self.bank_token = token['bankToken']

        id = config['ID']
        self.install_id = id['installID']
        self.provider_id = id['providerID']

        self.api_connector = APIConnector(self.url)

        if self.reg_token is None or self.reg_token == "":
            self.reg_token = self.api_connector.generate_registration_token(self.client_id, self.client_secret, self.username, self.pin)

    def get_transactions(self):
        api_connector = APIConnector(self.url)
        self.install_id = api_connector.user_registration(self.reg_token)
        self.bank_token = api_connector.get_banking_token(self.install_id, self.client_id, self.client_secret, self.username, self.pin)
        providers_list = api_connector.get_providers(self.bank_token)

        provider_id = providers_list[0]['id']
        print(provider_id)

        in_progress = True
        while in_progress:
            task_id, state = api_connector.create_new_access(self.bank_token, self.username, self.pin, provider_id)
            in_progress = (state == 'IN_PROGRESS')
        print('taskId: {}, state: {}'.format(task_id, state))

        in_progress = True
        while in_progress:
            response = api_connector.fetch_state_of_task(self.bank_token, task_id)
            in_progress = (response['state'] == 'IN_PROGRESS')
            time.sleep(2)
        access_id = response['accessId']
        print('accessId: {}'.format(access_id))

        accounts = api_connector.list_accounts(self.bank_token, access_id)
        print(accounts)

        transactions = dict()
        for account in accounts:
            account_id = account['id']
            transactions[account_id] = api_connector.get_transactions(self.bank_token, access_id, account_id)

        return transactions
