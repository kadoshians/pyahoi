import pandas
import json
from ahoi_functions import APIFunctions
import configparser


def fetch_transactions():
    config = configparser.ConfigParser()
    config.read('conf.ini')
    api_functions = APIFunctions(config)

    transactions = api_functions.get_transactions()

    for account in transactions:
        if not len(transactions[account]):
            print("account hallo ")
            with open('data/' + account + '.json', 'w') as file:
                json.dump(transactions[account], file)


if __name__ == '__main__':
    fetch_transactions()