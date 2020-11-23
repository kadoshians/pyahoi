import pandas as pd
import json
from ahoi_functions import APIFunctions
import configparser


def fetch_transactions():
    config = configparser.ConfigParser()
    config.read('conf.ini')
    api_functions = APIFunctions(config)

    transactions = api_functions.get_transactions()

    for iban in transactions:
        if len(transactions[iban]):
            with open(f"data/{iban}.json", 'w') as json_out:
                json.dump(transactions[iban], json_out, indent=4)

reload = True

if reload:
    fetch_transactions()


#df_transactions = pd.read_json('data/e38a4f14-b4bc-40ba-9fcb-2504f50d9013.json')

#print(df_transactions)