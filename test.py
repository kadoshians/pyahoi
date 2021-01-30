import pandas as pd
import json
from ahoi_functions import APIFunctions
from sec_ahoi_functions import SecAPIFunctions
import configparser


reload = False

test = True


def fetch_transactions():
    config = configparser.ConfigParser()
    config.read('conf.ini')
    api_functions = APIFunctions(config)

    transactions = api_functions.get_transactions()

    for iban in transactions:
        if len(transactions[iban]):
            with open(f"data/{iban}.json", 'w') as json_out:
                json.dump(transactions[iban], json_out, indent=4)



def test_x_auth():
    config = configparser.ConfigParser()
    config.read('conf.ini')
    sec_api_functions = SecAPIFunctions(config)

    sec_api_functions.test_x_auth()



if reload:
    fetch_transactions()

if test:
    test_x_auth()


#df_transactions = pd.read_json('data/e38a4f14-b4bc-40ba-9fcb-2504f50d9013.json')

#print(df_transactions)