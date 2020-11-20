import ahoi_functions
import pandas as pd
import json
from collections import defaultdict
from ahoi_functions import APIFunctions
import configparser

def fetch_transactions():
    config = configparser.ConfigParser()
    config.read('conf.ini')
    api_functions = APIFunctions(config)

    transactions = api_functions.get_transactions()

    for account in transactions:
        if not len(transactions[account]):
            print("account" + account)
            with open('data/' + account + '.json', 'w') as file:
                json.dump(transactions[account], file)


reload = True

if reload:
    fetch_transactions()

# TODO It would be nice to flatten the json
df_transactions = pd.read_json('data/3da3dfc6-d3d0-453c-8e07-1ff255fd0a3f.json')


# print(df_transactions.columns)
# print(df_transactions.head())
# print(df_transactions[['purpose', 'cleanPurpose']])
# print(df_transactions.transactionPatternId.unique())
# print(df_transactions[df_transactions.transactionPatternId == 'acd023b5-4d4d-49df-8b79-dd5b872c4dc9']['purpose'])
df_grouped = df_transactions.groupby('transactionPatternId').first()
# print(df_grouped['purpose'])

purposes = df_transactions['purpose'].to_list()

terminals = [purpose for purpose in purposes if 'Terminal' in purpose]
for terminal in terminals:
    print(terminal)

shops = [terminal.split('//')[0] for terminal in terminals]
cities = [terminal.split('/')[2] for terminal in terminals]
shop_dict = defaultdict(int)

print(shops)

for shop in shops:
    shop_dict[shop] += 1

for key in shop_dict:
    print('{}: {}'.format(key, shop_dict[key]))

print(cities)

# f(x) if condition for x in sequence]




