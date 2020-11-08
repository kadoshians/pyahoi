import ahoi_connector
import pandas as pd
import json


def fetch_transactions():
    transactions = ahoi_connector.get_transactions()
    for account in transactions:
        if not len(transactions[account]):
            with open('data/' + account + '.json', 'w') as file:
                json.dump(transactions[account], file)


reload = False
if reload:
    fetch_transactions()

# TODO It would be nice to flatten the json
df_transactions = pd.read_json('data/03d3cdee-98c5-4cb9-a0e8-8c405078d738.json')
print(df_transactions.columns)
print(df_transactions[['valueDate', 'amount']])
# print(df_transactions.creditor.unique())

