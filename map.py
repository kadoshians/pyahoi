import pandas as pd
import json
from collections import defaultdict
import geopandas as gpd
import matplotlib.pyplot as plt

df_transactions = pd.read_json('data/3da3dfc6-d3d0-453c-8e07-1ff255fd0a3f.json')
df_plz = pd.read_csv('data/zuordnung_plz_ort.csv')
plz_shape_df = gpd.read_file('data/plz-gebiete.shp', dtype={'plz': str})

purposes = df_transactions['purpose'].to_list()
terminals = [purpose for purpose in purposes if 'Terminal' in purpose]
cities = [terminal.split('/')[2] for terminal in terminals]

cities_new = list()

for i in cities:
    j = i.replace(' ','')
    cities_new.append(j.lower())


city_dict = defaultdict(int)
for city in cities_new:
    city_dict[city] += 1

df_plz["ort"] = df_plz["ort"].str.lower()

plz_numbers = pd.DataFrame(columns=['plz', 'count'])
for key in city_dict:
    plz = df_plz[df_plz.ort == key]
    if not plz.empty:
        plz_numbers = plz_numbers.append({'plz': str(plz.iloc[0][0])[:5], 'count': city_dict[key]}, ignore_index=True)
print(plz_numbers)
plz_region_df = pd.read_csv(
    'data/zuordnung_plz_ort.csv',
    sep=',',
    dtype={'plz': str}
)

plz_region_df.drop('osm_id', axis=1, inplace=True)

germany_df = pd.merge(
    left=plz_shape_df,
    right=plz_region_df,
    on='plz',
    how='inner'
)

germany_df.drop(['note'], axis=1, inplace=True)

germany_df = pd.merge(
    left=germany_df,
    right=plz_numbers,
    on='plz',
    how='left'
)

germany_df = germany_df.fillna(0)
print(germany_df)

fig, ax = plt.subplots()

germany_df.plot(
    ax=ax,
    column='count',
    categorical=False,
    legend=True,
    cmap='autumn_r',
    alpha=0.8
)

top_cities = {
    'Berlin': (13.404954, 52.520008),
    'Cologne': (6.953101, 50.935173),
    'Düsseldorf': (6.782048, 51.227144),
    'Frankfurt am Main': (8.682127, 50.110924),
    'Hamburg': (9.993682, 53.551086),
    'Leipzig': (12.387772, 51.343479),
    'Munich': (11.576124, 48.137154),
    'Dortmund': (7.468554, 51.513400),
    'Stuttgart': (9.181332, 48.777128),
    'Nuremberg': (11.077438, 49.449820),
    'Hannover': (9.73322, 52.37052)
}


for c in top_cities.keys():
    ax.text(
        x=top_cities[c][0],
        y=top_cities[c][1] + 0.08,
        s=c,
        fontsize=12,
        ha='center',
    )

    ax.plot(
        top_cities[c][0],
        top_cities[c][1],
        marker='o',
        c='black',
        alpha=0.5
    )

ax.set(
    title='Germany: Number of Inhabitants per Postal Code',
    aspect=1.3,
    facecolor='lightblue'
)


plt.show()
