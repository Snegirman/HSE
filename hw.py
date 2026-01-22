import requests

json_url = "https://jsonplaceholder.typicode.com/posts"
weather_url = "http://api.openweathermap.org/data/2.5/weather"

# Задание 1
response = requests.get(json_url)
data = response.json()[0:5]

print(data)

# Задание 2
api_key='40b890f695599d1453d46e22f8321cea'
city=input('Введите ваш город: ')
response = requests.get(f'{weather_url}?q={city}&APPID={api_key}')
data = response.json()

print(data)