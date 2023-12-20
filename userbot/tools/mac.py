import xml.etree.ElementTree as ET
import asyncio
import aiohttp

from tools.config import wigle_api_key, wigle_api_name, yandex_api_key
from colorama import Fore, Style, init

init(autoreset = True)
yellow  =  Fore.YELLOW + Style.BRIGHT
red     =  Fore.RED + Style.BRIGHT

async def mac_main(mac_address):
    async with aiohttp.ClientSession() as session:
        async def mac_whois(mac_address):
            try:
                async with session.get(url = f'https://api.maclookup.app/v2/macs/{mac_address}') as mac_whois_data:
                    if mac_whois_data.status == 200 or mac_whois_data.status == 304:
                        return await mac_whois_data.json()
                    else:
                        print(f'{yellow}[MAC WHOIS]: {red}api.maclookup.app недоступен!')
                        return None
            except Exception as e:
                print(f'{yellow}[MAC WHOIS]: {red}Возникла ошибка при запросе: {e}')
                return None
        
        async def mac_yandex(mac_address, yandex_api_key):
            try:
                async with session.post(
                    url = 'http://api.lbs.yandex.net/geolocation',
                    data = {'xml': f'<ya_lbs_request><common><version>1.0</version><api_key>{str(yandex_api_key)}</api_key></common><wifi_networks><network><mac>{str(mac_address)}</mac><signal_strength>-1</signal_strength><age>2000</age></network></wifi_networks></ya_lbs_request>'}, 
                    headers = {'Content-Type': 'application/xml'}) as mac_yandex_data:
                    if mac_yandex_data.status == 200 or mac_yandex_data.status == 304:
                        return await mac_yandex_data.text()
                    else:
                        print(f'{yellow}[YANDEX API]: {red}api.lbs.yandex.net недоступен!')
                        return None
            except Exception as e:
                print(f'{yellow}[YANDEX API]: {red}Возникла ошибка при запросе: {e}')
                return None
        
        async def mac_wigle(mac_address, wigle_api_key, wigle_api_name):
            try:
                async with session.get(
                    url = f'https://api.wigle.net/api/v2/network/detail?netid={mac_address}',
                    auth = aiohttp.BasicAuth(wigle_api_name, wigle_api_key)) as mac_wigle_data:
                    if mac_wigle_data.status == 200 or mac_wigle_data.status == 304:
                        if mac_wigle_data['message'] == 'Too many queries today.':
                            print(f'{yellow}[WIGLE API]: {red}Spamblock')
                            return None
                        else:
                            return await mac_wigle_data.json()
                    elif mac_wigle_data.status == 429:
                        print(f'{yellow}[WIGLE API]: {red}Spamblock')
                        return None
                    else:
                        print(f'{yellow}[WIGLE API]: {red}api.wigle.net недоступен!')
                        return None
            except Exception as e:
                print(f'{yellow}[WIGLE API]: {red}Возникла ошибка при запросе: {e}')
                return None

        async def mac_mylinkov(mac_address):
            try:
                async with session.get(url = f'https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={mac_address}') as mac_mylinkov_data:
                    if mac_mylinkov_data.status == 200 or mac_mylinkov_data.status == 304:
                        return await mac_mylinkov_data.json()
                    else:
                        print(f'{yellow}[MYLINKOV API]: {red}api.mylnikov.org недоступен!')
                        return None
            except Exception as e:
                print(f'{yellow}[MYLINKOV API]: {red}Возникла ошибка при запросе: {e}')
                return None
        
        async def mac_output(mac_address, mac_whois_data, mac_yandex_data, mac_wigle_data, mac_mylinkov_data):
            if mac_whois_data is not None:
                if not mac_whois_data.get('found', False):
                    whois_prefix      =  '❌'
                    whois_company     =  '❌'
                    whois_country     =  '❌'
                    whois_blockstart  =  '❌'
                    whois_blockend    =  '❌'
                    whois_blocksize   =  '❌'
                    whois_blocktype   =  '❌'
                    whois_updated     =  '❌'
                    whois_random      =  '❌'
                    whois_private     =  '❌'
                else:
                    whois_prefix      =  mac_whois_data.get('macPrefix', '❌')
                    whois_company     =  mac_whois_data.get('company', '❌')
                    whois_country     =  mac_whois_data.get('country', '❌')
                    whois_blockstart  =  mac_whois_data.get('blockStart', '❌')
                    whois_blockend    =  mac_whois_data.get('blockEnd', '❌')
                    whois_blocksize   =  mac_whois_data.get('blockSize', '❌')
                    whois_blocktype   =  mac_whois_data.get('blockType', '❌')
                    whois_updated     =  mac_whois_data.get('updated', '❌')
                
                    whois_random   =  'Да' if mac_whois_data.get('isRand', False) else 'Нет'
                    whois_private  =  'Да' if mac_whois_data.get('isPrivate', False) else 'Нет'
            
            if mac_yandex_data is not None:
                yandex_data = ET.fromstring(mac_yandex_data)
                yandex_latitude   =  yandex_data.find('.//latitude').text if yandex_data.find('.//latitude') is not None else '❌'
                yandex_longitude  =  yandex_data.find('.//longitude').text if yandex_data.find('.//longitude') is not None else '❌'
            
            if mac_wigle_data is not None:
                wigle_latitude    =  next((wigle_result.get('trilat', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
                wigle_longitude   =  next((wigle_result.get('trilong', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
                wigle_ssid        =  next((wigle_result.get('ssid', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
                wigle_encryption  =  next((wigle_result.get('encryption', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
                wigle_country     =  next((wigle_result.get('country', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
                wigle_region      =  next((wigle_result.get('region', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
                wigle_road        =  next((wigle_result.get('road', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
                wigle_city        =  next((wigle_result.get('city', '❌') for wigle_result in mac_wigle_data.get('results', [])), '❌')
            else:
                wigle_latitude    =  '❌' 
                wigle_longitude   =  '❌' 
                wigle_ssid        =  '❌' 
                wigle_encryption  =  '❌' 
                wigle_country     =  '❌' 
                wigle_region      =  '❌' 
                wigle_road        =  '❌' 
                wigle_city        =  '❌' 

            if mac_mylinkov_data is not None:
                mylinkov_latitude  =  mac_mylinkov_data.get('data').get('lat', '❌')
                mylinkov_logitude  =  mac_mylinkov_data.get('data').get('lon', '❌')
                mylinkov_range     =  mac_mylinkov_data.get('data').get('range', '❌')
            
            mac_output_data = (
                f"┌[ 🎯 **{mac_address}** ]\n"
                f"├ Производитель: **{whois_company}**\n"
                f"└ Страна производителя: **{whois_country}**\n\n"
                f"┌[ ⚙️ Структура адреса ]\n"
                f"├ Тип блока: **{whois_blocktype}**\n"
                f"├ Префикс: **{whois_prefix}**\n"
                f"├ Размер блока: **{whois_blocksize}**\n"
                f"├ Начало блока: **{whois_blockstart}**\n"
                f"└ Конец блока: **{whois_blockend}**\n\n"
                f"┌[ 📋 Доп. сведения ]\n"
                f"├ Обновлен: **{whois_updated}**\n"
                f"├ Рандом: **{whois_random}**\n"
                f"└ Приватный: **{whois_private}**\n\n"
                f"┌[ 🌎 Геолокационные данные (Yandex) ]\n"
                f"├ Широта: **{yandex_latitude}**\n"
                f"└ Долгота: **{yandex_longitude}**\n\n"
                f"┌[ 📶 Wigle ]\n"
                f"├ SSID: **{wigle_ssid}**\n"
                f"├ Защита: **{wigle_encryption}**\n"
                f"├ Страна: **{wigle_country}**\n"
                f"├ Регион: **{wigle_region}**\n"
                f"├ Город: **{wigle_city}**\n"
                f"├ Улица: **{wigle_road}**\n"
                f"├ Широта: **{wigle_latitude}**\n"
                f"└ Долгота: **{wigle_longitude}**\n\n"
                f"┌[ 🅾️ Mylinkov ]\n"
                f"├ Широта: **{mylinkov_latitude}**\n"
                f"├ Долгота: **{mylinkov_logitude}**\n"
                f"└ Диапазон: **{mylinkov_range}**"
            )
            return mac_output_data
        try:
            mac_whois_data     =  await mac_whois(mac_address)
            mac_yandex_data    =  await mac_yandex(mac_address, yandex_api_key)
            mac_wigle_data     =  await mac_wigle(mac_address, wigle_api_key, wigle_api_name)
            mac_mylinkov_data  =  await mac_mylinkov(mac_address)
            mac_output_data    =  await mac_output(mac_address, mac_whois_data, mac_yandex_data, mac_wigle_data, mac_mylinkov_data)
            return mac_output_data
        finally:
            await session.close()