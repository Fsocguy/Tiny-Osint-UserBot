import asyncio
import aiohttp

from tools.config import shodan_api_key
from colorama import Fore, Style, init

init(autoreset = True)
yellow  =  Fore.YELLOW + Style.BRIGHT
red     =  Fore.RED + Style.BRIGHT

async def ip_main(ip_address):
    async with aiohttp.ClientSession() as session:
        async def ip_whois(ip_address):
            try:
                async with session.get(url = f'http://ip-api.com/json/{ip_address}') as ip_whois_data:
                    if ip_whois_data.status == 200 or ip_whois_data.status == 304:
                        return await ip_whois_data.json()
                    else:
                        print(f'{yellow}[WHOIS API [1]]: {red}ip-api не доступен!')
                        return None
            except Exception as e:
                print(f'{yellow}[WHOIS API [1]]: {red}Возникла ошибка при запросе: {e}')
                return None
        
        async def ip_whois_additional(ip_address):
            try:
                async with session.get(url = f'https://api.ipapi.is/?q={ip_address}') as ip_whois_additional_data:
                    if ip_whois_additional_data.status == 200 or ip_whois_additional_data.status == 304:
                        return await ip_whois_additional_data.json()
                    else:
                        print(f'{yellow}[WHOIS API [2]]: {red}api.ipapi.is не доступен')
                        return None
            except Exception as e:
                print(f'{yellow}[WHOIS API [2]]: {red}Возникла ошибка при запросе: {e}')
                return None

        async def ip_shodan(ip_address, shodan_api_key):
            try:
                async with session.get(url = f'https://api.shodan.io/shodan/host/{ip_address}?key={shodan_api_key}') as ip_shodan_data:
                    if ip_shodan_data.status == 200 or ip_shodan_data.status == 304:        
                        return await ip_shodan_data.json()
                    elif ip_shodan_data.status == 404:
                        print(f'{yellow}[SHODAN API]: {red}Нету информации по такому адресу: {ip_address}')
                        return None
                    else:
                        print(f'{yellow}[SHODAN API]: {red}shodan.io не доступен!')
                        return None
            except Exception as e:
                print(f'{yellow}[SHODAN API]: {red}Возникла ошибка при запросе: {e}')
                return None
        
        async def ip_output(ip_address, ip_whois_data, ip_whois_additional_data, ip_shodan_data):
            if ip_whois_data is not None:
                ip_whois_data_variables  = ['regionName', 'timezone', 'org', 'country', 'lon', 'lat', 'isp', 'city']
                ip_whois_data_values     = [ip_whois_data.get(variable, '❌') for variable in ip_whois_data_variables]
                whois_region, whois_timezone, whois_organization, whois_country, whois_longitude, whois_latitude, whois_provider, whois_city = ip_whois_data_values
            
            if ip_whois_additional_data is not None:
                additional_datacenter  = 'Да' if ip_whois_additional_data.get('is_datacenter', False) else 'Нет'
                additional_abuser      = 'Да' if ip_whois_additional_data.get('is_abuser', False) else 'Нет'
                additional_bogon       = 'Да' if ip_whois_additional_data.get('is_abuser', False) else 'Нет'
                additional_proxy       = 'Да' if ip_whois_additional_data.get('is_proxy', False) else 'Нет'
                additional_tor         = 'Да' if ip_whois_additional_data.get('is_tor', False) else 'Нет'
                additional_vpn         = 'Да' if ip_whois_additional_data.get('is_vpn', False) else 'Нет'
                
                additional_range   =  ip_whois_additional_data.get('company', {}).get('network', '❌')
                additional_update  =  ip_whois_additional_data.get('asn', {}).get('updated', '❌')
                additional_create  =  ip_whois_additional_data.get('asn', {}).get('created', '❌')
                additional_asn     =  ip_whois_additional_data.get('asn', {}).get('asn', '❌')

            if ip_shodan_data is not None:
                shodan_hostname   =  ip_shodan_data.get('hostnames', '❌') if ip_shodan_data.get('hostames') else '❌'
                shodan_os         =  ip_shodan_data.get('os', '❌') if ip_shodan_data.get('os', '❌') else '❌'
                shodan_country    =  ip_shodan_data.get('country_name', '❌')
                shodan_longitude  =  ip_shodan_data.get('longitude', '❌')
                shodan_latitude   =  ip_shodan_data.get('latitude', '❌')
                shodan_ports      =  ip_shodan_data.get('ports', '❌')
                shodan_ports      =  ', '.join(map(str, shodan_ports))
                shodan_city       =  ip_shodan_data.get('city', '❌')
            else:
                shodan_hostname   =  '❌'
                shodan_os         =  '❌'
                shodan_country    =  '❌'
                shodan_longitude  =  '❌'
                shodan_latitude   =  '❌'
                shodan_ports      =  '❌'
                shodan_city       =  '❌'

            ip_output_data = (
                f"┌[ 🎯 **{ip_address}** ]\n"
                f"├ Интернет провайдер: **{whois_provider}**\n"
                f"├ Огранизация: **{whois_organization}**\n"
                f"├ ASN: **{additional_asn}**\n"
                f"├ Дата создания: **{additional_create}**\n"
                f"├ Дата обновления: **{additional_update}**\n"
                f"└ Диапазон адресов: **{additional_range}**\n\n"
                "┌[ 📢 Репутация адреса ]\n"
                f"├ Датацентр?: **{additional_datacenter}**\n"
                f"├ Вредоносный?: **{additional_abuser}**\n"
                f"├ Недопустимый?: **{additional_bogon}**\n"
                f"├ Адрес TOR?: **{additional_tor}**\n"
                f"├ Адрес PROXY?: **{additional_proxy}**\n"
                f"└ Адрес VPN?: **{additional_vpn}**\n\n"
                "┌[ 🌎 Геолокационные данные ]\n"
                f"├ Страна: **{whois_country}**\n"
                f"├ Область: **{whois_region}**\n"
                f"├ Город: **{whois_city}**\n"
                f"├ Часовой пояс: **{whois_timezone}**\n"
                f"├ Широта: **{whois_latitude}**\n"
                f"└ Долгота: **{whois_longitude}**\n\n"
                "┌[ 🔴 Shodan ]\n"
                f"├ Страна: **{shodan_country}**\n"
                f"├ Город: **{shodan_city}**\n"
                f"├ Широта: **{shodan_latitude}**\n"
                f"├ Долгота: **{shodan_longitude}**\n"
                f"├ OC: **{shodan_os}**\n"
                f"├ Имена хоста: **{shodan_hostname}**\n"
                f"└ Открытые порты: **{shodan_ports}**"
            )
            return ip_output_data
        try:
            ip_whois_data             =  await ip_whois(ip_address)
            ip_whois_additional_data  =  await ip_whois_additional(ip_address)
            ip_shodan_data            =  await ip_shodan(ip_address, shodan_api_key)
            ip_output_data            =  await ip_output(ip_address, ip_whois_data, ip_whois_additional_data, ip_shodan_data)
            return ip_output_data
        finally:
            await session.close()