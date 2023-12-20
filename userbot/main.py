import asyncio
import os
import re

from colorama import Fore, Style, init
from pyrogram import Client, filters

from tools.config import userbot_api_hash, userbot_api_id, userbot_api_targets
from tools.mac import mac_main
from tools.ip import ip_main

init(autoreset = True)
green = Fore.GREEN + Style.BRIGHT

app = Client('UB_OSINT', userbot_api_id, userbot_api_hash)

def userbot_main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f'{green}Бот запущен!')

    @app.on_message(filters.chat(userbot_api_targets))
    async def message_handler(client, message):
        if message.text.startswith('/ip'):
            message_words       =  message.text.split()
            message_ip_pattern  =  re.compile(r'(?:\/ip)\s+(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', re.IGNORECASE)
            if message_ip_pattern.match(message.text):
                if len(message_words) > 1:
                    ip_address      =  message_words[1]
                    ip_output_data  =  await ip_main(ip_address)
                    if ip_output_data:
                        await app.send_message(message.chat.id, ip_output_data)
            else:
                await app.send_message(message.chat.id, '❌ Неверный формат IP-адреса')
        
        elif message.text.startswith('/mac'):
            message_words        =  message.text.split()
            message_mac_pattern  =  re.compile(r'^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$', re.IGNORECASE)
            if message_mac_pattern.match(message_words[1]):
                if len(message_words) > 1:
                    mac_address      =  message_words[1]
                    mac_output_data  =  await mac_main(mac_address)
                    if mac_output_data:
                        await app.send_message(message.chat.id, mac_output_data)
            else:
                await app.send_message(message.chat.id, '❌ Неверный формат MAC-адреса')
        
        elif message.text == '/help':
            await app.send_message(message.chat.id, '[Меню помощи]\nПоиск по IP: **/ip (IP-адрес)**\nПоиск по MAC: **/mac (MAC-адрес)**\nВызов меню помощи: **/help**')

try:
    app.run(userbot_main())
except KeyboardInterrupt:
    exit()