import asyncio
import logging
import os
from mnemonic import Mnemonic
from tronpy import Tron
from tronpy.keys import PrivateKey
from aiohttp import ClientSession, TCPConnector

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

error_logger = logging.getLogger("error_logger")
balance_logger = logging.getLogger("balance_logger")

# Файл для сохранения проверенных адресов
CHECKED_ADDRESSES_FILE = "checked_tron_addresses.txt"
checked_addresses = set()

# Глобальные метрики
total_checked = 0
wallets_found = 0

# Загрузка проверенных адресов
def load_checked_addresses():
    if os.path.exists(CHECKED_ADDRESSES_FILE):
        with open(CHECKED_ADDRESSES_FILE, "r") as file:
            for line in file:
                checked_addresses.add(line.strip())

def save_checked_address(address):
    """Сохранение проверенного адреса"""
    with open(CHECKED_ADDRESSES_FILE, "a") as file:
        file.write(address + "\n")

def generate_mnemonic():
    """Генерация случайной мнемонической фразы"""
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)

def get_tron_address_from_mnemonic(mnemonic_phrase):
    """Получение TRON-адреса из мнемонической фразы"""
    try:
        seed = Mnemonic.to_seed(mnemonic_phrase)
        private_key = PrivateKey.from_seed(seed)
        return private_key.address
    except Exception as e:
        error_logger.error(f"Ошибка генерации TRON-адреса: {e}")
        return None

async def check_tron_balance(address, session):
    """Проверка баланса TRON-адреса через API"""
    url = f"https://api.trongrid.io/v1/accounts/{address}"
    try:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                if "data" in data and len(data["data"]) > 0:
                    account_data = data["data"][0]
                    trx_balance = int(account_data.get("balance", 0)) / 1_000_000  # Конвертируем в TRX
                    usdt_balance = next(
                        (int(t["amount"]) / 1_000_000 for t in account_data.get("trc20", []) if t["key"] == "USDT"),
                        0,
                    )
                    return trx_balance, usdt_balance
            return 0, 0
    except Exception as e:
        error_logger.error(f"Ошибка при запросе к Tron API для адреса {address}: {e}")
        return 0, 0

async def process_mnemonic(session):
    """Обработка одной мнемонической фразы"""
    global total_checked, wallets_found
    mnemonic_phrase = generate_mnemonic()
    address = get_tron_address_from_mnemonic(mnemonic_phrase)

    if address and address not in checked_addresses:
        checked_addresses.add(address)
        save_checked_address(address)
        trx_balance, usdt_balance = await check_tron_balance(address, session)

        total_checked += 1

        if trx_balance > 0 or usdt_balance > 0:
            wallets_found += 1
            # Логирование успешного результата
            balance_logger.info(
                f"{mnemonic_phrase} -> {address}, Баланс: {trx_balance} TRX, {usdt_balance} USDT"
            )
            logging.info(
                f"!!! Найден кошелек: {address}, Баланс: {trx_balance} TRX, {usdt_balance} USDT !!!"
            )
        else:
            logging.info(f"Пустой кошелек: {address}")

async def main():
    """Основная функция программы"""
    load_checked_addresses()
    connector = TCPConnector(limit_per_host=10)  # Ограничиваем количество соединений
    async with ClientSession(connector=connector) as session:
        while True:
            tasks = [process_mnemonic(session) for _ in range(10)]  # Параллельно обрабатываем 10 адресов
            await asyncio.gather(*tasks)
            logging.info(f"Обработано адресов: {total_checked}, Найдено кошельков: {wallets_found}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"Произошла ошибка: {e}")
