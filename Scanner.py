#
# created by globareley
#
import logging
import socket
import struct
import time
from datetime import datetime
import concurrent.futures
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, 
    CommandHandler, 
    MessageHandler, 
    filters,
    CallbackContext,
    CallbackQueryHandler
)


TOKEN = "Your Token"
PORT_RANGE = (19130, 19630) 
SCAN_TIMEOUT = 1.5
MAX_WORKERS = 100  


logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

async def start(update: Update, context: CallbackContext) -> None:
    """Обработка команды /start"""
    user = update.effective_user
    await update.message.reply_html(
        f"Привет {user.mention_html()}! 👋\n"
        "Я - сканер Minecraft Bedrock серверов.\n"
        "Просто отправь мне IP или домен сервера, и я проверю 500+ портов!\n\n"
        "Примеры:\n"
        "<code>breadix.ru</code>\n"
        "<code>mc.example.com</code>\n"
        "<code>192.168.1.1</code>"
    )

async def scan_server(update: Update, context: CallbackContext) -> None:
    """Обработка запроса на сканирование"""
    host = update.message.text.strip()
    
  
    if not is_valid_host(host):
        await update.message.reply_text("❌ Неверный формат IP/домена!")
        return
    
   
    message = await update.message.reply_text(
        f"🔎 Сканирование активных портов сервера: {host}\n"
        f"Проверяю {PORT_RANGE[1]-PORT_RANGE[0]+1} портов...\n"
        "⏳ Пожалуйста, подождите..."
    )
    

    start_time = time.time()
    active_ports = await scan_ports(host)
    scan_time = time.time() - start_time
    
 
    server_info = None
    if active_ports:
        server_info = get_server_info(host, active_ports[0])
    
   
    result = format_results(host, active_ports, server_info, scan_time)
    
  
    await context.bot.edit_message_text(
        chat_id=message.chat_id,
        message_id=message.message_id,
        text=result,
        parse_mode="HTML"
    )

def is_valid_host(host: str) -> bool:
    """Проверка валидности хоста"""
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False

async def scan_ports(host: str) -> list:
    """Асинхронное сканирование портов"""
    ports_to_scan = range(PORT_RANGE[0], PORT_RANGE[1] + 1)
    active_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        loop = asyncio.get_event_loop()
        futures = [
            loop.run_in_executor(
                executor, 
                check_bedrock_port, 
                host, 
                port
            )
            for port in ports_to_scan
        ]
        
        for future in asyncio.as_completed(futures):
            port, is_active = await future
            if is_active:
                active_ports.append(port)
    
    return active_ports

def check_bedrock_port(host: str, port: int) -> tuple:
    """Проверка одного порта на наличие Bedrock сервера"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SCAN_TIMEOUT)
        
       
        timestamp = int(time.time())
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
        packet = b'\x01'
        packet += struct.pack('>Q', timestamp)
        packet += magic
        packet += struct.pack('>Q', 0)
        
        sock.sendto(packet, (host, port))
        data = sock.recv(1024)
        
        
        if len(data) > 0 and data[0] == 0x1c:
            return port, True
    
    except:
        pass
    finally:
        sock.close()
    
    return port, False

def get_server_info(host: str, port: int):
    """Получение информации о сервере"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        
        timestamp = int(time.time())
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
        packet = b'\x01' + struct.pack('>Q', timestamp) + magic + struct.pack('>Q', 0)
        
        sock.sendto(packet, (host, port))
        data, addr = sock.recvfrom(2048)
        
        if data[0] != 0x1c:
            return None
        
        server_info = data[33:].split(b';')
        if len(server_info) < 10:
            return None
            
        return {
            'edition': safe_decode(server_info[0]),
            'motd': safe_decode(server_info[1]),
            'protocol': safe_decode(server_info[2]),
            'version': safe_decode(server_info[3]),
            'players': safe_decode(server_info[4]),
            'max_players': safe_decode(server_info[5]),
            'server_id': safe_decode(server_info[6]),
            'server_name': safe_decode(server_info[7]),
            'gamemode': safe_decode(server_info[8]),
            'port': port
        }
        
    except:
        return None
    finally:
        sock.close()

def safe_decode(byte_str):
    """Безопасное декодирование строки"""
    try:
        return byte_str.decode('utf-8')
    except:
        return byte_str.decode('latin-1', errors='ignore')

def format_results(host: str, active_ports: list, server_info: dict, scan_time: float) -> str:
    """Форматирование результатов сканирования"""
    timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
    port_count = PORT_RANGE[1] - PORT_RANGE[0] + 1
    
    if not active_ports:
        return (
            f"<b>[{timestamp}] ❌ Результаты сканирования {host}</b>\n\n"
            f"🔢 Проверено портов: <code>{port_count}</code>\n"
            f"📂 Активные порты: <b>не найдено</b>\n\n"
            f"⏱ Время сканирования: {scan_time:.2f} сек"
        )
    
    ports_str = ", ".join(map(str, active_ports[:10]))
    if len(active_ports) > 10:
        ports_str += f" (+{len(active_ports)-10} других)"
    
    result = [
        f"<b>[{timestamp}] ✅ Результаты сканирования {host}</b>\n\n",
        f"🔢 Проверено портов: <code>{port_count}</code>",
        f"📂 Активные порты: <b>{ports_str}</b>"
    ]
    
    if server_info:
        result.extend([
            f"🏷️ Название: <b>{server_info['server_name']}</b>",
            f"🛠️ Версия: <b>{server_info['version']}</b>",
            f"👥 Игроки: <b>{server_info['players']}/{server_info['max_players']}</b>",
            f"🎮 Режим: <b>{server_info['gamemode']}</b>",
            f"📝 MOTD: <i>{server_info['motd']}</i>",
            f"🚪 Основной порт: <b>{server_info['port']}</b>"
        ])
    
    result.append(f"\n⏱ Время сканирования: {scan_time:.2f} сек")
    return "\n".join(result)

def main() -> None:
    """Запуск бота"""
    application = Application.builder().token(TOKEN).build()
    
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_server))
    
    
    application.run_polling()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
