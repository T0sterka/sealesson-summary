import telebot
import requests
import hashlib
import base64  # Добавьте эту строку в начало файла
from telebot import types
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import secrets
import string
import requests
import hashlib

def check_password_leak(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        for line in response.text.splitlines():
            parts = line.split(':')
            if parts[0] == suffix:
                return int(parts[1])
        return 0
    except requests.RequestException:
        return -1

def check_email_leak(email, api_key):
    headers = {"hibp-api-key": api_key}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return []
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return None

# Инициализация бота с токеном
bot = telebot.TeleBot('7514486365:AAE5R7whBl37aeIMVtya8Zr4GdLQE37aw6s')

# Словарь для хранения сессий пользователей
user_sessions = {}

# Класс для хранения данных сессии пользователя
class UserSession:
    def __init__(self):
        self.aes_key = None  # Ключ для AES-шифрования
        self.rsa_private_key = None  # Приватный ключ RSA
        self.rsa_public_key = None  # Публичный ключ RSA
        self.current_action = None  # Текущее действие пользователя

# ====================== ОСНОВНЫЕ КОМАНДЫ ======================

# Обработчик команды /start - главное меню
@bot.message_handler(commands=['start'])
def send_welcome(message):
    # Создаем клавиатуру с основными функциями
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn1 = types.KeyboardButton('🔐 Шифрование AES')
    btn2 = types.KeyboardButton('🔑 Шифрование RSA')
    btn3 = types.KeyboardButton('🔢 Генератор паролей')
    btn4 = types.KeyboardButton('⚠ Проверка утечек')
    markup.add(btn1, btn2, btn3, btn4)
    
    # Отправляем приветственное сообщение
    bot.send_message(
        message.chat.id,
        "👋 Добро пожаловать в Бот-Шифровальщик!\n"
        "Выберите нужную функцию:",
        reply_markup=markup
    )
    
    # Инициализируем сессию пользователя, если ее нет
    if message.chat.id not in user_sessions:
        user_sessions[message.chat.id] = UserSession()

# ====================== ШИФРОВАНИЕ AES ======================

@bot.message_handler(func=lambda message: message.text == '🔐 Шифрование AES')
def aes_menu(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn1 = types.KeyboardButton('🔒 Зашифровать текст (AES)')
    btn2 = types.KeyboardButton('🔓 Расшифровать текст (AES)')
    btn3 = types.KeyboardButton('↩ Назад')
    markup.add(btn1, btn2, btn3)
    
    bot.send_message(
        message.chat.id,
        "🔐 Выберите действие с AES-шифрованием:",
        reply_markup=markup
    )

@bot.message_handler(func=lambda message: message.text == '🔒 Зашифровать текст (AES)')
def encrypt_aes_start(message):
    user_sessions[message.chat.id].current_action = 'encrypt_aes'
    bot.send_message(
        message.chat.id,
        "Введите текст для шифрования:",
        reply_markup=types.ReplyKeyboardRemove()
    )

@bot.message_handler(func=lambda message: message.text == '🔓 Расшифровать текст (AES)')
def decrypt_aes_start(message):
    user_sessions[message.chat.id].current_action = 'decrypt_aes'
    bot.send_message(
        message.chat.id,
        "Введите зашифрованный текст и ключ через '|' (текст|ключ):",
        reply_markup=types.ReplyKeyboardRemove()
    )

@bot.message_handler(func=lambda message: user_sessions.get(message.chat.id) and 
                    user_sessions[message.chat.id].current_action in ['encrypt_aes', 'decrypt_aes'])
def handle_aes(message):
    session = user_sessions[message.chat.id]
    
    if session.current_action == 'encrypt_aes':
        # Генерируем ключ, если его нет
        if not session.aes_key:
            session.aes_key = Fernet.generate_key().decode()
        
        # Шифруем текст
        fernet = Fernet(session.aes_key.encode())
        encrypted = fernet.encrypt(message.text.encode()).decode()
        
        # Отправляем результат
        bot.send_message(
            message.chat.id,
            f"🔒 Зашифрованный текст:\n<code>{encrypted}</code>\n\n"
            f"🔑 Ключ (сохраните его!):\n<code>{session.aes_key}</code>",
            parse_mode='HTML'
        )
        
    elif session.current_action == 'decrypt_aes':
        try:
            # Разделяем текст и ключ
            parts = message.text.split('|')
            if len(parts) != 2:
                raise ValueError
            
            text, key = parts[0].strip(), parts[1].strip()
            
            # Дешифруем текст
            fernet = Fernet(key.encode())
            decrypted = fernet.decrypt(text.encode()).decode()
            
            bot.send_message(
                message.chat.id,
                f"🔓 Расшифрованный текст:\n<code>{decrypted}</code>",
                parse_mode='HTML'
            )
        except Exception as e:
            bot.send_message(
                message.chat.id,
                "❌ Ошибка дешифрования. Проверьте ключ и формат ввода (текст|ключ)."
            )
    
    # Сбрасываем текущее действие
    session.current_action = None
    send_welcome(message)

# ====================== ШИФРОВАНИЕ RSA ======================

@bot.message_handler(func=lambda message: message.text == '🔑 Шифрование RSA')
def rsa_menu(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn1 = types.KeyboardButton('🔐 Сгенерировать ключи RSA')
    btn2 = types.KeyboardButton('🔒 Зашифровать текст (RSA)')
    btn3 = types.KeyboardButton('🔓 Расшифровать текст (RSA)')
    btn4 = types.KeyboardButton('↩ Назад')
    markup.add(btn1, btn2, btn3, btn4)
    
    bot.send_message(
        message.chat.id,
        "🔑 Выберите действие с RSA-шифрованием:",
        reply_markup=markup
    )

@bot.message_handler(func=lambda message: message.text == '🔐 Сгенерировать ключи RSA')
def generate_rsa_keys(message):
    # Генерируем пару ключей
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Сериализуем ключи
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    # Сохраняем в сессию
    session = user_sessions[message.chat.id]
    session.rsa_private_key = private_pem
    session.rsa_public_key = public_pem
    
    # Отправляем пользователю
    bot.send_message(
        message.chat.id,
        "🔑 Приватный ключ (сохраните его!):\n"
        f"<code>{private_pem}</code>\n\n"
        "🔐 Публичный ключ:\n"
        f"<code>{public_pem}</code>",
        parse_mode='HTML'
    )

@bot.message_handler(func=lambda message: message.text == '🔒 Зашифровать текст (RSA)')
def encrypt_rsa_start(message):
    user_sessions[message.chat.id].current_action = 'encrypt_rsa'
    bot.send_message(
        message.chat.id,
        "Введите текст для шифрования и публичный ключ через '|' (текст|ключ):",
        reply_markup=types.ReplyKeyboardRemove()
    )

@bot.message_handler(func=lambda message: message.text == '🔓 Расшифровать текст (RSA)')
def decrypt_rsa_start(message):
    user_sessions[message.chat.id].current_action = 'decrypt_rsa'
    bot.send_message(
        message.chat.id,
        "Введите зашифрованный текст и приватный ключ через '|' (текст|ключ):",
        reply_markup=types.ReplyKeyboardRemove()
    )

@bot.message_handler(func=lambda message: user_sessions.get(message.chat.id) and 
                    user_sessions[message.chat.id].current_action in ['encrypt_rsa', 'decrypt_rsa'])
def handle_rsa(message):
    session = user_sessions[message.chat.id]
    
    try:
        parts = message.text.split('|')
        if len(parts) != 2:
            raise ValueError
        
        text, key = parts[0].strip(), parts[1].strip()
        
        if session.current_action == 'encrypt_rsa':
            # Загружаем публичный ключ
            public_key = serialization.load_pem_public_key(
                key.encode(),
                backend=default_backend()
            )
            
            # Шифруем текст
            encrypted = public_key.encrypt(
                text.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Кодируем в base64 для удобства
            encrypted_b64 = base64.b64encode(encrypted).decode()
            
            bot.send_message(
                message.chat.id,
                f"🔒 Зашифрованный текст:\n<code>{encrypted_b64}</code>",
                parse_mode='HTML'
            )
            
        elif session.current_action == 'decrypt_rsa':
            # Загружаем приватный ключ
            private_key = serialization.load_pem_private_key(
                key.encode(),
                password=None,
                backend=default_backend()
            )
            
            # Декодируем из base64
            encrypted = base64.b64decode(text.encode())
            
            # Дешифруем
            decrypted = private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            
            bot.send_message(
                message.chat.id,
                f"🔓 Расшифрованный текст:\n<code>{decrypted}</code>",
                parse_mode='HTML'
            )
    
    except Exception as e:
        bot.send_message(
            message.chat.id,
            f"❌ Ошибка: {str(e)}\nПроверьте формат ввода и ключи."
        )
    
    # Сбрасываем текущее действие
    session.current_action = None
    send_welcome(message)

# ====================== ГЕНЕРАТОР ПАРОЛЕЙ ======================

@bot.message_handler(func=lambda message: message.text == '🔢 Генератор паролей')
def password_generator(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn1 = types.KeyboardButton('🔢 Сгенерировать простой пароль (8 символов)')
    btn2 = types.KeyboardButton('🔢 Сгенерировать средний пароль (12 символов)')
    btn3 = types.KeyboardButton('🔢 Сгенерировать сложный пароль (16 символов)')
    btn4 = types.KeyboardButton('↩ Назад')
    markup.add(btn1, btn2, btn3, btn4)
    
    bot.send_message(
        message.chat.id,
        "🔢 Выберите сложность пароля:",
        reply_markup=markup
    )

@bot.message_handler(func=lambda message: message.text.startswith('🔢 Сгенерировать'))
def generate_password(message):
    # Определяем длину пароля
    if 'простой' in message.text:
        length = 8
    elif 'средний' in message.text:
        length = 12
    else:
        length = 16
    
    # Генерируем пароль
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    bot.send_message(
        message.chat.id,
        f"🔢 Ваш новый пароль:\n<code>{password}</code>\n\n"
        "⚠ Не сохраняйте пароли в незащищенных местах!",
        parse_mode='HTML'
    )

# ====================== ПРОВЕРКА УТЕЧЕК ======================

@bot.message_handler(func=lambda message: message.text == '⚠ Проверка утечек')
def check_leaks(message):
    user_sessions[message.chat.id].current_action = 'check_leaks'
    bot.send_message(
        message.chat.id,
        "Введите email или пароль для проверки утечек:",
        reply_markup=types.ReplyKeyboardRemove()
    )

@bot.message_handler(func=lambda message: user_sessions.get(message.chat.id) and 
                    user_sessions[message.chat.id].current_action == 'check_leaks')
def handle_leak_check(message):
    user_input = message.text.strip()
    HIBP_API_KEY = "ваш_api_ключ"  # Замени на реальный ключ!
    
    if '@' not in user_input:
        count = check_password_leak(user_input)
        if count == -1:
            bot.reply_to(message, "⚠ Ошибка при проверке. Попробуйте позже.")
        elif count == 0:
            bot.reply_to(message, "✅ Пароль не найден в утечках!")
        else:
            bot.reply_to(message, f"🚨 Пароль найден в {count} утечках! Срочно смените его!")
    else:
        leaks = check_email_leak(user_input, HIBP_API_KEY)
        if leaks is None:
            bot.reply_to(message, "⚠ Ошибка при проверке email.")
        elif not leaks:
            bot.reply_to(message, f"✅ Email {user_input} не найден в утечках!")
        else:
            breaches = "\n".join([f"- {b['Name']} ({b['BreachDate']})" for b in leaks])
            bot.reply_to(message, f"🚨 Email в {len(leaks)} утечках:\n{breaches}")
    
    user_sessions[message.chat.id].current_action = None

# ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======================

@bot.message_handler(func=lambda message: message.text == '↩ Назад')
def back_to_main(message):
    send_welcome(message)

# Запуск бота
if __name__ == '__main__':
    print("Бот запущен...")
    bot.polling(none_stop=True)