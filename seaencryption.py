import os
import io
import telebot
import speech_recognition as sr
import soundfile as sf
import numpy as np

TOKEN = 'Telegram_token'
bot = telebot.TeleBot(TOKEN)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Привет! Отправь мне голосовое сообщение, и я преобразую его в текст.")

@bot.message_handler(content_types=['voice'])
def handle_voice(message):
    try:
        # Получаем файл голосового сообщения
        file_info = bot.get_file(message.voice.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Создаем файловый объект в памяти
        audio_file = io.BytesIO(downloaded_file)
        
        # Читаем аудио данные
        audio_data, sample_rate = sf.read(audio_file)
        
        # Создаем временный файл с уникальным именем
        temp_wav = os.path.join(os.getenv('TEMP'), f'temp_{os.getpid()}.wav')
        
        # Сохраняем во временный файл
        sf.write(temp_wav, audio_data, sample_rate)
        
        # Распознаем текст
        recognizer = sr.Recognizer()
        with sr.AudioFile(temp_wav) as source:
            audio_data = recognizer.record(source)
            text = recognizer.recognize_google(audio_data, language='ru-RU')
        
        # Удаляем временный файл
        try:
            os.unlink(temp_wav)
        except:
            pass
        
        bot.reply_to(message, f"Распознанный текст:\n\n{text}")
    
    except Exception as e:
        bot.reply_to(message, f"Произошла ошибка: {str(e)}")

if __name__ == '__main__':
    print("Бот запущен...")
    bot.infinity_polling()
