// Використання import
import iconv from 'iconv-lite';

// Ваш текст у UTF-8
const utf8Text = "Ваш текст тут!";

// Конвертуємо текст в буфер Windows-1251
const windows1251Buffer = iconv.encode(utf8Text, 'windows-1251');

// Виведення буфера в консоль
console.log(windows1251Buffer); // Виведе буфер у Windows-1251

// Якщо потрібно перевести буфер назад у рядок
const decodedText = iconv.decode(windows1251Buffer, 'windows-1251');
console.log(decodedText); // Виведе: Ваш текст тут!
