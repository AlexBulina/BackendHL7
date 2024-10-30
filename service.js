import { Service } from 'node-windows';
// import { appendFileSync } from 'fs';

// appendFileSync('C:\\servicelog.txt', 'Service started\n');

const args = process.argv.slice(2);

// Створюємо нову службу
var svc = new Service({
  name: 'Kaskad HL7 JSON Virtual laboratory analyzer', // Назва служби
  description: 'This program emulates a laboratory analyzer using the (Health Level 7) HL7 protocol.', // Опис
  script: 'C:\\Kaskad Backend\\TCP_Client.js' // Шлях до вашого JS файлу
});

// Реєстрація події установки
svc.on('install', function() {
  svc.start();
  console.log('Service started')
});







// Встановлюємо службу
svc.install();
svc.on('error', function(err){
    console.error('Service error:', err);
  });
  
