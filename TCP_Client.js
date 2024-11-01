import { TIMEOUT } from 'dns';
import { createConnection } from 'net';
import express from 'express'; 
import { promises as fs } from 'fs';
import { existsSync, mkdirSync } from 'fs';
import { join } from'path';
import winston from 'winston';
import 'winston-daily-rotate-file';
import oracledb from 'oracledb';
import iconv from 'iconv-lite';



const app = express();
let clientTCP;
let responsejob = {};
let condition = false;
let barcodearray =[];
let barcodecount = 0;
let querybarcodePID = {};
let segmentPID = []
let idresult = {}
let idresultOrder = {}
let idresultOrderSid 




let PID = 1; let  indexcount = 1;
let counter = 0;
let counterjob = 0;
let jsonData
const appDataPath = process.env.APPDATA;
const transport = new winston.transports.DailyRotateFile({
  filename: join(process.env.APPDATA,'HL7',`application-%DATE%.log`),
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d',
});
//queryDatabase("'ADVIA'");
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss' // Формат часу
    }),
   
  
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`
    } 
    //winston.format.json(),
    )
  ),
  transports: [transport,

    new winston.transports.DailyRotateFile({
      filename: join('C:','HL7',`debug-%DATE%.log`),
      maxSize: '20m',
      maxFiles: '14d',
      datePattern: 'YYYY-MM-DD', // Тільки для debug рівня
      level: 'debug',
  })
  ],
});



const testDataArray = [
  { testCode: 'ALT', testName: 'ALT',value: '7.8', unit: 'mmol/L',FullValue: '7.8000001',Ref: '90-120', Barcode: '113194470031' },
  { testCode: 'BIL', testName: 'BIL',value: '4.2', unit: 'g/dL', FullValue: '54.23233443', Ref: '90-120',Barcode: '113194470031'   },
  { testCode: 'AST', testName: 'AST',value: '4.2', unit: 'g/dL', FullValue: '4.23233443', Ref: '90-120', Barcode: '113194470031'   }
  //{ testCode: '23456-79', testName: 'ALBT',value: '4.2', unit: 'g/dL', FullValue: '54.23233443', Ref: '45-430',Barcode: '113194470031'   }
  
];







const jsonFilePath = join("F:", 'data.json')
const logFilePath = join('C:', 'HL7');
console.log = (...args) => {
 const message = args.join(' ');
//logToFile(message); // Записуємо в файл

logger.info(message);
logger.debug(appDataPath);

};

async function readFileAsync() {
  try {
      const data = await fs.readFile('F:/data.json', 'utf8');
     // console.log('Вміст файлу:', data);
      return JSON.parse(data);
  } catch (err) {
      logger.error(console.error('Помилка:', err));
  }
}




const checkCondition = () => {
  return new Promise((resolve) => {
    const interval = setInterval(() => {
      console.log('Опрацьовую отимане повідомлення з LIS');
      
      if (condition === true) {
        clearInterval(interval); // Зупиняємо перевірку
        resolve(); // Виконуємо resolve, щоб завершити обіцянку
      }
    }, 1000); // Перевіряємо умову кожну секунду
  });
};

const validateTestdevId = async (req, res, next) => {
  const { token } = req.query; // Наприклад, очікуємо токен в запиті

  if (token !=null) {
   idresult = await queryDatabase(token)
   
    console.log(idresult)
 
    
    
   next();
     // Продовжуємо виконання, якщо JSON правильний
  } else {
    res.status(400).json({ message: 'Invalid JSON' });
  }
};
const validateOrder= async (req, res, next) => {
  const { token } = req.query; //  Очікуємо токен в запиті
  const {Device} = req.query;

  if (token !=null) {
   idresultOrder = await queryDatabaseOrder(token,Device)
   
    console.log(idresultOrder)
 
    
    
   next();
     // Продовжуємо виконання, якщо JSON правильний
  } else {
    res.status(400).json({ message: 'Invalid JSON' });
  }
};
const validateOrderSid= async (req, res, next) => {
  const { token } = req.query; // Наприклад, очікуємо токен в запиті
  const {begindate} = req.query;
  const {enddate} = req.query;

  if (token !=null) {

    
   idresultOrderSid =  JSON.stringify(sortAndAggregate(await queryDatabaseSidArray(token,begindate,enddate))       )                                                                        // queryDatabaseSidArray(token,begindate,enddate)
   
    console.log(idresultOrderSid)
 
    
    
   next();
     // Продовжуємо виконання, якщо JSON правильний
  } else {
    res.status(400).json({ message: 'Invalid JSON' });
  }
};


// Middleware для перевірки коректності отриманих даних
const validateRequest = (req, res, next) => {
  const { token } = req.query; // Наприклад, очікуємо токен в запиті

  if (token !=null) {
    let obj = JSON.parse(token);

  
    clientTCP.write(iconv.encode(createOBXSegment(obj), 'windows-1251'));
   next();
     // Продовжуємо виконання, якщо JSON правильний
  } else {
    res.status(400).json({ message: 'Invalid JSON' });
  }
};

const validatedescription = async (req, res, next) => { 
 
  
  next();
 
};

const validateUnits = async (req, res, next) => { 
 
  
  next();
 
};

const validateQuery = (req, res, next) => {
  const { token } = req.query; // Наприклад, очікуємо токен в запиті

  if (token !=null && token != undefined) {
     try {let obj = JSON.parse(token);
      barcodearray = [];
      barcodearray = obj;
    createQueryMessage(obj);
   // setTimeout(()=>{next();},3000)\
   const main = async () => {
    if (!clientTCP.destroyed){
    await checkCondition();
  
    console.log('Дані отримано і опрацьовано! Виконуємо наступні дії...'); 
    console.log('Зєднання з LIS активне: ' + !clientTCP.destroyed)
    condition = false;
    barcodecount = 0;
     next()
    // Тут можна виконати наступні дії
  
  } 
    else {res.status(400).json({message: 'Connection error', code: 'ECONNREFUSED'})}// Чекаємо, поки умова не стане true
    
  
  };
   main();
 
    } 
    catch (error) {res.status(400).json({message: 'Invalid request'})} // Продовжуємо виконання, якщо JSON правильний
  } else {
    res.status(400).json({ message: 'Invalid JSON' });
  }
};


const basicAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
      return res.sendStatus(401); // Unauthorized
  }

  const [scheme, credentials] = authHeader.split(' ');
  if (scheme !== 'Basic' || !credentials) {
      return res.sendStatus(401); // Unauthorized
  }

  const buffer = Buffer.from(credentials, 'base64');
  const [username, password] = buffer.toString().split(':');
 
  // Тут ви можете перевірити, чи правильні логін і пароль

switch (username)  {

case 'Omega': if (password === 'Onelab-Omega'){next();} else {return res.status(403).json({ error: "Невірний пароль" }); }// Forbidden
break;

// Тут добавляємо кейси для інших віртуальних аналізаторів. Перевірка авторизації з Фронта

default:
 
  
res.status(401).json({ error: "Невірний логін" })


}

}

  


app.get('/units',  basicAuth, validateUnits, async (req, res) => {

  const decription = await queryDatabaseUnits()
  res.send(unitsresultsParse(decription));
  
 } ),



// Використовуємо middleware на певному маршруті
app.get('/description',  basicAuth, validatedescription, async (req, res) => {

  const decription = await queryDatabaseDescription()
  res.send(decriptionresultsParse(decription));
  
 } ),
app.get('/test',  basicAuth,validateRequest, (req, res) => {
  res.status(200).json({ message: 'Valid JSON'
  
   });
 
});
app.get('/testdevid', basicAuth, validateTestdevId,(req, res) => {
  res.send(idresult.rows);
  
  // res.status(200).json({ message: 'Valid JSON'
  
  //  });
 
});

app.get('/order',  basicAuth,validateOrder,(req, res) => {
  res.send(idresultOrder.rows);
  
  // res.status(200).json({ message: 'Valid JSON'
  
  //  });
 
});
app.get('/ordersid', basicAuth,validateOrderSid,(req, res) => {
  res.send(idresultOrderSid);
  
  // res.status(200).json({ message: 'Valid JSON'
  
  //  });
 
});
app.get('/query', basicAuth, validateQuery, (req, res) => {
 
  
  res.status(200).json({ 
    message: 'Valid JSON',
    test: responsejob
   });
   responsejob = {};
   counter = 0
   counterjob = 0;
   
});


//console.log(JSON.stringify(testDataArray));

const ACK = `\x0BMSH|^~\&|Mindray|BS-330|||${getCurrentFormattedDate()}||ACK^Q03|1|P|2.3.1||||0||ASCII|||\rMSA|AA|1|Message accepted|||0|\rERR|0|\r\x1C\x0D`
// Підключення до сервера
jsonData = await readFileAsync();
async function Connection(){
  jsonData = await readFileAsync();
const client = createConnection({ port: jsonData.ServerPort, 
  host: jsonData.ServerIp, timeout: Number(jsonData.Timeout) }, () => {
    clientTCP = client
  console.log('Підключено до Lis сервера', 'на порту ' +  jsonData.ServerPort);



});
client.on('data', async (data) => {
  await handleClientData(data);

});

// Обробка закриття з'єднання
client.on('end', () => {
  console.log('Зєднання закрито');
});

// Відслідковування помилок з'єднання

client.on('error', (err) => {
  //console.error();
  logger.error(`Помилка підключення: ${err.message}`)
  console.log('Спроба повторного з\'єднання через 2 хвилини');
  setTimeout(() => {
    jsonData =  readFileAsync();
   clientTCP =  Connection(); // Повторна спроба підключитися після помилки через 2 хвилини
  }, 1000); // 2 хвилини
});
 // Відслідковування розриву з'єднання
client.on('close', (hadError) => {
  if (!hadError) {
    console.log('З\'єднання закрито, спроба повторного з\'єднання через 5 секунд');
    setTimeout(() => {
 
     clientTCP =  Connection(); // Повторна спроба підключитися після звичайного розриву
    }, 1000); // 5 секунд
  }
});


return client}




// Обробка даних, отриманих від сервера


clientTCP = Connection();

const handleClientData = async (data) => {
  try {
    console.log(`Отримано: ${data}`);

    let gettype = getHL7MessageType(data.toString());

    if (gettype != null) {
      let stringarr = gettype[0];

      if (stringarr[0] === 'DSR^Q03') {
        counterjob += 1;

        // Якщо MessageHL7Parser є асинхронною функцією, додаємо await
        const parsedMessage =  MessageHL7Parser(data.toString());

        responsejob[counterjob] = parsedMessage;

        console.log('Відправлено:' + ' ACK^Q03');
        
        // Якщо є асинхронні операції з client.write, можна обгорнути у проміс
        clientTCP.write(`\x0BMSH|^~\&|Mindray|BS-330|||${stringarr[1]}||ACK^Q03|1|P|2.3.1||||0||ASCII|||\rMSA|AA|${stringarr[2]}|Message accepted|||0|\rERR|0|\r\x1C\x0D`);
       
      } else if (
        stringarr == 'QCK^Q02'){
       // console.log('No info for barcode');
        const parsedMessage = parseHL7MessageQAK(data.toString());

       // responsejob[counterjob] = parsedMessage;
      // console.log(responsejob)
      // console.log('TEST_NK')

      } else {
        console.log('Hellllllllllllllll');
      }
    } else {
      console.log('Невідомий тип повідомлення');
    }

    // Якщо необхідно обробити результат після парсингу
   
   // console.log( MessageHL7Parser(data.toString()));
  } catch (error) {
    logger.error(console.error('Error processing client data:', error));
  }
};



function MessageHL7Parser (messtring) {


 
  const TESTarray = [];
  const hl7Parser = (hl7Message) => {
      // Розділити повідомлення на сегменти
      const segments = hl7Message.split('\r');
      const parsedMessage = {};
  
      segments.forEach(segment => {
          // Визначити тип сегмента
          const segmentType = segment.slice(0, 3);
          // Розділити сегмент на поля
          const fields = segment.split('|');
  
          // Додати сегмент до об'єкта
          if (!parsedMessage[segmentType]) {
              parsedMessage[segmentType] = [];
          }
  
          // Додати поля сегмента до об'єкта
          const parsedFields = {};
          fields.forEach((field, index) => {
              parsedFields[`field${index + 1}`] = field;
          });
  
          parsedMessage[segmentType].push(parsedFields);
      });
  
      return parsedMessage;
  };
  
  // Приклад HL7 повідомлення
  
  
  // Виклик парсера
  const parsedHL7 = hl7Parser(messtring.trim());
  //console.log(JSON.stringify(parsedHL7, null, 2));

  for (let key in parsedHL7) {
     switch (key){
      case 'MSA': 
  
      parsedHL7[key].forEach(
  
            
        item=> {
            
            if (item['field2'] = 'АА') {
                console.log((parsedHL7.QAK)[0].field3)

                  
                  
            } })
      break;
      case 'DSP' :

     
     
       
      parsedHL7[key].forEach(
  
          
  
  
          item=> {
              
              if (item["field2"] >=30) {
                  console.log(`Поле: ${key} ${item["field2"]}, Код тесту: `, item["field4"].slice(0,-3))
                      TESTarray.push(item["field4"].slice(0,-3))
              } })
              //console.log(parsedHL7["DSP"]["20"]['field4'])
              TESTarray.unshift(parsedHL7["DSP"]["20"]['field4'])


              // тут первірка на кількість баркодів і повернень на них для передачі в response

                barcodearray.forEach(item => {

                  if (item == parsedHL7["DSP"]["20"]['field4'] ){
                     barcodecount += 1;
                  } 

                  if (barcodecount == barcodearray.length){
                    condition = true}

                })


              break;
  
  }
  }

  
return TESTarray



}

function getHL7MessageType(hl7Message) {
  try {
    const cleanedMessage = hl7Message.replace(/\x0B/g, '').replace(/\r/g, '').replace(/\x1C/g, '');
    // Поділ повідомлення на рядки
    const segments = cleanedMessage.split('\n');

    // Пошук MSH сегмента
    const mshSegment = segments.find(
      segment => segment.startsWith('MSH'));

    if (!mshSegment) {
      throw new Error('Не знайдено MSH сегмента');
    }

    // Поділ MSH сегмента на поля за допомогою розділювача '|'
    const mshFields = mshSegment.split('|');

    // Перевірка, чи є достатньо полів для визначення типу повідомлення
    if (mshFields.length < 9) {
      throw new Error('Неправильний формат MSH сегмента');
    }

    // Витягування поля MSH-9 (тип повідомлення)
    const messageType = mshFields[8];
    // Витягування поля MSA-2 (АА - АСК)
    const MSAAcknoedlgement = mshFields[21];

    if (!messageType) {
      throw new Error('Не вдалося визначити тип повідомлення');
    }
      if (MSAAcknoedlgement == 'AA') {
        
        if (messageType == 'DSR^Q03') 
       { let typearray = [mshFields[8],mshFields[9],mshFields[36]]
        
        
        return [typearray]} 
        else {
          return [mshFields[8]]}

       }
      else {
        return [mshFields[8]];}
    
  } catch (error) {
    console.error('Помилка при парсингу HL7 повідомлення:', error.message);
    return null;
  }
}
async function queryDatabaseSidArray(Device,begin,end) {
 oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
  let connection;

  try {
    // Підключення до бази даних Oracle
    jsonData =  await readFileAsync();
    connection = await oracledb.getConnection({
      user: jsonData.DbUser,     // Ваш логін до Oracle
      password: jsonData.DbPassword, // Ваш пароль
      connectString: jsonData.ConnectString // Рядок підключення до бази даних
    });

    console.log('Successfully connected to Oracle database.');

    // Виконання запиту
    const result = await connection.execute(
      `WITH Parameters AS (
    SELECT ${Device} AS DeviceName FROM dual
),
LatestEvent AS (
    SELECT ev.idobject AS evId,
           ev."Обладнання",
           ev.parent,
           ROW_NUMBER() OVER (PARTITION BY ev.parent ORDER BY ev."Час" DESC) AS rn
    FROM "#ПОДІЇ ТЕСТУ" ev
    WHERE ev."Тип" = KLabVars.AAT_PREPARED_FOR_EQUIPMENT_ID
),
DeviceTestCode AS (
   SELECT es."Назва", ks."Код"
   FROM "#ОБЛАДНАННЯ" ts
   JOIN "#ТЕСТИ ОБЛАДНАННЯ" ks ON ks.parent = ts.idobject
   JOIN "#ЕКСПЕРТИЗИ" es ON es.idobject = ks."Тест"
   JOIN Parameters p ON ts."Назва" = p.DeviceName
     WHERE ks."Пріоритет" = '1' AND ks."Активний" = '1'
),
FilteredExams AS (
    SELECT exams.*, 
           expe."Назва" AS "Дослідження",
           expe."Опис результату" AS "Опис",
           pt."Повна назва",
           pt."Стать",
           pt."Дата народження",
           d."Штрих-код",
           sta."Назва",
           pe."Експертиза",
           ev.evId,
           NVL(ev."Обладнання", eq."Обладнання") AS eqId
    FROM "#ОБСТЕЖЕННЯ" exams
    JOIN "#ПЕРЕЛІК ЕКСПЕРТИЗ" pe ON exams.idobject = pe.parent
    JOIN "#ОБСТЕЖЕННЯ_Пробірки" d ON exams.idobject = d.parent AND pe."Пробірка" = d.idobject
    JOIN "#СТАТУСИ" sta ON sta.idobject = pe."Статус"
    JOIN "#ПАЦІЄНТИ" pt ON pt.idobject = exams."Пацієнт"
    JOIN "#ЕКСПЕРТИЗИ" expe ON expe.idobject = pe."Експертиза"
    LEFT JOIN LatestEvent ev ON pe.idobject = ev.parent AND ev.rn = 1
    LEFT JOIN "#КОЛ.ОБЛАДНАННЯ" eq ON ev.evId = eq.parent
    WHERE exams.docdate BETWEEN TO_DATE(${begin}, 'DD-MM-YYYY') AND TO_DATE(${end}, 'DD-MM-YYYY')
      AND exams.deleted = 0
      AND sta."Назва" NOT IN ('перевірено', 'виконано', 'відмінено', 'в роботі')
)
SELECT  t."Штрих-код",
        TRUNC(MONTHS_BETWEEN(SYSDATE, t."Дата народження") / 12) || ' р.' AS "Вік",  
        t.DOCDATE AS "Дата реєстрації",
        t."Дата забору", 
          CASE 
           WHEN t."Стать" = 'ж' THEN 'жіноча'
           WHEN t."Стать" = 'ч' THEN 'чоловіча'
           ELSE t."Стать"
       END AS "Стать", 
        t."Повна назва",
       
         t."Опис",
         t."Експертиза" AS "ID_Експертизи",
        t."Дослідження",
        dev."Код"
FROM FilteredExams t 
JOIN "#ОБЛАДНАННЯ" eq ON t.eqId = eq.idobject
JOIN DeviceTestCode dev ON dev."Назва" = t."Дослідження"
JOIN Parameters p ON eq."Назва" = p.DeviceName` 


  
    )
  
    return result


  } catch (err) {
    logger.error(console.error(err));
  } finally {
    if (connection) {
      try {
        // Закриття підключення
        await connection.close();
      } catch (err) {
       logger.error( console.error(err));
      }
    }
  }
}


async function queryDatabaseUnits() {
  oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
   let connection;
 
   try {
     // Підключення до бази даних Oracle
     connection = await oracledb.getConnection({
       user: jsonData.DbUser,     // Ваш логін до Oracle
       password: jsonData.DbPassword, // Ваш пароль
       connectString: jsonData.ConnectString // Рядок підключення до бази даних
     });
 
     console.log('Successfully connected to Oracle database.');
 
     // Виконання запиту
     const result = await connection.execute(
       `select ov."Назва" from "#ОДИНИЦІ ВИМІРУ" ov` 
 
 
   
     )
   
     return result
 
 
   } catch (err) {
     logger.error(console.error(err));
   } finally {
     if (connection) {
       try {
         // Закриття підключення
         await connection.close();
       } catch (err) {
        logger.error( console.error(err));
       }
     }
   }
 }





async function queryDatabaseDescription() {
  oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
   let connection;
 
   try {
     // Підключення до бази даних Oracle
     connection = await oracledb.getConnection({
       user: jsonData.DbUser,     // Ваш логін до Oracle
       password: jsonData.DbPassword, // Ваш пароль
       connectString: jsonData.ConnectString // Рядок підключення до бази даних
     });
 
     console.log('Successfully connected to Oracle database.');
 
     // Виконання запиту
     const result = await connection.execute(
       `SELECT a."Назва" AS "Аналіз",ex.idobject As "IDexp",ex."Назва" AS "Дослідження" , r.idobject AS "IDdescr",r."Назва", rn."Значення"
FROM "#ОПИСИ РЕЗУЛЬТАТІВ" r
JOIN "#ОПИСИ РЕЗУЛЬТАТІВ_Значення" rn ON rn.parent = r.idobject 
JOIN "ЕКСПЕРТИЗИ" ex ON ex."Опис результату"  = r.IDOBJECT 
JOIN "#АНАЛІЗИ_Експертизи" tt ON tt."Експертиза" = ex.IDOBJECT
JOIN "#АНАЛІЗИ" a ON a.idobject = tt.PARENT 
ORDER BY "Аналіз" desc` 
 
 
   
     )
   
     return result
 
 
   } catch (err) {
     logger.error(console.error(err));
   } finally {
     if (connection) {
       try {
         // Закриття підключення
         await connection.close();
       } catch (err) {
        logger.error( console.error(err));
       }
     }
   }
 }
async function queryDatabase(Device) {
  oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
  let connection;

  try {
    jsonData = await readFileAsync();
    // Підключення до бази даних Oracle
    connection = await oracledb.getConnection({
      user: jsonData.DbUser,     // Ваш логін до Oracle
      password: jsonData.DbPassword, // Ваш пароль
      connectString: jsonData.ConnectString // Рядок підключення до бази даних
    });

    console.log('Successfully connected to Oracle database.');

    // Виконання запиту
    const result = await connection.execute(
      `SELECT o."Експертиза_NM", o."Код", o."Обладнання_NM"
FROM "ЕКСПЕРТИЗИ ОБЛАДН" o WHERE o."Обладнання_NM" = ${Device}` 


  
    )
  
    return result


  } catch (err) {
    logger.error(console.error(err));
  } finally {
    if (connection) {
      try {
        // Закриття підключення
        await connection.close();
      } catch (err) {
       logger.error( console.error(err));
      }
    }
  }
}

async function queryDatabaseOrder(Barcode,DeviceName) {
  oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
  let connection;

  try {
    // Підключення до бази даних Oracle
    connection = await oracledb.getConnection({
      user: jsonData.DbUser,     // Ваш логін до Oracle
      password: jsonData.DbPassword, // Ваш пароль
      connectString: jsonData.ConnectString // Рядок підключення до бази даних
    });

    console.log('Successfully connected to Oracle database.');

    // Виконання запиту
    const result = await connection.execute(
      `SELECT   t."Аналіз_NM" AS "Аналіз", 
       u."Експертиза_NM" AS "Показник",
       d."Повна назва"  AS "Пацієнт", 
            CASE 
           WHEN d."Стать" = 'ж' THEN 'жіноча'
           WHEN d."Стать" = 'ч' THEN 'чоловіча'
           ELSE d."Стать"
       END AS "Стать", 
       TRUNC(MONTHS_BETWEEN(SYSDATE, d."Дата народження") / 12) || ' р.' as "Вік", 
       k."DOCDATE" as "Дата реєстрації", 
       k."Дата забору" AS "Дата забору крові", 
       s1."Штрих-код",
       o."Назва" AS "Виконавець",
       s3."Код"     
     --  s3."Пріоритет",
     --  s3."Активний"
FROM "ОБСТЕЖЕННЯ_Аналізи" t
LEFT JOIN "#ОБСТЕЖЕННЯ" k ON t."PARENT" = k."IDOBJECT" 
LEFT JOIN "#ПАЦІЄНТИ" d ON k."Пацієнт" = d."IDOBJECT"
LEFT JOIN "#ОБСТЕЖЕННЯ_Пробірки" s1 ON s1."PARENT" = k."IDOBJECT"
LEFT JOIN "АНАЛІЗИ" s2 ON t."Аналіз" = s2."IDOBJECT"
LEFT JOIN "АНАЛІЗИ_Експертизи" u ON u."PARENT" = t."Аналіз"
LEFT JOIN "#ТЕСТИ ОБЛАДНАННЯ" s3 on  u."Експертиза"= s3."Тест" 
Left join "ОБЛАДНАННЯ" o on  o."IDOBJECT" = s3."PARENT"                              
WHERE s1."Штрих-код" = ${Barcode} 
AND o."Назва" = ${DeviceName}
And s3."Пріоритет"   = '1'
And s3."Активний" = '1'
` 


  
    )
  
    return result


  } catch (err) {
    logger.error(console.error(err));
  } finally {
    if (connection) {
      try {
        // Закриття підключення
        await connection.close();
      } catch (err) {
       logger.error( console.error(err));
      }
    }
  }
}

function getCurrentFormattedDate() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');

  return `${year}${month}${day}${hours}${minutes}${seconds}`;
}

function createOBXSegment(testDataArray) {
  let testdescription;
 
  let typeValues
  const counterbar = checkBarcodes(testDataArray);
  console.log(counterbar);
  const segments = [];

  testDataArray.forEach((test, index) => {
   let indexcountbarcode = counterbar[test.Barcode]
   if ((Number(test.value))) {typeValues = "NM"} 
   else { typeValues = "ST"}

    // Збираємо дані для OBX сегменту        \rOBR|1|112830480031|7|Mindray^BS-330|N||20241007113540||||||||Serum|||||||||||||||||||||||||||||||||\r
    const obxSegment = [
      `\x0BMSH|^~\&|Cloud|Omega|||${getCurrentFormattedDate()}||ORU^R01|${PID}|P|2.3.1||||0||ASCII||`,
      `\rPID|${PID}|||||||||||||||||||||||||||||`,
      `\rOBR|1|${test.Barcode}|${indexcountbarcode}|Cloud^Omega|N||${getCurrentFormattedDate()}||||||||Serum|||||||||||||||||||||||||||||||||` ,
      '\rOBX', // Назва сегменту
      '1', // Порядковий номер OBX
      `${typeValues}`, // Тип даних (наприклад, NM - числовий)
      `${test.testCode}`, // Ідентифікатор тесту
      `${test.testName}`, // Sub-ID компоненти (якщо не потрібне, залишаємо порожнім)
      `${test.value}`, // Значення тесту
      `${test.unit ? test.unit : '' || ''}`, // Одиниці виміру (опційно)
      `${test.Ref ? test.Ref : ''}`, 'Normal', '', `${test.description ? test.description : ''}`, // Резервні поля для додаткових даних
      'F','' ,
      `${test.value}`,
       `${test.Barcode}`,'','','',`\r\x1C\x0D`// Статус результату (F - фінальний)
    ].join('|');
      PID += 1;
    // Додаємо створений OBX сегмент до масиву
    segments.push(obxSegment);
    
  });
indexcount +=1;
  // Повертаємо масив OBX сегментів, об'єднаний символом переносу рядка
  return segments.join('');
  
}
function checkBarcodes(dataArray) {
  const barcodeCounters = {}; // Об'єкт для зберігання лічильників для кожного баркоду
  let counter = 0; // Глобальний лічильник різних баркодів

  dataArray.forEach(item => {
    const { Barcode } = item;

    if (!barcodeCounters[Barcode]) {
      // Якщо такий Barcode ще не зустрічався, збільшуємо лічильник
      counter++;
      barcodeCounters[Barcode] = counter; // Зберігаємо значення лічильника для цього баркоду
    }
  });

  return barcodeCounters; // Повертаємо об'єкт з лічильниками для кожного баркоду
}

function unitsresultsParse (objdecription){
  const transformedDataUnits = [];

  objdecription.rows.forEach(row => {
    const {Назва} = row;
    transformedDataUnits.push(Назва)

   
  });

  //console.log(JSON.stringify(transformedDataUnits, null, 2));
  return transformedDataUnits;
}

function decriptionresultsParse (objdecription){
  const transformedData = {};

  objdecription.rows.forEach(row => {
    const { Аналіз, IDexp, Дослідження, IDdescr, Назва, Значення } = row;

    // Створюємо об'єкт для аналізу, якщо він не існує
    if (!transformedData[Аналіз]) {
      transformedData[Аналіз] = {};
    }

    // Створюємо об'єкт для дослідження в межах аналізу, якщо він не існує
    if (!transformedData[Аналіз][Дослідження]) {
      transformedData[Аналіз][Дослідження] = {
        "ID експертизи": IDexp,
        "ID опису": IDdescr
      };
    }

    // Перевіряємо, чи є масив для відповідного Назва, якщо ні, ініціалізуємо його
    if (!transformedData[Аналіз][Дослідження][Назва]) {
      transformedData[Аналіз][Дослідження][Назва] = [];
    }

    // Додаємо значення до масиву для відповідного Назва
    transformedData[Аналіз][Дослідження][Назва].push(Значення);
  });

  console.log(JSON.stringify(transformedData, null, 2));
  return transformedData;
}





function createQueryMessage(query){

  query.forEach(item =>{

const hl7 = [`\x0BMSH|^~\&|Cloud|Omega|||${getCurrentFormattedDate()}||QRY^Q02|${counter}|P|2.3.1||||0||ASCII|||`,
    `QRD|${getCurrentFormattedDate()}|R|D|${counter}|||RD|${item}|OTH|||T|`,
    `QRF|BS-330|${getCurrentFormattedDate()}|${getCurrentFormattedDate()}|||RCT|COR|ALL||\x1C\x0D`].join('\r')
    console.log(`Відправлено: ${getHL7MessageType(hl7)}`)
    console.log('Відправлено' + hl7)
   // console.log(typeof(hl7))
    clientTCP.write(String(hl7));
    querybarcodePID[counter] = item;
    counter +=1;
    setTimeout(()=>{},2000)
  })

  


}

function parseHL7MessageQAKPID(hl7Message) {
  // Розбиваємо повідомлення на сегменти
  const segments = hl7Message.split('\r').map(seg => seg.trim());

  // Перебираємо кожен сегмент
  for (let segment of segments) {
      const fields = segment.split('|');

      // Перші три символи — це ім'я сегмента (MSH, MSA, ERR, QAK тощо)
      const segmentType = fields[8];

      // Шукаємо сегмент QAK і повертаємо третє поле
      if (segmentType === 'QCK^Q02') {
          return fields[9]; // Поле QAK.3
      }
  }

  // Якщо сегмент QAK не знайдено
  return null;
}
function parseHL7MessageQAK(hl7Message) {
  segmentPID = []
  // Розбиваємо повідомлення на сегменти
  const segments = hl7Message.split('\r').map(seg => seg.trim());

  // Перебираємо кожен сегмент
  for (let segment of segments) {
      const fields = segment.split('|');

      // Перші три символи — це ім'я сегмента (MSH, MSA, ERR, QAK тощо)
      const segmentType = fields[0];

      // Шукаємо сегмент QAK і повертаємо третє поле
      if (segmentType == 'QAK' && fields[2] != 'OK') {
        //resarray=[];
       // counterjob +=1;
       barcodecount +=1;


        segmentPID.push(String(fields[2]));


        responsejob[barcodecount] =  segmentPID; 
        if (barcodecount == barcodearray.length){
         // console.log(querybarcodePID)
          condition = true}
      } else if (segmentType == 'MSH'){
      
        segmentPID.push(String(querybarcodePID[fields[9]]))
      //  console.log(querybarcodePID[fields[9]])


      }
  }

  // Якщо сегмент QAK не знайдено
  return null;
}
function sortAndAggregate(data) {
    // Створюємо об'єкт для зберігання агрегованих записів
    const aggregated = {};

    data.rows.forEach(item => {
        const barcode = item["Штрих-код"];

        if (!aggregated[barcode]) {
            const { ID_Експертизи, Опис, Код, ...itemWithoutCode } = item;

            aggregated[barcode] = {
                ...itemWithoutCode,
                Дослідження: [{
                    Name: item.Дослідження,
                    Properties: [{
                        Код: Код,
                        ID_Опис_результату: Опис,
                        ID_Дослідження: ID_Експертизи
                    }]
                }]
            };
        } else {
            // Шукаємо дослідження з такою ж назвою
            let existingResearch = aggregated[barcode].Дослідження.find(d => d.Name === item.Дослідження);

            // Якщо дослідження з такою назвою ще немає, додаємо новий об'єкт
            if (!existingResearch) {
                existingResearch = {
                    Name: item.Дослідження,
                    Properties: []
                };
                aggregated[barcode].Дослідження.push(existingResearch);
            }

            // Додаємо новий об'єкт у Properties, якщо такого коду ще немає
            const existingCodes = existingResearch.Properties.map(prop => prop.Код);
            if (!existingCodes.includes(item.Код)) {
                existingResearch.Properties.push({
                    Код: item.Код,
                    ID_Опис_результату: item.Опис,
                    ID_Дослідження: item.ID_Експертизи
                });
            }
        }
    });

    // Отримуємо результат у вигляді масиву, сортуємо за Штрих-кодом
    const result = Object.values(aggregated);
    result.sort((a, b) => a["Штрих-код"].localeCompare(b["Штрих-код"]));

    return result;
}


//const PORT = 3000;
app.listen(Number(jsonData.HL7Port), () => {
  console.log(`HL7 емулятор запущено на порту ${jsonData.HL7Port}`);
});




