// ab_analyzer

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/hjson/hjson-go"
	"github.com/kpango/glg"
)

type listToBanStruct struct {
	siteid uint
	ip     uint
}

func main() {
	mainConfig := readCfgFile("config.json") // чтение конфигурации
	var dbConnect = mainConfig["dbUser"].(string) + ":" + mainConfig["dbPsw"].(string) + "@tcp(" + mainConfig["dbAddress"].(string) + ":" + FloatToString(mainConfig["dbPort"].(float64)) + ")/" + mainConfig["dbBase"].(string)

	//	установки log-файла
	infolog := glg.FileWriter("ab_analyzer.log", 0666) // открытие лог.файла
	defer infolog.Close()
	//	customLevel := "FINE"
	customErrLevel := "CRIT"
	glg.Get().
		SetMode(glg.BOTH). // default is STD
		AddWriter(infolog).
		SetWriter(infolog).
		SetLevelColor(glg.TagStringToLevel(customErrLevel), glg.Red) // set color output to user custom level
	//	завершение установки log-файла

	// Initializing DB connection
	db, err := sql.Open("mysql", dbConnect)
	checkErr(err)
	defer db.Close()
	db.SetConnMaxLifetime(time.Second * 100)

	// обработчик параметров коммандной строки
	switch flagOperate() {
	case "daily":
		beginTime := logSQLStart(db, 0) // создание статуса начала работы
		glg.Infof("[%s,%s] %s", "D", beginTime, "DAILY mode")
		glg.Infof("[%s,%s] %s", "D", beginTime, "started looking for ban ip")

		query := "SELECT siteid, ip AS visits FROM allvisits WHERE ownervisit=0 AND DATE >= UNIX_TIMESTAMP(NOW())-86400 GROUP BY ip, siteid HAVING COUNT(ip) > ? ORDER BY COUNT(ip) DESC"
		listToBan := mainReqToGetBanList(db, query, uint(mainConfig["maxDailyConnect"].(float64)))
		glg.Infof("[%s,%s] %s", "D", beginTime, "finished looking for ban ip, begin update banlist")

		updateBanlistInBase(db, listToBan, "D", beginTime, 0)

		glg.Infof("[%s,%s] %s", "D", beginTime, "finihed banlist update")
		logSQLFinish(db, beginTime, 0) // обновление статуса завершения работы

	case "hourly":
		beginTime := logSQLStart(db, 1) // создание статуса начала работы
		glg.Infof("[%s,%s] %s", "H", beginTime, "HOURLY mode")
		glg.Infof("[%s,%s] %s", "H", beginTime, "started looking for ban ip")

		query := "SELECT siteid, ip AS visits FROM allvisits WHERE ownervisit=0 AND DATE >= UNIX_TIMESTAMP(NOW())-3600 GROUP BY ip, siteid HAVING COUNT(ip) > ? ORDER BY COUNT(ip) DESC"
		listToBan := mainReqToGetBanList(db, query, uint(mainConfig["maxHourlyConnect"].(float64)))
		glg.Infof("[%s,%s] %s", "H", beginTime, "finished looking for ban ip, begin update banlist")

		updateBanlistInBase(db, listToBan, "H", beginTime, 0)

		glg.Infof("[%s,%s] %s", "H", beginTime, "finihed banlist update")
		logSQLFinish(db, beginTime, 1) // обновление статуса завершения работы

	case "10m":
		beginTime := logSQLStart(db, 2) // создание статуса начала работы
		glg.Infof("[%s,%s] %s", "10M", beginTime, "10m mode")
		glg.Infof("[%s,%s] %s", "10M", beginTime, "started looking for ban ip")

		query := "SELECT siteid, ip FROM allvisits WHERE ownervisit=0 AND DATE >= UNIX_TIMESTAMP(NOW())-600 GROUP BY ip, siteid HAVING COUNT(ip) > ? ORDER BY COUNT(ip) DESC"
		listToBan := mainReqToGetBanList(db, query, uint(mainConfig["max10mConnect"].(float64)))
		glg.Infof("[%s,%s] %s", "10M", beginTime, "finished looking for ban ip, begin update banlist")

		updateBanlistInBase(db, listToBan, "10M", beginTime, 0)

		glg.Infof("[%s,%s] %s", "10M", beginTime, "finihed banlist update")
		logSQLFinish(db, beginTime, 2) // обновление статуса завершения работы
	}
}

// ###########################
// обновление банлиста в базе
func updateBanlistInBase(db *sql.DB, listToBan map[uint]listToBanStruct, logCurrentMode string, logBeginTime string, reason uint) {
	if len(listToBan) > 0 {
		glg.Infof("[%s,%s] %s", logCurrentMode, logBeginTime, "updating banlist")
		for i, _ := range listToBan {
			stmt, err := db.Prepare("INSERT INTO blacklistip SET siteid = ?, ip = ?, reason = ? ON DUPLICATE KEY UPDATE ban_count = ban_count + 1 AND lastupdate = NOW()")
			checkErr(err)

			res, err := stmt.Exec(listToBan[i].siteid, listToBan[i].ip, reason)
			checkErr(err)
			_ = res
		}
	} else {
		glg.Infof("[%s,%s] %s", logCurrentMode, logBeginTime, "nothing to update in banlist")

	}
}

// чтение содержимого файла
func readFile(filename string) string {
	configFileText, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	str := string(configFileText)
	return str
}

// чтение конфиг файла
func readCfgFile(filename string) map[string]interface{} {
	configFileText, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	var dat map[string]interface{}
	// Decode and a check for errors.
	if err := hjson.Unmarshal(configFileText, &dat); err != nil {
		panic(err)
	}

	return dat
}

// обработчик параметров коммандной строки
func flagOperate() string {
	var flagSum uint
	var retVar string

	// обработка флагов
	flagDaily := flag.Bool("daily", false, "process daily analyze")
	flagHourly := flag.Bool("hourly", false, "process hourly analyze")
	flag10m := flag.Bool("10m", false, "process every 10 minutes analyze")

	flag.Parse()
	if *flagDaily == true {
		flagSum++
		retVar = "daily"
	}
	if *flagHourly == true {
		flagSum++
		retVar = "hourly"
	}
	if *flag10m == true {
		flagSum++
		retVar = "10m"
	}
	if *flagDaily == false && *flagHourly == false && *flag10m == false {
		fmt.Println("Missing required parameters. Use -h for help.")
		os.Exit(0)
	}
	if flagSum > 1 {
		fmt.Println("Too many parameters. Use -h for help.")
		os.Exit(0)
	}
	return retVar
}

// to convert a float number to a string
func FloatToString(input_num float64) string {
	return strconv.FormatFloat(input_num, 'f', 0, 64)
}

// to convert a float number to uint
func FloatToUint(input_num float64) uint {
	return uint(input_num)
}

// запись в базу времени начала работы
func logSQLStart(db *sql.DB, flagMode uint) string { // db *sql.DB,
	beginTime := returnTimestamp()
	// flagMode 0 - daily
	// flagMode 1 - hourly
	// flagMode 2 - 10m
	stmt, err := db.Prepare("INSERT ab_analyzer_status SET flagmode=?, begin=FROM_UNIXTIME(?)")
	checkErr(err)
	res, err := stmt.Exec(flagMode, beginTime)
	checkErr(err)
	_ = res
	return beginTime
}

// запись в базу времени окончания работы
func logSQLFinish(db *sql.DB, beginTime string, flagMode uint) {
	// flagMode 0 - daily
	// flagMode 1 - hourly
	// flagMode 2 - 10m
	stmt, err := db.Prepare("UPDATE ab_analyzer_status SET finish=FROM_UNIXTIME(?) WHERE flagmode=? AND begin=FROM_UNIXTIME(?)")
	checkErr(err)
	res, err := stmt.Exec(returnTimestamp(), flagMode, beginTime)
	checkErr(err)
	_ = res
}

// возвращает timestamp в виде строки
func returnTimestamp() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

// проверка ошибок
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// запрос на анализ и получение бан листа
func mainReqToGetBanList(db *sql.DB, query string, maxConnections uint) map[uint]listToBanStruct { // тут надо возвращать массив, а не map
	listToBan := make(map[uint]listToBanStruct)
	var (
		count  uint
		ip     uint
		siteid uint
	)

	mainQuery, err := db.Query(query, maxConnections)
	//	mainDailyQuery, err := db.Query("SELECT siteid, ip, COUNT(ip) AS visits FROM allvisits WHERE ownervisit=0 AND DATE >= UNIX_TIMESTAMP(NOW())-86400 GROUP BY ip, siteid HAVING `visits` > ? ORDER BY visits DESC", maxDailyConnect)
	checkErr(err)
	defer mainQuery.Close()
	for mainQuery.Next() {
		err := mainQuery.Scan(&siteid, &ip)
		checkErr(err)
		listToBan[count] = listToBanStruct{
			siteid: siteid,
			ip:     ip}
		count++
	}
	return listToBan
}

// ipv4 2 int64
func IP4toInt(ipv4 string) int64 {
	IPv4Address := net.ParseIP(ipv4)
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

// int64 2 ipv4
func InttoIP4(ipInt int64) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((ipInt & 0xff), 10)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

// примеры сообщений в лог файл и на экран
//	glg.Info("info")
//	glg.Infof("%s : %s", "info", "formatted")
//	glg.Log("log")
//	glg.Logf("%s : %s", "info", "formatted")
//	glg.Debug("debug")
//	glg.Debugf("%s : %s", "info", "formatted")
//	glg.Warn("warn")
//	glg.Warnf("%s : %s", "info", "formatted")
//	glg.Error("error")
//	glg.Errorf("%s : %s", "info", "formatted")
//	glg.Success("ok")
//	glg.Successf("%s : %s", "info", "formatted")
//	glg.Fail("fail")
//	glg.Failf("%s : %s", "info", "formatted")
//	glg.Print("Print")
//	glg.Println("Println")
//	glg.Printf("%s : %s", "printf", "formatted")
//	glg.CustomLog(customLevel, "custom logging")
//	glg.CustomLog(customErrLevel, "custom error logging")
