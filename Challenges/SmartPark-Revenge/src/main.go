package main

import (
	docs "SmartPark/docs"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"net/http"
)

func setupRouter() *gin.Engine {
	r := gin.Default()

	docs.SwaggerInfo.BasePath = "/"

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Greetings from miniL 2024 ^^")
	})
	r.POST("/test", AuthMiddleware(), templateTest)
	r.GET("/backup", AuthMiddleware(), srcSend)
	r.POST("/account", accountAddition)
	r.DELETE("/account", accountDeletion)
	r.GET("/vehicleInfo", parkingQuery)
	r.POST("/vehicleInfo", parkingAddition)
	r.DELETE("/vehicleInfo", parkingDeletion)
	r.POST("/login", login)
	r.GET("/captcha", newCaptcha)
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	return r
}

func setupDb() {
	q := newQuery()
	sql := `
CREATE TABLE IF NOT EXISTS captcha (
	id SERIAL PRIMARY KEY,
	key VARCHAR(255) NOT NULL,
	token VARCHAR(255) NOT NULL,
	timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
	id SERIAL PRIMARY KEY,
	username VARCHAR(255) NOT NULL,
	password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS vehicle_info (
	id SERIAL PRIMARY KEY,
	driver_id INT NOT NULL,
	driver_name VARCHAR(255) NOT NULL,
	plate VARCHAR(255) NOT NULL,
	describe TEXT
);

CREATE OR REPLACE VIEW captcha_view AS
	SELECT * FROM captcha
	WHERE timestamp >= NOW() - INTERVAL '15 minutes';

INSERT INTO users (username, password) VALUES ('master', 'I_3m_The_Gre3t_M3steR_0F_PArkINg_Lot!!');

INSERT INTO vehicle_info (driver_id, driver_name, plate, describe) VALUES (1, 'Mr.K', '京A88888', 'Hacked by Mr.K :)');
    `
	q.DbCall(sql)
}

// @title SmartParkingDBMS
// @version		1.0
// @license.name Apache 2.0

func main() {
	setupDb()
	r := setupRouter()
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}
