package main

import (
	_ "SmartPark/docs"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"regexp"
	"text/template"
	"time"
)

// @Summary Test template
// @Description Test template endpoint (requires authentication)
// @Accept plain
// @Produce plain
// @Param body body string false "Template body"
// @Success 200 {string} string "When Success"
// @Failure 500 {string} string "Error"
// @Router /test [post]
func templateTest(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to read request body")
		return
	}
	if len(body) == 0 {
		body = []byte("Welcome, server time: {{.Result}}")
	}
	f := newQuery()
	f.DbCall("SELECT now();")

	tmpl := template.Must(template.New("text").Parse(string(body)))
	c.Writer.WriteHeader(http.StatusOK)
	tmpl.Execute(c.Writer, f)
}

// @Summary Send source code file
// @Description Send source file endpoint (requires authentication)
// @Accept plain
// @Produce octet-stream
// @Router /backup [get]
func srcSend(c *gin.Context) {
	filePath := "/tmp/src.zip"
	c.File(filePath)
}

// @Summary Add new account
// @Description Add new account endpoint, do not use weak pass or short username
// @Accept x-www-form-urlencoded
// @Produce plain
// @Param username formData string true "Username"
// @Param password formData string true "Password"
// @Success 200 {string} string "Success"
// @Failure 403 {string} string "Failure reasons"
// @Router /account [post]
func accountAddition(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	//check
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9]{6,}$`)
	passwordRegex := regexp.MustCompile(`^[a-zA-Z0-9]{8,}$`)

	if !usernameRegex.MatchString(username) {
		c.String(http.StatusForbidden, "Username is not valid")
		return
	}

	if !passwordRegex.MatchString(password) {
		c.String(http.StatusForbidden, "Password is not valid")
		return
	}

	sql := fmt.Sprintf("INSERT INTO users (username, password) VALUES ('%s', '%s');", username, password)

	f := newQuery()
	f.DbCall(sql)

	c.JSON(http.StatusOK, f)
}

// @Summary Delete account
// @Description Delete account endpoint
// @Accept plain
// @Produce plain
// @Param id path string true "Account ID"
// @Success 200 {string} string "Success"
// @Failure 403 {string} string "Failure reasons"
// @Router /account [delete]
func accountDeletion(c *gin.Context) {

	id := c.Param("id")

	//check
	regex := regexp.MustCompile(`^[0-9]+$`)

	if !regex.MatchString(id) {
		c.String(http.StatusForbidden, "ID is not valid")
		return
	}

	sql := fmt.Sprintf("DELETE FROM users WHERE id=%s;", id)

	f := newQuery()
	f.DbCall(sql)

	c.JSON(http.StatusOK, f)
}

// @Summary Query parking information
// @Description Query parking information endpoint
// @Accept x-www-form-urlencoded
// @Produce plain
// @Param plate path string true "Plate number"
// @Success 200 {string} string "Success"
// @Failure 403 {string} string "Failure reasons"
// @Router /vehicleInfo [get]
func parkingQuery(c *gin.Context) {
	plate := c.Param("plate")

	if plate == "" {
		c.String(http.StatusForbidden, "Plate number required")
		return
	}

	//check
	plateRegex := regexp.MustCompile(`/^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领]{1}[A-Z]{5}[A-Z0-9]$/`)

	if !plateRegex.MatchString(plate) {
		c.String(http.StatusForbidden, "Plate number is not valid")
		return
	}

	sql := fmt.Sprintf("SELECT * FROM vehicle_info WHERE plate = '%s';", plate)
	f := newQuery()
	f.DbCall(sql)
	c.JSON(http.StatusOK, f)
}

// @Summary Add new parking information
// @Description Add new parking information endpoint
// @Accept x-www-form-urlencoded
// @Produce plain
// @Param driver_id formData string true "Driver ID"
// @Param driver_name formData string true "Driver Name"
// @Param plate formData string true "Plate Number"
// @Param describe formData string false "Description"
// @Success 200 {string} string "Success"
// @Failure 403 {string} string "Failure reasons"
// @Router /vehicleInfo [post]
func parkingAddition(c *gin.Context) {
	driverID := c.PostForm("driver_id")
	driverName := c.PostForm("driver_name")
	plate := c.PostForm("plate")
	describe := c.PostForm("describe")

	//check
	idRegex := regexp.MustCompile(`^[0-9]+$`)
	nameRegex := regexp.MustCompile("^[a-zA-Z\\p{Han}]+$")
	plateRegex := regexp.MustCompile(`/^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领]{1}[A-Z]{5}[A-Z0-9]$/`)
	descRegex := regexp.MustCompile("^[a-zA-Z ]+$")

	if !idRegex.MatchString(driverID) {
		c.String(http.StatusForbidden, "Driver ID is not valid")
		return
	}

	if !nameRegex.MatchString(driverName) {
		c.String(http.StatusForbidden, "Driver name is not valid")
		return
	}

	if !plateRegex.MatchString(plate) {
		c.String(http.StatusForbidden, "Plate content is not valid")
		return
	}

	if !descRegex.MatchString(describe) {
		c.String(http.StatusForbidden, "Describe is not valid")
		return
	}

	sql := fmt.Sprintf("INSERT INTO vehicle_info (driver_id, driver_name, plate, describe) VALUES (%s, '%s', '%s', '%s');", driverID, driverName, plate, describe)
	f := newQuery()
	f.DbCall(sql)

	c.JSON(http.StatusOK, f)
}

// @Summary Delete parking information
// @Description Delete parking information endpoint
// @Accept x-www-form-urlencoded
// @Produce plain
// @Param id path string true "Parking ID"
// @Success 200 {string} string "Success"
// @Failure 403 {string} string "Failure reasons"
// @Router /vehicleInfo [delete]
func parkingDeletion(c *gin.Context) {
	id := c.Param("id")

	//check
	regex := regexp.MustCompile(`^[0-9]+$`)

	if !regex.MatchString(id) {
		c.String(http.StatusForbidden, "ID is not valid")
		return
	}

	sql := fmt.Sprintf("DELETE FROM vehicle_info WHERE id=%s;", id)

	f := newQuery()
	f.DbCall(sql)

	// 返回成功或失败的响应
	c.JSON(http.StatusOK, f)
}

// @Summary User login
// @Description User login endpoint
// @Accept x-www-form-urlencoded
// @Produce plain
// @Param username formData string true "Username"
// @Param password formData string true "Password"
// @Param captcha_key formData string true "Captcha Key"
// @Param captcha_token formData string true "Captcha Token"
// @Success 200 {string} string "Success"
// @Failure 403 {string} string "Failure reasons"
// @Router /login [post]
func login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	captchaKey := c.PostForm("captcha_key")
	captchaToken := c.PostForm("captcha_token")

	usernameRegex := regexp.MustCompile("^[a-zA-Z0-9]{6,}$")
	passwordRegex := regexp.MustCompile(`^[a-zA-Z0-9]{8,}$`)
	keyRegex := regexp.MustCompile(`^[A-Z0-9]{4}$`)
	tokenRegex := regexp.MustCompile(`^[A-Z0-9]{16}$`)

	if !usernameRegex.MatchString(username) {
		c.String(http.StatusForbidden, "Username is not valid")
		return
	}

	if !passwordRegex.MatchString(password) {
		c.String(http.StatusForbidden, "Password is not valid")
		return
	}

	if !keyRegex.MatchString(captchaKey) {
		c.String(http.StatusForbidden, "Captcha key is not valid")
		return
	}

	if !tokenRegex.MatchString(captchaToken) {
		c.String(http.StatusForbidden, "Captcha token is not valid")
		return
	}

	captchaExists := queryCaptcha(captchaKey, captchaToken)

	if !captchaExists {
		c.String(http.StatusForbidden, "Invalid captcha")
		return
	}

	userExists, correctPassword := queryUser(username, password)

	if !userExists {
		c.String(http.StatusForbidden, "User not found")
		return
	}

	if !correctPassword {
		c.String(http.StatusForbidden, "Incorrect password")
		return
	}

	jwtToken, err := genAuth(username)
	if err != nil {
		c.String(http.StatusForbidden, "Generate auth token failed")
		return
	}

	c.Header("Authorization", jwtToken)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// @Summary Generate new captcha
// @Description Generate new captcha endpoint
// @Accept plain
// @Produce json
// @Success 200 {string} string "Success"
// @Router /captcha [get]
func newCaptcha(c *gin.Context) {
	key, token := genCaptcha()
	sql := fmt.Sprintf("INSERT INTO captcha (key, token) VALUES ('%s', '%s');", key, token)
	f := newQuery()
	f.DbCall(sql)
	c.JSON(http.StatusOK, gin.H{"key": key, "token": token, "time": time.Now()})
}
