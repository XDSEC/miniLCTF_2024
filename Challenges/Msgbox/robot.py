import os
from urllib.parse import urlparse

from selenium.common import NoSuchElementException
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class AdminBot:
    def __init__(self, flag, username, password, url, driver):
        self.flag = flag
        self.username = username
        self.password = password
        self.domain = urlparse(url).netloc.split(':')[0]
        self.url = url

        # self.driver = webdriver.Chrome(options=self.chrome_options)
        # self.driver = webdriver.Remote(command_executor='http://chrome:4444/wd/hub', options=self.chrome_options)
        self.driver = driver

    def check(self):
        try:
            # flag
            cookie = {'name': 'flag', 'value': self.flag, 'domain': self.domain}
            print("bot: getting url `" + self.url + '`')
            self.driver.get(self.url)
            print("bot: setting cookie with flag = " + self.flag)
            self.driver.add_cookie(cookie)

            print("bot: login")
            self.driver.get(self.url + 'login')

            print("bot: wait loading of page")
            wait = WebDriverWait(self.driver, 10)
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, '.form-wrapper')))

            print("bot: enter account")
            username_input = self.driver.find_element(By.CSS_SELECTOR, 'input[name="username"]')
            password_input = self.driver.find_element(By.CSS_SELECTOR, 'input[name="password"]')
            username_input.send_keys(self.username)
            password_input.send_keys(self.password)

            print("bot: press login")
            login_btn = self.driver.find_element(By.ID, 'loginBtn')
            login_btn.click()

            print("bot: wait for redirect")
            wait.until(EC.url_to_be(self.url + 'inbox'))

            print("bot: find the first message and click its link")
            first_message_link = self.driver.find_element(By.CSS_SELECTOR, 'ul li:first-child a')
            first_message_link.click()

            print("bot: wait message page load")
            wait.until(EC.presence_of_element_located((By.ID, 'content')))

            print("bot: finding msg content")
            message_content = self.driver.find_element(By.ID, 'content').text
            print("bot: msg content `" + message_content + "`")
            page = self.driver.page_source
            print("bot: msg page `" + page + "`")
            return "success"
        except NoSuchElementException:
            print("bot: no messages received")
            return 'no messages yet...'
        except Exception as e:
            print("bot: error encountered when visiting")
            print(e)
            # return str(e)
            return "error reading content..."


if __name__ == '__main__':
    admin_user = 'admin'
    admin_pass = '1O6Xy4VvLHTBNu2GbSYEzfxt'
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument('--ignore-certificate-errors')
    print("bot local test: loading driver")
    driver = webdriver.Remote(command_executor='http://127.0.0.1:4444/wd/hub',
                              options=chrome_options)
    print("bot local test: instancing bot")
    checker = AdminBot(os.getenv('FLAG', 'flag{testflag}'), admin_user, admin_pass,
                       'http://web:5000/', driver)
    res = checker.check()
    print("bot: msg visit result: " + res)

    print("bot local test: quiting driver")
    driver.quit()