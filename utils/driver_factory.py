from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import shutil
import os


def get_driver():

    chrome_options = Options()

    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-logging")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("--window-size=1920,1080")

    # Detect chromium location (GitHub runner)
    chrome_binary = shutil.which("chromium-browser") or shutil.which("chromium")

    if chrome_binary:
        chrome_options.binary_location = chrome_binary

    service = Service(log_path=os.devnull)

    driver = webdriver.Chrome(
        service=service,
        options=chrome_options
    )

    return driver
