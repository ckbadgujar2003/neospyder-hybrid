from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import os
import sys


def get_driver():
    chrome_options = Options()

    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("--silent")
    chrome_options.add_argument("--disable-logging")

    # suppress selenium logs
    service = Service(
        log_path=os.devnull
    )

    driver = webdriver.Chrome(
        service=service,
        options=chrome_options
    )

    return driver