from flask import Flask, request, session, render_template
import requests

def lookup_ip_info(ip):
    try:
        url = f"https://ipwho.is/{ip}"
        response = requests.get(url, timeout=3)

        # If the API returns a non-200 status, print the details
        if response.status_code != 200:
            print("HTTP Error:", response.status_code)
            print("Response text:", response.text)
            return {}

        data = response.json()

        # ipwho.is includes a "success" field
        if not data.get("success", True):
            print("API Error:", data.get("message"))
            return {}

        print (data)
        return data


    except Exception as e:
        print("Exception occurred:", e)
        return {}


lookup_ip_info("24.166.23.174")

