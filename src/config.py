import json

with open("configuration.json") as conf:
    configuration = json.load(conf)
    SECRET_KEY = configuration["jwt_secret"]
    ADMIN_PASSWORD = configuration["admin_password"]
