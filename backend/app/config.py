import json

with open("configuration.json") as conf:
    configuration = json.load(conf)
    SECRET_KEY = configuration["jwt_secret"]
    ADMIN_PASSWORD = configuration["admin_password"]
    SMTP_SERVER = configuration["smtp_server"]
    SMTP_PORT = configuration["smtp_port"]
    EMAIL = configuration["email"]
    EMAIL_PASSWORD = configuration["email_password"]
    SERVICE_NAME = configuration["service_name"]
