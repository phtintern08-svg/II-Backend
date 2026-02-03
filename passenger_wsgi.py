import os
import traceback
import importlib.util

# ✅ Load .env file explicitly (Passenger doesn't load it automatically)
from dotenv import load_dotenv

# backend/ directory (this is the project root)
PROJECT_ROOT = os.path.dirname(__file__)

# ✅ Load .env file explicitly (Passenger-safe)
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
load_dotenv(ENV_PATH)

# app.py lives directly inside backend/
APP_FILE = os.path.join(PROJECT_ROOT, "app.py")

captured_error = None

try:
    spec = importlib.util.spec_from_file_location("app", APP_FILE)
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)

    if hasattr(app_module, "app"):
        application = app_module.app
    elif hasattr(app_module, "application"):
        application = app_module.application
    else:
        raise AttributeError(
            "app.py loaded but no 'app' or 'application' variable found"
        )

except Exception as e:
    captured_error = str(e) + "\n\n" + traceback.format_exc()

# Fallback WSGI app to show error in browser
if captured_error:
    def application(environ, start_response):
        start_response(
            "500 Internal Server Error",
            [("Content-Type", "text/plain")]
        )
        body = "DEPLOYMENT FAILED\n\n" + captured_error
        return [body.encode("utf-8")]


