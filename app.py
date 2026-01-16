import os
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                "https://impromptuindian.com",
                "https://apparels.impromptuindian.com",
                "https://vendor.impromptuindian.com",
                "https://rider.impromptuindian.com",
                "https://support.impromptuindian.com",
            ]
        }
    }
)

app.config["DEBUG"] = os.environ.get("DEBUG", "False") == "True"

@app.route("/test", methods=["GET"])
def test_api():
    return jsonify({
        "status": "success",
        "message": "Backend API is live!"
    })

# Only for local testing (ignored by Passenger)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

