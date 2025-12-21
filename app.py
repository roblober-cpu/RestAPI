from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message":"Hello from Flask API!"})

if __name__ == "__main__":
    #Listen on all interfaces, port 5000
    app.run(host="0.0.0.0", port=5000)
