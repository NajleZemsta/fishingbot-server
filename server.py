from flask import Flask, send_from_directory, jsonify

app = Flask(__name__, static_folder="static")

@app.route("/version.json")
def version():
    return send_from_directory("static", "version.json", mimetype="application/json")

@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory("static", filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
