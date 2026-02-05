from flask import Flask

app = Flask(__name__)
app.secret_key = "pixelforge-secret-key"

@app.route("/")
def home():
    return "PixelForge Nexus is running securely!"

if __name__ == "__main__":
    app.run(debug=True)
