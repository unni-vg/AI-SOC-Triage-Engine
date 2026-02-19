from flask import Flask, render_template
from ioc_extractor import run_engine

app = Flask(__name__)

@app.route("/")
def dashboard():
    alerts = run_engine()
    return render_template("index.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)
