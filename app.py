from flask import Flask, render_template

from search import api_search
from graph import make_graph

app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')

app.register_blueprint(api_search)
app.register_blueprint(make_graph)



