from flask import Flask, render_template, request, redirect, url_for, flash
import os

app = Flask(__name__, static_url_path='/static')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'secret')

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
