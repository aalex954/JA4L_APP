from flask import Flask, render_template
import sqlite3
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
Bootstrap(app)
CSRFProtect(app)
Talisman(app, content_security_policy=None)

# Function to execute secure database queries
def execute_db(query, params=()):
    conn = sqlite3.connect('fingerprints.db')
    c = conn.cursor()
    c.execute(query, params)
    results = c.fetchall()
    conn.close()
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/show_info')
def show_info():
    records = execute_db('SELECT ip, ja4l_fingerprint, ja4t_fingerprint, ja4_fingerprint, ja4l_a, hop_count, distance FROM fingerprints ORDER BY timestamp DESC LIMIT 10')
    return render_template('info.html', records=records)

@app.route('/analytics')
def analytics():
    fingerprints = execute_db('SELECT ja4_fingerprint, COUNT(*) as count FROM fingerprints GROUP BY ja4_fingerprint ORDER BY count DESC')
    metrics = {'unique_fingerprints': len(fingerprints), 'total_sessions': sum(f[1] for f in fingerprints)}
    return render_template('analytics.html', fingerprints=fingerprints, metrics=metrics)

if __name__ == '__main__':
    # Run Flask on port 5000 to ensure it's separate from the packet sniffing process
    app.run(host='0.0.0.0', port=5000, debug=True)

