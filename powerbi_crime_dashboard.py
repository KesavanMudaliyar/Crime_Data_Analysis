from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for, make_response
from flask_socketio import SocketIO, emit
import pandas as pd
import sqlite3
import hashlib
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import base64
import io
from datetime import datetime
import numpy as np
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# User authentication system
users = {
    'admin': {
        'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  # 'password'
        'role': 'admin',
        'access_level': 'full'
    },
    'analyst': {
        'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  # 'password'
        'role': 'analyst',
        'access_level': 'read_write'
    },
    'viewer': {
        'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  # 'password'
        'role': 'viewer',
        'access_level': 'read_only'
    }
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# File paths
CSV_PATH = "CrimesOnWomenData.csv"
DB_PATH = "crimes.db"
TABLE_NAME = "CrimesOnWomenData"

# Authentication decorators
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'user' not in session or users[session['user']]['access_level'] not in ['full']:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def write_access_required(f):
    def decorated_function(*args, **kwargs):
        if 'user' not in session or users[session['user']]['access_level'] not in ['full', 'read_write']:
            return jsonify({"error": "Write access required"}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Data management functions
def initialize_data():
    """Initialize sample data if CSV doesn't exist"""
    if not os.path.exists(CSV_PATH):
        # Create sample data matching your database structure
        data = {
            'Id': range(1001, 1051),  # 50 records
            'State': ['UTTAR PRADESH', 'MAHARASHTRA', 'WEST BENGAL', 'BIHAR', 'RAJASTHAN',
                     'MADHYA PRADESH', 'TAMIL NADU', 'KARNATAKA', 'ANDHRA PRADESH', 'GUJARAT'] * 5,
            'Year': [2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024] * 5,
            'Rape': np.random.randint(1000, 5000, 50),
            'KidnapAndAbduction': np.random.randint(500, 2000, 50),
            'DowryDeaths': np.random.randint(50, 300, 50),
            'AssaultOnWomen': np.random.randint(2000, 8000, 50),
            'AssaultOnMinors': np.random.randint(100, 1000, 50),
            'DomesticViolence': np.random.randint(5000, 15000, 50),
            'WomenTrafficking': np.random.randint(20, 200, 50)
        }
        df = pd.DataFrame(data)
        df.to_csv(CSV_PATH, index=False)
        return df
    return pd.read_csv(CSV_PATH)

def read_csv():
    """Read CSV data with error handling"""
    try:
        df = pd.read_csv(CSV_PATH)
        # Ensure proper column names and data types
        df.columns = df.columns.str.strip()
        
        # Ensure numeric columns are properly formatted
        numeric_columns = ['Id', 'Year', 'Rape', 'KidnapAndAbduction', 'DowryDeaths', 
                          'AssaultOnWomen', 'AssaultOnMinors', 'DomesticViolence', 'WomenTrafficking']
        
        for col in numeric_columns:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
        
        return df
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return initialize_data()

def sync_to_sql():
    """Sync CSV to SQLite database"""
    df = read_csv()
    conn = sqlite3.connect(DB_PATH)
    df.to_sql(TABLE_NAME, conn, if_exists="replace", index=False)
    conn.close()

def generate_powerbi_visuals():
    """Generate Power BI style visualizations"""
    df = read_csv()
    charts = {}
    
    try:
        # Color scheme similar to Power BI
        powerbi_colors = ['#00BCF2', '#8B5CF6', '#06D6A0', '#FFD60A', '#FF006E', '#FB5607', '#8338EC']
        
        # 1. KPI Cards - Total Records and Sum metrics
        total_records = len(df)
        total_kidnap = df['KidnapAndAbduction'].sum()
        
        # KPI Card 1: Count of Id
        kpi_fig1 = go.Figure()
        kpi_fig1.add_trace(go.Indicator(
            mode="number",
            value=total_records,
            title={"text": "Count of Id", "font": {"size": 20}},
            number={'font': {'size': 60, 'color': '#00BCF2'}},
            domain={'x': [0, 1], 'y': [0, 1]}
        ))
        kpi_fig1.update_layout(
            height=200, width=300,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor="white",
            font=dict(color="#323130", family="Segoe UI")
        )
        charts['kpi_count'] = base64.b64encode(kpi_fig1.to_image(format="png")).decode('utf-8')

        # KPI Card 2: Sum of KidnapAndAbduction
        kpi_fig2 = go.Figure()
        kpi_fig2.add_trace(go.Indicator(
            mode="number",
            value=total_kidnap,
            title={"text": "Sum of KidnapAndAbduction", "font": {"size": 16}},
            number={'font': {'size': 50, 'color': '#8B5CF6'}},
            domain={'x': [0, 1], 'y': [0, 1]}
        ))
        kpi_fig2.update_layout(
            height=200, width=350,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor="white",
            font=dict(color="#323130", family="Segoe UI")
        )
        charts['kpi_kidnap'] = base64.b64encode(kpi_fig2.to_image(format="png")).decode('utf-8')

        # 2. Sum of Year (Donut Chart)
        year_sum = df.groupby('Year').size().reset_index(name='count')
        donut_fig = px.pie(year_sum, values='count', names='Year', hole=0.6,
                          color_discrete_sequence=powerbi_colors)
        donut_fig.update_layout(
            title="Sum of Year",
            height=300, width=350,
            showlegend=True,
            paper_bgcolor="white",
            font=dict(color="#323130", family="Segoe UI")
        )
        donut_fig.add_annotation(
            text=f"{df['Year'].sum():,}", x=0.5, y=0.5, showarrow=False,
            font=dict(size=30, color="#323130")
        )
        charts['year_donut'] = base64.b64encode(donut_fig.to_image(format="png")).decode('utf-8')

        # 3. Line Chart - Crime trends by State
        state_crimes = df.groupby('State')[['DomesticViolence', 'AssaultOnWomen', 'DowryDeaths']].sum().reset_index()
        
        line_fig = go.Figure()
        line_fig.add_trace(go.Scatter(x=state_crimes['State'], y=state_crimes['DomesticViolence'],
                                     mode='lines+markers', name='Sum of DomesticViolence',
                                     line=dict(color='#8B5CF6', width=3),
                                     marker=dict(size=8)))
        line_fig.add_trace(go.Scatter(x=state_crimes['State'], y=state_crimes['AssaultOnWomen'],
                                     mode='lines+markers', name='Sum of AssaultOnWomen',
                                     line=dict(color='#06D6A0', width=3),
                                     marker=dict(size=8)))
        line_fig.add_trace(go.Scatter(x=state_crimes['State'], y=state_crimes['DowryDeaths'],
                                     mode='lines+markers', name='Sum of DowryDeaths',
                                     line=dict(color='#00BCF2', width=3),
                                     marker=dict(size=8)))
        
        line_fig.update_layout(
            title="Sum of DomesticViolence, Sum of AssaultOnWomen and Sum of DowryDeaths by State",
            height=400, width=800,
            xaxis_title="State",
            yaxis_title="Sum of Crimes",
            xaxis_tickangle=-45,
            paper_bgcolor="white",
            plot_bgcolor="white",
            font=dict(color="#323130", family="Segoe UI"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        line_fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='#E5E5E5')
        line_fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='#E5E5E5')
        charts['line_chart'] = base64.b64encode(line_fig.to_image(format="png")).decode('utf-8')

        # 4. Map visualization (simulated with bar chart)
        map_data = df.groupby('State').agg({
            'Id': 'count',
            'DomesticViolence': 'sum',
            'AssaultOnWomen': 'sum'
        }).reset_index()
        
        map_fig = px.bar(map_data, x='State', y='Id',
                        title='Count of Id, Sum of DomesticViolence and Sum of AssaultOnWomen by State',
                        color_discrete_sequence=['#8B5CF6'])
        map_fig.update_layout(
            height=300, width=400,
            xaxis_tickangle=-45,
            paper_bgcolor="white",
            font=dict(color="#323130", family="Segoe UI")
        )
        charts['map_chart'] = base64.b64encode(map_fig.to_image(format="png")).decode('utf-8')

        # 5. Treemap for comprehensive view
        treemap_data = df.groupby(['State', 'Year']).agg({
            'Rape': 'sum',
            'KidnapAndAbduction': 'sum',
            'DomesticViolence': 'sum',
            'AssaultOnWomen': 'sum'
        }).reset_index()
        
        treemap_fig = px.treemap(treemap_data, 
                                path=['State', 'Year'], 
                                values='DomesticViolence',
                                title='Crime Distribution by State and Year',
                                color='AssaultOnWomen',
                                color_continuous_scale='Viridis')
        treemap_fig.update_layout(
            height=400, width=600,
            paper_bgcolor="white",
            font=dict(color="#323130", family="Segoe UI")
        )
        charts['treemap'] = base64.b64encode(treemap_fig.to_image(format="png")).decode('utf-8')

        # 6. Comprehensive metrics table
        metrics_summary = df.agg({
            'Id': 'count',
            'Rape': 'sum',
            'KidnapAndAbduction': 'sum',
            'DowryDeaths': 'sum',
            'AssaultOnWomen': 'sum',
            'AssaultOnMinors': 'sum',
            'DomesticViolence': 'sum',
            'WomenTrafficking': 'sum'
        }).to_dict()
        
        charts['metrics'] = metrics_summary

    except Exception as e:
        print(f"Error generating charts: {e}")
    
    return charts

# Authentication routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username in users and users[username]['password'] == hash_password(password):
            session['user'] = username
            session['role'] = users[username]['role']
            session['access_level'] = users[username]['access_level']
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# Main dashboard route
@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    df = read_csv()
    charts = generate_powerbi_visuals()
    user_info = users[session['user']]
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                df=df, 
                                charts=charts, 
                                user_info=user_info,
                                session=session)

# Data management routes
@app.route("/add_record", methods=["POST"])
@write_access_required
def add_record():
    try:
        df = read_csv()
        
        # Generate new ID
        new_id = df['Id'].max() + 1 if len(df) > 0 else 1001
        
        # Get form data
        new_record = {
            'Id': new_id,
            'State': request.form.get('State', '').upper(),
            'Year': int(request.form.get('Year', 2024)),
            'Rape': int(request.form.get('Rape', 0)),
            'KidnapAndAbduction': int(request.form.get('KidnapAndAbduction', 0)),
            'DowryDeaths': int(request.form.get('DowryDeaths', 0)),
            'AssaultOnWomen': int(request.form.get('AssaultOnWomen', 0)),
            'AssaultOnMinors': int(request.form.get('AssaultOnMinors', 0)),
            'DomesticViolence': int(request.form.get('DomesticViolence', 0)),
            'WomenTrafficking': int(request.form.get('WomenTrafficking', 0))
        }
        
        # Add to dataframe
        df = pd.concat([df, pd.DataFrame([new_record])], ignore_index=True)
        df.to_csv(CSV_PATH, index=False)
        sync_to_sql()
        
        # Emit update to all clients
        charts = generate_powerbi_visuals()
        socketio.emit('data_updated', {'charts': charts, 'message': 'Record added successfully'})
        
        return jsonify({"status": "success", "message": "Record added successfully", "new_id": new_id})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/update_record", methods=["POST"])
@write_access_required
def update_record():
    try:
        df = read_csv()
        record_id = int(request.form.get('Id'))
        column = request.form.get('column')
        new_value = request.form.get('value')
        
        if record_id not in df['Id'].values:
            return jsonify({"status": "error", "message": "Record not found"}), 404
        
        # Convert value to appropriate type
        if column in ['Id', 'Year', 'Rape', 'KidnapAndAbduction', 'DowryDeaths', 
                     'AssaultOnWomen', 'AssaultOnMinors', 'DomesticViolence', 'WomenTrafficking']:
            new_value = int(new_value)
        
        # Update the record
        df.loc[df['Id'] == record_id, column] = new_value
        df.to_csv(CSV_PATH, index=False)
        sync_to_sql()
        
        # Emit update to all clients
        charts = generate_powerbi_visuals()
        socketio.emit('data_updated', {'charts': charts, 'message': 'Record updated successfully'})
        
        return jsonify({"status": "success", "message": "Record updated successfully"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/delete_record", methods=["POST"])
@admin_required
def delete_record():
    try:
        df = read_csv()
        record_id = int(request.form.get('Id'))
        
        if record_id not in df['Id'].values:
            return jsonify({"status": "error", "message": "Record not found"}), 404
        
        # Delete the record
        df = df[df['Id'] != record_id]
        df.to_csv(CSV_PATH, index=False)
        sync_to_sql()
        
        # Emit update to all clients
        charts = generate_powerbi_visuals()
        socketio.emit('data_updated', {'charts': charts, 'message': 'Record deleted successfully'})
        
        return jsonify({"status": "success", "message": "Record deleted successfully"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/add_column", methods=["POST"])
@admin_required
def add_column():
    try:
        df = read_csv()
        column_name = request.form.get('column_name')
        default_value = request.form.get('default_value', '')
        
        if column_name in df.columns:
            return jsonify({"status": "error", "message": "Column already exists"}), 400
        
        # Add new column
        df[column_name] = default_value
        df.to_csv(CSV_PATH, index=False)
        sync_to_sql()
        
        return jsonify({"status": "success", "message": "Column added successfully"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('status', {'msg': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# Templates
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Crime Analytics - Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .login-header h1 {
            color: #333;
            margin-bottom: 0.5rem;
        }
        
        .login-header p {
            color: #666;
            font-size: 0.9rem;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn-login {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 1rem;
            cursor: pointer;
            transition: opacity 0.3s;
        }
        
        .btn-login:hover {
            opacity: 0.9;
        }
        
        .demo-accounts {
            margin-top: 1.5rem;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 5px;
            font-size: 0.85rem;
        }
        
        .error {
            color: #dc3545;
            text-align: center;
            margin-bottom: 1rem;
            padding: 0.5rem;
            background: #f8d7da;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🚨 Crime Analytics</h1>
            <p>Power BI Style Dashboard</p>
        </div>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn-login">Login</button>
        </form>
        
        <div class="demo-accounts">
            <strong>Demo Accounts:</strong><br>
            • admin / password (Full Access)<br>
            • analyst / password (Read/Write)<br>
            • viewer / password (Read Only)
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Crimes Against Women - Data Analysis Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.0/socket.io.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f3f2f1;
            color: #323130;
            line-height: 1.4;
        }
        
        .header {
            background: #ffffff;
            padding: 1rem 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 3px solid #0078d4;
        }
        
        .header h1 {
            color: #323130;
            font-size: 1.8rem;
            font-weight: 600;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 0.9rem;
        }
        
        .user-badge {
            background: #e1f5fe;
            color: #0277bd;
            padding: 0.3rem 0.8rem;
            border-radius: 15px;
            font-weight: 500;
        }
        
        .nav-bar {
            background: #ffffff;
            padding: 0.5rem 2rem;
            display: flex;
            gap: 1rem;
            border-bottom: 1px solid #edebe9;
        }
        
        .nav-btn {
            padding: 0.5rem 1rem;
            background: #f3f2f1;
            border: 1px solid #d2d0ce;
            border-radius: 3px;
            text-decoration: none;
            color: #323130;
            transition: all 0.2s;
            font-size: 0.9rem;
        }
        
        .nav-btn:hover {
            background: #0078d4;
            color: white;
            border-color: #0078d4;
        }
        
        .dashboard-container {
            padding: 1.5rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 300px 350px 1fr;
            grid-template-rows: 200px 300px auto;
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .widget {
            background: #ffffff;
            border-radius: 8px;
            padding: 1rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid #edebe9;
        }
        
        .widget-title {
            font-size: 1rem;
            font-weight: 600;
            color: #323130;
            margin-bottom: 0.8rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #f3f2f1;
        }
        
        .kpi-widget {
            grid-column: 1;
            grid-row: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
        }
        
        .kpi-value {
            font-size: 3rem;
            font-weight: 700;
            color: #0078d4;
            margin: 0.5rem 0;
        }
        
        .kpi-label {
            font-size: 0.9rem;
            color: #605e5c;
            margin-bottom: 0.5rem;
        }
        
        .donut-widget {
            grid-column: 2;
            grid-row: 1;
        }
        
        .line-chart-widget {
            grid-column: 1 / -1;
            grid-row: 2;
        }
        
        .map-widget {
            grid-column: 3;
            grid-row: 1;
        }
        
        .data-management {
            background: #ffffff;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
        }
        
        .management-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 1rem;
        }
        
        .management-section {
            background: #faf9f8;
            padding: 1rem;
            border-radius: 6px;
            border-left: 4px solid #0078d4;
        }
        
        .management-section h4 {
            color: #323130;
            margin-bottom: 1rem;
            font-size: 1.1rem;
        }
        
        .form-group {
            margin-bottom: 0.8rem;
        }
        
        .form-group label {
            display: block;
            font-size: 0.85rem;
            font-weight: 500;
            color: #323130;
            margin-bottom: 0.3rem;
        }
        
        .form-control {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #d2d0ce;
            border-radius: 3px;
            font-size: 0.9rem;
            transition: border-color 0.2s;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #0078d4;
            box-shadow: 0 0 0 2px rgba(0,120,212,0.2);
        }
        
        .btn {
            padding: 0.6rem 1.2rem;
            border: none;
            border-radius: 3px;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }
        
        .btn-primary {
            background: #0078d4;
            color: white;
        }
        
        .btn-primary:hover {
            background: #106ebe;
        }
        
        .btn-success {
            background: #107c10;
            color: white;
        }
        
        .btn-success:hover {
            background: #0e6e0e;
        }
        
        .btn-danger {
            background: #d13438;
            color: white;
        }
        
        .btn-danger:hover {
            background: #b52b2f;
        }
        
        .btn-warning {
            background: #ff8c00;
            color: white;
        }
        
        .btn-warning:hover {
            background: #e67c00;
        }
        
        .data-table {
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-top: 2rem;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        
        .table th {
            background: #0078d4;
            color: white;
            padding: 0.8rem;
            text-align: left;
            font-weight: 600;
        }
        
        .table td {
            padding: 0.6rem 0.8rem;
            border-bottom: 1px solid #edebe9;
        }
        
        .table tr:hover {
            background: #f8f9fa;
        }
        
        .chart-container {
            width: 100%;
            height: 100%;
            display: flex;
            flex-direction: column;
        }
        
        .chart-container img {
            width: 100%;
            height: auto;
            object-fit: contain;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 0.5rem;
            margin-top: 1rem;
        }
        
        .metric-card {
            background: #f8f9fa;
            padding: 0.8rem;
            border-radius: 4px;
            text-align: center;
            border-left: 3px solid #0078d4;
        }
        
        .metric-value {
            font-size: 1.2rem;
            font-weight: 600;
            color: #0078d4;
        }
        
        .metric-label {
            font-size: 0.75rem;
            color: #605e5c;
            margin-top: 0.2rem;
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem;
            border-radius: 5px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            display: none;
        }
        
        .notification.success {
            background: #107c10;
        }
        
        .notification.error {
            background: #d13438;
        }
        
        @media (max-width: 1200px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
                grid-template-rows: auto;
            }
            
            .kpi-widget,
            .donut-widget,
            .line-chart-widget,
            .map-widget {
                grid-column: 1;
                grid-row: auto;
            }
        }
        
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 1rem;
            }
            
            .nav-bar {
                flex-wrap: wrap;
            }
            
            .management-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Crimes Against Women – Data Analysis Dashboard</h1>
        <div class="user-info">
            <span class="user-badge">{{ user_info.role | title }} - {{ session.user }}</span>
            <a href="/logout" class="btn btn-primary">Logout</a>
        </div>
    </div>
    
    <nav class="nav-bar">
        <a href="#dashboard" class="nav-btn">📊 Dashboard</a>
        <a href="#data-table" class="nav-btn">📋 Data Table</a>
        {% if user_info.access_level in ['full', 'read_write'] %}
        <a href="#data-management" class="nav-btn">⚙️ Data Management</a>
        {% endif %}
        {% if user_info.access_level == 'full' %}
        <a href="#admin-panel" class="nav-btn">👥 Admin Panel</a>
        {% endif %}
    </nav>
    
    <div class="dashboard-container">
        <div id="dashboard" class="dashboard-grid">
            <!-- KPI Widget 1 -->
            <div class="widget kpi-widget">
                <div class="widget-title">Count of Id</div>
                <div class="kpi-value">{{ charts.metrics.Id if charts.metrics else 0 }}</div>
                <div class="kpi-label">Total Records</div>
            </div>
            
            <!-- KPI Widget 2 -->
            <div class="widget donut-widget">
                <div class="widget-title">Sum of KidnapAndAbduction</div>
                {% if charts.kpi_kidnap %}
                <div class="chart-container">
                    <img src="data:image/png;base64,{{ charts.kpi_kidnap }}" alt="KidnapAndAbduction KPI">
                </div>
                {% else %}
                <div class="kpi-value">{{ charts.metrics.KidnapAndAbduction if charts.metrics else 0 }}</div>
                {% endif %}
            </div>
            
            <!-- Map Widget -->
            <div class="widget map-widget">
                <div class="widget-title">Sum of Year</div>
                {% if charts.year_donut %}
                <div class="chart-container">
                    <img src="data:image/png;base64,{{ charts.year_donut }}" alt="Year Distribution">
                </div>
                {% else %}
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">{{ df.Year.min() if not df.empty else 'N/A' }}</div>
                        <div class="metric-label">Min Year</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{ df.Year.max() if not df.empty else 'N/A' }}</div>
                        <div class="metric-label">Max Year</div>
                    </div>
                </div>
                {% endif %}
            </div>
            
            <!-- Line Chart Widget -->
            <div class="widget line-chart-widget">
                <div class="widget-title">Sum of DomesticViolence, Sum of AssaultOnWomen and Sum of DowryDeaths by State</div>
                {% if charts.line_chart %}
                <div class="chart-container">
                    <img src="data:image/png;base64,{{ charts.line_chart }}" alt="Crime Trends by State">
                </div>
                {% else %}
                <p style="text-align: center; color: #605e5c; padding: 2rem;">Chart will be generated when data is available</p>
                {% endif %}
            </div>
        </div>
        
        <!-- Additional Charts Row -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
            <div class="widget">
                <div class="widget-title">Count of Id, Sum of DomesticViolence and Sum of AssaultOnWomen by State</div>
                {% if charts.map_chart %}
                <div class="chart-container">
                    <img src="data:image/png;base64,{{ charts.map_chart }}" alt="State-wise Crime Distribution">
                </div>
                {% endif %}
            </div>
            
            <div class="widget">
                <div class="widget-title">Crime Overview Metrics</div>
                {% if charts.metrics %}
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">{{ "{:,}".format(charts.metrics.Rape) }}</div>
                        <div class="metric-label">Total Rape</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{ "{:,}".format(charts.metrics.DomesticViolence) }}</div>
                        <div class="metric-label">Domestic Violence</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{ "{:,}".format(charts.metrics.AssaultOnWomen) }}</div>
                        <div class="metric-label">Assault on Women</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{ "{:,}".format(charts.metrics.AssaultOnMinors) }}</div>
                        <div class="metric-label">Assault on Minors</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{ "{:,}".format(charts.metrics.DowryDeaths) }}</div>
                        <div class="metric-label">Dowry Deaths</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{{ "{:,}".format(charts.metrics.WomenTrafficking) }}</div>
                        <div class="metric-label">Women Trafficking</div>
                    </div>
                </div>
                {% endif %}
            </div>
        </div>
        
        {% if charts.treemap %}
        <div class="widget" style="margin-bottom: 2rem;">
            <div class="widget-title">Crime Distribution by State and Year</div>
            <div class="chart-container">
                <img src="data:image/png;base64,{{ charts.treemap }}" alt="Crime Distribution Treemap">
            </div>
        </div>
        {% endif %}
        
        {% if user_info.access_level in ['full', 'read_write'] %}
        <div id="data-management" class="data-management">
            <h3 style="color: #323130; margin-bottom: 1rem;">🔧 Data Management</h3>
            
            <div class="management-grid">
                <!-- Add Record Section -->
                <div class="management-section">
                    <h4>➕ Add New Record</h4>
                    <form id="add-record-form">
                        <div class="form-group">
                            <label>State</label>
                            <input type="text" name="State" class="form-control" placeholder="e.g., UTTAR PRADESH" required>
                        </div>
                        <div class="form-group">
                            <label>Year</label>
                            <input type="number" name="Year" class="form-control" min="2000" max="2030" value="2024" required>
                        </div>
                        <div class="form-group">
                            <label>Rape Cases</label>
                            <input type="number" name="Rape" class="form-control" min="0" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Kidnap and Abduction</label>
                            <input type="number" name="KidnapAndAbduction" class="form-control" min="0" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Dowry Deaths</label>
                            <input type="number" name="DowryDeaths" class="form-control" min="0" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Assault on Women</label>
                            <input type="number" name="AssaultOnWomen" class="form-control" min="0" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Assault on Minors</label>
                            <input type="number" name="AssaultOnMinors" class="form-control" min="0" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Domestic Violence</label>
                            <input type="number" name="DomesticViolence" class="form-control" min="0" value="0" required>
                        </div>
                        <div class="form-group">
                            <label>Women Trafficking</label>
                            <input type="number" name="WomenTrafficking" class="form-control" min="0" value="0" required>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%;">Add Record</button>
                    </form>
                </div>
                
                <!-- Update Record Section -->
                <div class="management-section">
                    <h4>✏️ Update Record</h4>
                    <form id="update-record-form">
                        <div class="form-group">
                            <label>Record ID</label>
                            <input type="number" name="Id" class="form-control" min="1001" placeholder="Enter ID to update" required>
                        </div>
                        <div class="form-group">
                            <label>Column to Update</label>
                            <select name="column" class="form-control" required>
                                <option value="">Select Column</option>
                                <option value="State">State</option>
                                <option value="Year">Year</option>
                                <option value="Rape">Rape</option>
                                <option value="KidnapAndAbduction">KidnapAndAbduction</option>
                                <option value="DowryDeaths">DowryDeaths</option>
                                <option value="AssaultOnWomen">AssaultOnWomen</option>
                                <option value="AssaultOnMinors">AssaultOnMinors</option>
                                <option value="DomesticViolence">DomesticViolence</option>
                                <option value="WomenTrafficking">WomenTrafficking</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>New Value</label>
                            <input type="text" name="value" class="form-control" placeholder="Enter new value" required>
                        </div>
                        <button type="submit" class="btn btn-success" style="width: 100%;">Update Record</button>
                    </form>
                </div>
                
                {% if user_info.access_level == 'full' %}
                <!-- Delete Record Section -->
                <div class="management-section">
                    <h4>🗑️ Delete Record</h4>
                    <form id="delete-record-form">
                        <div class="form-group">
                            <label>Record ID</label>
                            <input type="number" name="Id" class="form-control" min="1001" placeholder="Enter ID to delete" required>
                        </div>
                        <button type="submit" class="btn btn-danger" style="width: 100%;">Delete Record</button>
                    </form>
                </div>
                
                <!-- Add Column Section -->
                <div class="management-section">
                    <h4>📊 Add New Column</h4>
                    <form id="add-column-form">
                        <div class="form-group">
                            <label>Column Name</label>
                            <input type="text" name="column_name" class="form-control" placeholder="Enter column name" required>
                        </div>
                        <div class="form-group">
                            <label>Default Value</label>
                            <input type="text" name="default_value" class="form-control" placeholder="Default value (optional)">
                        </div>
                        <button type="submit" class="btn btn-warning" style="width: 100%;">Add Column</button>
                    </form>
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}
        
        <!-- Data Table -->
        <div id="data-table" class="data-table">
            <div style="background: #0078d4; color: white; padding: 1rem;">
                <h3 style="margin: 0;">📋 Complete Data Table</h3>
                <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem;">
                    Total Records: {{ df|length }} | 
                    ID Range: {{ df.Id.min() if not df.empty else 'N/A' }} - {{ df.Id.max() if not df.empty else 'N/A' }} | 
                    Years: {{ df.Year.min() if not df.empty else 'N/A' }} - {{ df.Year.max() if not df.empty else 'N/A' }}
                </p>
            </div>
            <div style="overflow-x: auto; max-height: 500px;">
                {{ df.to_html(classes='table', index=False, table_id='data-table-content')|safe }}
            </div>
        </div>
    </div>
    
    <!-- Notification -->
    <div id="notification" class="notification"></div>
    
    <script>
        // Initialize SocketIO
        var socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to server');
            showNotification('Connected to server', 'success');
        });
        
        socket.on('data_updated', function(data) {
            console.log('Data updated:', data);
            showNotification(data.message || 'Data updated successfully', 'success');
            
            // Refresh page after a short delay to show updated charts
            setTimeout(function() {
                location.reload();
            }, 1500);
        });
        
        // Utility function to show notifications
        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = `notification ${type}`;
            notification.style.display = 'block';
            
            setTimeout(function() {
                notification.style.display = 'none';
            }, 3000);
        }
        
        // Form submission handlers
        document.getElementById('add-record-form')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            fetch('/add_record', {
                method: 'POST',
                body: new FormData(this)
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showNotification(data.message, 'success');
                    this.reset();
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('An error occurred', 'error');
            });
        });
        
        document.getElementById('update-record-form')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            fetch('/update_record', {
                method: 'POST',
                body: new FormData(this)
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showNotification(data.message, 'success');
                    this.reset();
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('An error occurred', 'error');
            });
        });
        
        document.getElementById('delete-record-form')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
                fetch('/delete_record', {
                    method: 'POST',
                    body: new FormData(this)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        showNotification(data.message, 'success');
                        this.reset();
                    } else {
                        showNotification(data.message, 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showNotification('An error occurred', 'error');
                });
            }
        });
        
        document.getElementById('add-column-form')?.addEventListener('submit', function(e) {
            e.preventDefault();
            
            fetch('/add_column', {
                method: 'POST',
                body: new FormData(this)
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showNotification(data.message, 'success');
                    this.reset();
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('An error occurred', 'error');
            });
        });
        
        // Smooth scrolling for navigation
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
        
        // Auto-refresh data every 30 seconds
        setInterval(function() {
            fetch('/dashboard')
            .then(response => {
                if (response.ok) {
                    console.log('Data refreshed');
                }
            })
            .catch(error => console.log('Auto-refresh error:', error));
        }, 30000);
    </script>
</body>
</html>
'''

if __name__ == "__main__":
    # Initialize data and database
    initialize_data()
    sync_to_sql()
    
    print("🚨 Crime Analytics Dashboard Starting...")
    print("📊 Access the dashboard at: http://localhost:5000")
    print("👤 Demo accounts:")
    print("   • admin/password (Full Access)")
    print("   • analyst/password (Read/Write)")
    print("   • viewer/password (Read Only)")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)