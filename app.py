from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pandas as pd
import os
from functools import wraps
import io
import json
import csv
import logging
import random
import time
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
import plotly.express as px
import plotly.io as pio
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Set up basic logging
logging.basicConfig(level=logging.INFO)

# --- CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'crime-data-visualization-secure-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crime_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
db = SQLAlchemy(app)

# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CrimeRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    YEAR = db.Column(db.Integer, nullable=False)
    STATE = db.Column(db.String(120), nullable=False)
    RAPE = db.Column(db.Float, nullable=False, default=0)
    KIDNAP_ABDUCTION = db.Column(db.Float, nullable=False, default=0)
    DOMESTIC_VIOLENCE = db.Column(db.Float, nullable=False, default=0)
    DOWRY_DEATHS = db.Column(db.Float, nullable=False, default=0)
    ASSAULT_WOMEN = db.Column(db.Float, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.Integer, nullable=True)
    table_name = db.Column(db.String(50), nullable=True)
    old_data = db.Column(db.Text, nullable=True)
    new_data = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    description = db.Column(db.Text, nullable=True)

# --- HELPER FUNCTIONS ---
def get_user_id():
    return session.get('user_id')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(user_id)
        if not user:
            session.clear()
            flash('Your account no longer exists. Please register again.', 'danger')
            return redirect(url_for('login'))
            
        if user.role != 'admin':
            flash('Administrator access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def log_action(action, record_id=None, table_name=None, old_data=None, new_data=None, description=None):
    try:
        user_id = get_user_id() or 'System'
        log = AuditLog(
            user_id=user_id,
            action=action,
            record_id=record_id,
            table_name=table_name,
            old_data=json.dumps(old_data) if old_data else None,
            new_data=json.dumps(new_data) if new_data else None,
            ip_address=request.remote_addr,
            description=description
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error logging action: {e}")

def create_sample_data():
    """Create sample crime data for demonstration"""
    sample_data = [
        {'YEAR': 2020, 'STATE': 'California', 'RAPE': 1500, 'KIDNAP_ABDUCTION': 800, 'DOMESTIC_VIOLENCE': 3000, 'DOWRY_DEATHS': 50, 'ASSAULT_WOMEN': 2000},
        {'YEAR': 2020, 'STATE': 'Texas', 'RAPE': 1200, 'KIDNAP_ABDUCTION': 600, 'DOMESTIC_VIOLENCE': 2500, 'DOWRY_DEATHS': 40, 'ASSAULT_WOMEN': 1800},
        {'YEAR': 2020, 'STATE': 'Florida', 'RAPE': 900, 'KIDNAP_ABDUCTION': 400, 'DOMESTIC_VIOLENCE': 2000, 'DOWRY_DEATHS': 30, 'ASSAULT_WOMEN': 1500},
        {'YEAR': 2021, 'STATE': 'California', 'RAPE': 1600, 'KIDNAP_ABDUCTION': 850, 'DOMESTIC_VIOLENCE': 3200, 'DOWRY_DEATHS': 55, 'ASSAULT_WOMEN': 2100},
        {'YEAR': 2021, 'STATE': 'Texas', 'RAPE': 1300, 'KIDNAP_ABDUCTION': 650, 'DOMESTIC_VIOLENCE': 2600, 'DOWRY_DEATHS': 45, 'ASSAULT_WOMEN': 1900},
        {'YEAR': 2021, 'STATE': 'Florida', 'RAPE': 950, 'KIDNAP_ABDUCTION': 450, 'DOMESTIC_VIOLENCE': 2100, 'DOWRY_DEATHS': 35, 'ASSAULT_WOMEN': 1600},
    ]
    
    if CrimeRecord.query.count() == 0:
        for data in sample_data:
            record = CrimeRecord(**data)
            db.session.add(record)
        db.session.commit()
        print("Sample data created successfully!")

def generate_statistics():
    """Generate comprehensive statistics"""
    stats = {
        'total_records': CrimeRecord.query.count(),
        'total_states': db.session.query(CrimeRecord.STATE).distinct().count(),
        'years_covered': db.session.query(CrimeRecord.YEAR).distinct().count(),
        'total_users': User.query.count(),
        'recent_activity': AuditLog.query.count()
    }
    return stats

def create_visualization(chart_type='bar', auto_refresh=False):
    """Create various types of visualizations"""
    records = CrimeRecord.query.all()
    
    if not records:
        return "<p>No data available for visualization. Please upload data first.</p>"
    
    # Prepare data for visualization
    data = []
    for record in records:
        data.extend([
            {'STATE': record.STATE, 'YEAR': record.YEAR, 'crime_type': 'Rape', 'value': record.RAPE},
            {'STATE': record.STATE, 'YEAR': record.YEAR, 'crime_type': 'Kidnap', 'value': record.KIDNAP_ABDUCTION},
            {'STATE': record.STATE, 'YEAR': record.YEAR, 'crime_type': 'Domestic Violence', 'value': record.DOMESTIC_VIOLENCE},
            {'STATE': record.STATE, 'YEAR': record.YEAR, 'crime_type': 'Dowry Deaths', 'value': record.DOWRY_DEATHS},
            {'STATE': record.STATE, 'YEAR': record.YEAR, 'crime_type': 'Assault Women', 'value': record.ASSAULT_WOMEN}
        ])
    
    df = pd.DataFrame(data)
    
    try:
        if chart_type == 'bar':
            fig = px.bar(df, x='STATE', y='value', color='crime_type', 
                        title='Crime Data - Bar Chart', barmode='group',
                        color_discrete_sequence=px.colors.qualitative.Set3)
        elif chart_type == 'pie':
            pie_data = df.groupby('crime_type')['value'].sum().reset_index()
            fig = px.pie(pie_data, values='value', names='crime_type', 
                        title='Crime Data Distribution - Pie Chart',
                        color_discrete_sequence=px.colors.qualitative.Pastel)
        elif chart_type == 'line':
            line_data = df.groupby(['YEAR', 'crime_type'])['value'].sum().reset_index()
            fig = px.line(line_data, x='YEAR', y='value', color='crime_type',
                         title='Crime Trends Over Years - Line Chart',
                         color_discrete_sequence=px.colors.qualitative.Bold)
        elif chart_type == 'heatmap':
            pivot_data = df.pivot_table(values='value', index='STATE', columns='crime_type', aggfunc='sum')
            fig = px.imshow(pivot_data, title='Crime Heatmap - State vs Crime Type',
                           color_continuous_scale='Viridis')
        elif chart_type == 'scatter':
            scatter_data = df.groupby('STATE').agg({'value': 'sum'}).reset_index()
            fig = px.scatter(scatter_data, x='value', y='value', color='STATE',
                           size='value', title='Crime Distribution - Scatter Plot',
                           color_discrete_sequence=px.colors.qualitative.Dark24)
        elif chart_type == 'area':
            area_data = df.groupby(['YEAR', 'crime_type'])['value'].sum().reset_index()
            fig = px.area(area_data, x='YEAR', y='value', color='crime_type',
                         title='Cumulative Crime Data - Area Chart',
                         color_discrete_sequence=px.colors.qualitative.Light24)
        elif chart_type == 'box':
            fig = px.box(df, x='crime_type', y='value', color='crime_type',
                        title='Crime Data Distribution - Box Plot',
                        color_discrete_sequence=px.colors.qualitative.Set1)
        elif chart_type == 'violin':
            fig = px.violin(df, x='crime_type', y='value', color='crime_type',
                           title='Crime Data Density - Violin Plot',
                           color_discrete_sequence=px.colors.qualitative.Pastel)
        elif chart_type == 'histogram':
            fig = px.histogram(df, x='value', color='crime_type', marginal='rug',
                             title='Crime Value Distribution - Histogram',
                             color_discrete_sequence=px.colors.qualitative.Vivid)
        elif chart_type == '3d_scatter':
            scatter_3d_data = df.groupby(['STATE', 'YEAR']).agg({'value': 'sum'}).reset_index()
            fig = px.scatter_3d(scatter_3d_data, x='STATE', y='YEAR', z='value',
                              color='value', title='3D Crime Distribution',
                              color_continuous_scale='Plasma')
        elif chart_type == 'sunburst':
            sunburst_data = df.groupby(['STATE', 'crime_type'])['value'].sum().reset_index()
            fig = px.sunburst(sunburst_data, path=['STATE', 'crime_type'], values='value',
                            title='Crime Data Hierarchy - Sunburst Chart',
                            color_continuous_scale='RdBu')
        elif chart_type == 'treemap':
            treemap_data = df.groupby(['STATE', 'crime_type'])['value'].sum().reset_index()
            fig = px.treemap(treemap_data, path=['STATE', 'crime_type'], values='value',
                           title='Crime Data Distribution - Treemap',
                           color_continuous_scale='Blues')
        
        fig.update_layout(
            template='plotly_white',
            font=dict(size=12),
            height=600,
            margin=dict(l=50, r=50, t=80, b=50),
            hovermode='closest'
        )
        
        if auto_refresh:
            fig.update_layout(
                title=f"{fig.layout.title.text} - Auto Refresh",
                xaxis=dict(rangeslider=dict(visible=True))
            )
        
        return pio.to_html(fig, full_html=False)
    except Exception as e:
        logging.error(f"Error creating visualization: {e}")
        return f"<p>Error creating visualization: {str(e)}</p>"

def get_random_color():
    """Generate random RGB color"""
    return f"rgb({random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)})"

# --- ROUTES ---
@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'warning')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'warning')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        # First user becomes admin
        if User.query.count() == 0:
            user.role = 'admin'
        
        db.session.add(user)
        db.session.commit()
        
        log_action('USER_REGISTER', user.id, 'users', description=f"New user registered: {username}")
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password!', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['email'] = user.email
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_action('USER_LOGIN', user.id, 'users', description=f"User logged in: {username}")
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials or account disabled!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action('USER_LOGOUT', user_id, 'users', description=f"User logged out: {session.get('username')}")
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get current user for last login info
    current_user = User.query.get(session['user_id'])
    
    # Check if user exists
    if not current_user:
        # User doesn't exist in database, clear session and redirect to login
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    stats = generate_statistics()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all()
    
    # Safely get last login info
    last_login = current_user.last_login.strftime('%Y-%m-%d %H:%M') if current_user.last_login else 'Never'
    
    # Generate random background color
    bg_color = get_random_color()
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_logs=recent_logs,
                         username=session.get('username'),
                         role=session.get('role'),
                         last_login=last_login,
                         current_time=datetime.now().strftime('%Y-%m-%d %H:%M'),
                         bg_color=bg_color)

@app.route('/data', methods=['GET', 'POST'])
@login_required
def data_management():
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'upload_csv':
            if 'csv_file' in request.files:
                file = request.files['csv_file']
                if file and file.filename.endswith('.csv'):
                    try:
                        df = pd.read_csv(file)
                        
                        # Validate required columns
                        required_columns = ['YEAR', 'STATE', 'RAPE', 'KIDNAP_ABDUCTION', 'DOMESTIC_VIOLENCE', 'DOWRY_DEATHS', 'ASSAULT_WOMEN']
                        if not all(col in df.columns for col in required_columns):
                            flash(f'CSV must contain columns: {", ".join(required_columns)}', 'danger')
                            return redirect(url_for('data_management'))
                        
                        # Clear existing data
                        CrimeRecord.query.delete()
                        
                        for _, row in df.iterrows():
                            record = CrimeRecord(
                                YEAR=int(row.get('YEAR', 0)),
                                STATE=str(row.get('STATE', 'Unknown')),
                                RAPE=float(row.get('RAPE', 0)),
                                KIDNAP_ABDUCTION=float(row.get('KIDNAP_ABDUCTION', 0)),
                                DOMESTIC_VIOLENCE=float(row.get('DOMESTIC_VIOLENCE', 0)),
                                DOWRY_DEATHS=float(row.get('DOWRY_DEATHS', 0)),
                                ASSAULT_WOMEN=float(row.get('ASSAULT_WOMEN', 0)),
                            )
                            db.session.add(record)
                        
                        db.session.commit()
                        log_action('DATA_UPLOAD', new_data={'rows': len(df)}, description=f"Uploaded {len(df)} records from CSV")
                        flash(f'Successfully uploaded {len(df)} records!', 'success')
                        
                    except Exception as e:
                        db.session.rollback()
                        flash(f'Error processing CSV: {str(e)}', 'danger')
                else:
                    flash('Please upload a valid CSV file.', 'warning')
        
        elif action == 'add_record':
            try:
                record = CrimeRecord(
                    YEAR=int(request.form.get('year', 0)),
                    STATE=request.form.get('state', ''),
                    RAPE=float(request.form.get('rape', 0)),
                    KIDNAP_ABDUCTION=float(request.form.get('kidnap', 0)),
                    DOMESTIC_VIOLENCE=float(request.form.get('domestic_violence', 0)),
                    DOWRY_DEATHS=float(request.form.get('dowry_deaths', 0)),
                    ASSAULT_WOMEN=float(request.form.get('assault_women', 0)),
                )
                db.session.add(record)
                db.session.commit()
                
                log_action('ADD_RECORD', record.id, 'crime_records', 
                          new_data=record.to_dict(),
                          description=f"Added new record for {record.STATE} - {record.YEAR}")
                flash('Record added successfully!', 'success')
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error adding record: {str(e)}', 'danger')
        
        elif action == 'update_record':
            try:
                record_id = int(request.form.get('record_id'))
                record = CrimeRecord.query.get(record_id)
                if record:
                    old_data = record.to_dict()
                    record.YEAR = int(request.form.get('year', record.YEAR))
                    record.STATE = request.form.get('state', record.STATE)
                    record.RAPE = float(request.form.get('rape', record.RAPE))
                    record.KIDNAP_ABDUCTION = float(request.form.get('kidnap', record.KIDNAP_ABDUCTION))
                    record.DOMESTIC_VIOLENCE = float(request.form.get('domestic_violence', record.DOMESTIC_VIOLENCE))
                    record.DOWRY_DEATHS = float(request.form.get('dowry_deaths', record.DOWRY_DEATHS))
                    record.ASSAULT_WOMEN = float(request.form.get('assault_women', record.ASSAULT_WOMEN))
                    
                    db.session.commit()
                    
                    log_action('UPDATE_RECORD', record.id, 'crime_records', 
                              old_data=old_data, new_data=record.to_dict(),
                              description=f"Updated record for {record.STATE} - {record.YEAR}")
                    flash('Record updated successfully!', 'success')
                else:
                    flash('Record not found!', 'danger')
                    
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating record: {str(e)}', 'danger')
    
    records = CrimeRecord.query.all()
    return render_template('data_management.html', records=records)

@app.route('/data/edit/<int:record_id>')
@login_required
def get_record(record_id):
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    record = CrimeRecord.query.get_or_404(record_id)
    return jsonify(record.to_dict())

@app.route('/visualizations')
@login_required
def visualizations():
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    chart_type = request.args.get('type', 'bar')
    auto_refresh = request.args.get('auto_refresh', 'false') == 'true'
    chart_html = create_visualization(chart_type, auto_refresh)
    
    return render_template('visualizations.html', 
                         chart_html=chart_html, 
                         current_chart=chart_type,
                         auto_refresh=auto_refresh)

@app.route('/data/delete/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        return jsonify({'success': False, 'error': 'User not found'})
    
    record = CrimeRecord.query.get_or_404(record_id)
    old_data = record.to_dict()
    
    db.session.delete(record)
    db.session.commit()
    
    log_action('DELETE_RECORD', record_id, 'crime_records', old_data=old_data,
              description=f"Deleted record for {record.STATE} - {record.YEAR}")
    flash('Record deleted successfully!', 'success')
    return jsonify({'success': True})

@app.route('/stream-visuals')
@login_required
def stream_visuals():
    """Endpoint for streaming live visuals"""
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        return jsonify({'error': 'User not found'})
    
    chart_types = ['bar', 'pie', 'line', 'heatmap', 'scatter', 'area', 'box', 'violin', 'histogram', '3d_scatter', 'sunburst', 'treemap']
    current_type = request.args.get('type', random.choice(chart_types))
    chart_html = create_visualization(current_type, auto_refresh=True)
    
    return jsonify({
        'chart_html': chart_html,
        'current_type': current_type
    })

@app.route('/download-data')
@login_required
def download_data():
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    records = CrimeRecord.query.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['ID', 'YEAR', 'STATE', 'RAPE', 'KIDNAP_ABDUCTION', 'DOMESTIC_VIOLENCE', 
                    'DOWRY_DEATHS', 'ASSAULT_WOMEN'])
    
    for record in records:
        writer.writerow([record.id, record.YEAR, record.STATE, record.RAPE, record.KIDNAP_ABDUCTION,
                        record.DOMESTIC_VIOLENCE, record.DOWRY_DEATHS, record.ASSAULT_WOMEN])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'crime_data_export_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/download-pdf')
@login_required
def download_pdf():
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#2c3e50')
    )
    
    elements.append(Paragraph("Crime Data Analytics Report", title_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Heading2']))
    elements.append(Paragraph(f"Generated by: {session.get('username', 'Unknown')}", styles['Heading3']))
    elements.append(Spacer(1, 20))
    
    # Statistics
    stats = generate_statistics()
    stats_data = [
        ['Metric', 'Value'],
        ['Total Records', stats['total_records']],
        ['States Covered', stats['total_states']],
        ['Years of Data', stats['years_covered']],
        ['Total Users', stats['total_users']]
    ]
    
    stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(Paragraph("Summary Statistics", styles['Heading2']))
    elements.append(Spacer(1, 10))
    elements.append(stats_table)
    elements.append(PageBreak())
    
    # Recent Data
    elements.append(Paragraph("Crime Data Sample", styles['Heading2']))
    elements.append(Spacer(1, 10))
    
    records = CrimeRecord.query.limit(15).all()
    if records:
        data = [['ID', 'Year', 'State', 'Rape', 'Kidnap', 'Domestic Violence', 'Dowry Deaths']]
        for record in records:
            data.append([
                str(record.id),
                str(record.YEAR),
                record.STATE,
                f"{record.RAPE:.0f}",
                f"{record.KIDNAP_ABDUCTION:.0f}",
                f"{record.DOMESTIC_VIOLENCE:.0f}",
                f"{record.DOWRY_DEATHS:.0f}"
            ])
        
        data_table = Table(data, repeatRows=1)
        data_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(data_table)
    
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'crime_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    )

@app.route('/audit')
@login_required
def audit_logs():
    # Check if user exists
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    
    return render_template('audit_logs.html', logs=logs)

@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    stats = generate_statistics()
    return render_template('admin_panel.html', users=users, stats=stats)

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    # Check if user exists
    if not user:
        # User doesn't exist in database, clear session and redirect to login
        session.clear()
        flash('Your account no longer exists. Please register again.', 'danger')
        return redirect(url_for('login'))
    
    user_logs = AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('profile.html', user=user, user_logs=user_logs)

# Initialize database and create sample data
def init_db():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create admin user
        admin = User(username='admin', email='admin@crimevis.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: admin/admin123")
        
        create_sample_data()

# Create templates directory and files
def create_templates():
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # Base template with enhanced features
    base_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Crime Data System{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --accent-color: #f093fb;
            --success-color: #4CAF50;
            --warning-color: #FF9800;
            --danger-color: #f44336;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            background-attachment: fixed;
            font-family: 'Poppins', sans-serif;
            min-height: 100vh;
            transition: background 1s ease-in-out;
            animation: backgroundShift 20s infinite alternate;
        }
        
        @keyframes backgroundShift {
            0% { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            25% { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
            50% { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
            75% { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }
            100% { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
        }
        
        .glass-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .glass-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            transition: 0.5s;
        }
        
        .glass-card:hover::before {
            left: 100%;
        }
        
        .glass-card:hover {
            transform: translateY(-10px) scale(1.02);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
        }
        
        .navbar {
            background: rgba(44, 62, 80, 0.95) !important;
            backdrop-filter: blur(15px);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        }
        
        .stat-card {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            border: none;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            transform: rotate(45deg);
            transition: all 0.5s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-8px) rotate(1deg);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .stat-card:hover::before {
            transform: rotate(90deg);
        }
        
        .quick-action-btn {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            border: none;
            border-radius: 20px;
            padding: 25px 15px;
            margin: 10px;
            transition: all 0.4s ease;
            text-decoration: none;
            display: block;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            position: relative;
            overflow: hidden;
        }
        
        .quick-action-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: 0.5s;
        }
        
        .quick-action-btn:hover::before {
            left: 100%;
        }
        
        .quick-action-btn:hover {
            transform: translateY(-8px) scale(1.05);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .chart-btn {
            transition: all 0.3s ease;
            border-radius: 15px;
            margin: 5px;
            font-weight: 500;
            position: relative;
            overflow: hidden;
        }
        
        .chart-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            transition: 0.5s;
        }
        
        .chart-btn:hover::before {
            left: 100%;
        }
        
        .chart-btn.active {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%) !important;
            color: white !important;
            transform: scale(1.05);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
        }
        
        .btn-realistic {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            border: none;
            border-radius: 15px;
            padding: 12px 25px;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
            position: relative;
            overflow: hidden;
        }
        
        .btn-realistic::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: 0.5s;
        }
        
        .btn-realistic:hover::before {
            left: 100%;
        }
        
        .btn-realistic:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.25);
        }
        
        .nav-arrow {
            position: fixed;
            right: 30px;
            bottom: 30px;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            z-index: 1000;
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
            40% { transform: translateY(-10px); }
            60% { transform: translateY(-5px); }
        }
        
        .nav-arrow:hover {
            transform: scale(1.1);
            animation: none;
        }
        
        .social-icons {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 30px;
        }
        
        .social-icon {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            transition: all 0.3s ease;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
        }
        
        .social-icon:hover {
            transform: translateY(-5px) scale(1.1);
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.25);
        }
        
        .footer {
            background: rgba(44, 62, 80, 0.95);
            color: white;
            padding: 40px 0;
            margin-top: 50px;
            backdrop-filter: blur(15px);
        }
        
        .vibrate {
            animation: vibrate 0.3s linear infinite both;
        }
        
        @keyframes vibrate {
            0% { transform: translate(0); }
            20% { transform: translate(-2px, 2px); }
            40% { transform: translate(-2px, -2px); }
            60% { transform: translate(2px, 2px); }
            80% { transform: translate(2px, -2px); }
            100% { transform: translate(0); }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .glass-card {
                margin: 10px;
                padding: 20px;
            }
            
            .quick-action-btn {
                padding: 20px 10px;
                margin: 5px;
            }
            
            .stat-card {
                padding: 20px;
            }
            
            .nav-arrow {
                width: 50px;
                height: 50px;
                right: 20px;
                bottom: 20px;
            }
        }
        
        @media (max-width: 576px) {
            .container-fluid {
                padding: 10px;
            }
            
            .glass-card {
                border-radius: 15px;
            }
            
            .btn-realistic {
                padding: 10px 20px;
                font-size: 14px;
            }
        }
        
        /* Sound effects */
        .sound-effect {
            display: none;
        }
    </style>
</head>
<body>
    <!-- Sound Elements -->
    <audio id="clickSound" class="sound-effect">
        <source src="https://assets.mixkit.co/active_storage/sfx/269/269-preview.mp3" type="audio/mpeg">
    </audio>
    <audio id="hoverSound" class="sound-effect">
        <source src="https://assets.mixkit.co/active_storage/sfx/250/250-preview.mp3" type="audio/mpeg">
    </audio>
    <audio id="successSound" class="sound-effect">
        <source src="https://assets.mixkit.co/active_storage/sfx/257/257-preview.mp3" type="audio/mpeg">
    </audio>
    
    <nav class="navbar navbar-expand-lg navbar-dark sticky-top">
        <div class="container">
            <a class="navbar-brand fw-bold" href="{{ url_for('dashboard') }}">
                <i class="fas fa-shield-alt me-2"></i>Crime Analytics Pro
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <div class="navbar-nav ms-auto">
                    {% if session.user_id %}
                    <a class="nav-link" href="{{ url_for('dashboard') }}">
                        <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                    </a>
                    <a class="nav-link" href="{{ url_for('data_management') }}">
                        <i class="fas fa-database me-1"></i>Data Management
                    </a>
                    <a class="nav-link" href="{{ url_for('visualizations') }}">
                        <i class="fas fa-chart-bar me-1"></i>Visualizations
                    </a>
                    <a class="nav-link" href="{{ url_for('audit_logs') }}">
                        <i class="fas fa-history me-1"></i>History
                    </a>
                    {% if session.role == 'admin' %}
                    <a class="nav-link" href="{{ url_for('admin_panel') }}">
                        <i class="fas fa-cogs me-1"></i>Admin
                    </a>
                    {% endif %}
                    <a class="nav-link" href="{{ url_for('profile') }}">
                        <i class="fas fa-user me-1"></i>{{ session.username }}
                    </a>
                    <a class="nav-link" href="{{ url_for('logout') }}">
                        <i class="fas fa-sign-out-alt me-1"></i>Logout
                    </a>
                    {% else %}
                    <a class="nav-link" href="{{ url_for('login') }}">Login</a>
                    <a class="nav-link" href="{{ url_for('register') }}">Register</a>
                    {% endif %}
                </div>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show glass-card">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>

    <!-- Navigation Arrow -->
    <a href="{{ url_for('visualizations') }}" class="nav-arrow" onclick="playClickSound()">
        <i class="fas fa-arrow-right fa-2x"></i>
    </a>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="col-md-6 text-center text-md-start">
                    <h5><i class="fas fa-shield-alt me-2"></i>Crime Analytics Pro</h5>
                    <p>Advanced crime data visualization and analysis platform</p>
                </div>
                <div class="col-md-6 text-center text-md-end">
                    <div class="social-icons">
                        <a href="https://www.facebook.com/" class="social-icon" onclick="playClickSound()">
                            <i class="fab fa-facebook-f"></i>
                        </a>
                        <a href="https://x.com/?lang=en" class="social-icon" onclick="playClickSound()">
                            <i class="fab fa-twitter"></i>
                        </a>
                        <a href="https://www.linkedin.com/" class="social-icon" onclick="playClickSound()">
                            <i class="fab fa-linkedin-in"></i>
                        </a>
                        <a href="https://github.com/" class="social-icon" onclick="playClickSound()">
                            <i class="fab fa-github"></i>
                        </a>
                        <a href="https://www.youtube.com/" class="social-icon" onclick="playClickSound()">
                            <i class="fab fa-youtube"></i>
                        </a>
                    </div>
                </div>
            </div>
            <div class="row mt-4">
                <div class="col-12 text-center">
                    <p>&copy; 2024 Crime Analytics Pro. All rights reserved.</p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    
    <script>
        // Sound effects
        function playClickSound() {
            const audio = document.getElementById('clickSound');
            audio.currentTime = 0;
            audio.play().catch(e => console.log('Audio play failed:', e));
        }
        
        function playHoverSound() {
            const audio = document.getElementById('hoverSound');
            audio.currentTime = 0;
            audio.play().catch(e => console.log('Audio play failed:', e));
        }
        
        function playSuccessSound() {
            const audio = document.getElementById('successSound');
            audio.currentTime = 0;
            audio.play().catch(e => console.log('Audio play failed:', e));
        }
        
        // Add hover sound to interactive elements
        document.addEventListener('DOMContentLoaded', function() {
            const interactiveElements = document.querySelectorAll('.btn, .nav-link, .quick-action-btn, .social-icon, .chart-btn');
            interactiveElements.forEach(element => {
                element.addEventListener('mouseenter', function() {
                    playHoverSound();
                    this.classList.add('pulse');
                });
                element.addEventListener('mouseleave', function() {
                    this.classList.remove('pulse');
                });
                element.addEventListener('click', function() {
                    playClickSound();
                    this.classList.add('vibrate');
                    setTimeout(() => {
                        this.classList.remove('vibrate');
                    }, 300);
                });
            });
            
            // Auto background color change
            let colorIndex = 0;
            const colors = [
                'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
                'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
                'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
                'linear-gradient(135deg, #fa709a 0%, #fee140 100%)'
            ];
            
            setInterval(() => {
                document.body.style.background = colors[colorIndex];
                colorIndex = (colorIndex + 1) % colors.length;
            }, 10000);
        });
        
        // Success sound for flash messages
        {% if get_flashed_messages() %}
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(() => {
                playSuccessSound();
            }, 500);
        });
        {% endif %}
    </script>
    
    {% block scripts %}{% endblock %}
</body>
</html>'''

    # Enhanced Dashboard template
    dashboard_template = '''{% extends "base.html" %}
{% block title %}Dashboard - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="glass-card p-5 mb-4 text-center">
        <h1 class="display-4 fw-bold mb-3"><i class="fas fa-shield-alt me-3"></i>Crime Analytics Pro</h1>
        <p class="lead text-muted">Advanced Crime Data Visualization & Analysis Platform</p>
        <div class="mt-4">
            <span class="badge bg-primary me-2">Real-time</span>
            <span class="badge bg-success me-2">Interactive</span>
            <span class="badge bg-warning me-2">Secure</span>
            <span class="badge bg-info">Analytics</span>
        </div>
    </div>

    <div class="row mb-4">
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-database fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ stats.total_records }}</h2>
                <p class="mb-0">Total Records</p>
                <small>Crime Data Entries</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-map-marker-alt fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ stats.total_states }}</h2>
                <p class="mb-0">States Covered</p>
                <small>Geographical Coverage</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-calendar-alt fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ stats.years_covered }}</h2>
                <p class="mb-0">Years Data</p>
                <small>Historical Analysis</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-users fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ stats.total_users }}</h2>
                <p class="mb-0">Active Users</p>
                <small>Platform Engagement</small>
            </div>
        </div>
    </div>

    <div class="row mb-4">
        <div class="col-12">
            <div class="glass-card p-4">
                <h3 class="mb-4"><i class="fas fa-bolt me-2"></i>Quick Actions</h3>
                <div class="row text-center">
                    <div class="col-md-2 col-6 mb-3">
                        <a href="{{ url_for('data_management') }}" class="btn quick-action-btn">
                            <i class="fas fa-upload fa-2x mb-2"></i>
                            <h5>Upload Data</h5>
                            <small>CSV Import</small>
                        </a>
                    </div>
                    <div class="col-md-2 col-6 mb-3">
                        <a href="{{ url_for('visualizations') }}" class="btn quick-action-btn">
                            <i class="fas fa-chart-bar fa-2x mb-2"></i>
                            <h5>Create Viz</h5>
                            <small>12+ Chart Types</small>
                        </a>
                    </div>
                    <div class="col-md-2 col-6 mb-3">
                        <a href="{{ url_for('visualizations', type='bar', auto_refresh=true) }}" class="btn quick-action-btn">
                            <i class="fas fa-sync fa-2x mb-2"></i>
                            <h5>Live Stream</h5>
                            <small>Real-time Viz</small>
                        </a>
                    </div>
                    <div class="col-md-2 col-6 mb-3">
                        <a href="{{ url_for('download_pdf') }}" class="btn quick-action-btn">
                            <i class="fas fa-file-pdf fa-2x mb-2"></i>
                            <h5>Generate PDF</h5>
                            <small>Export Reports</small>
                        </a>
                    </div>
                    <div class="col-md-2 col-6 mb-3">
                        <a href="{{ url_for('audit_logs') }}" class="btn quick-action-btn">
                            <i class="fas fa-history fa-2x mb-2"></i>
                            <h5>View History</h5>
                            <small>Audit Trail</small>
                        </a>
                    </div>
                    <div class="col-md-2 col-6 mb-3">
                        <a href="{{ url_for('profile') }}" class="btn quick-action-btn">
                            <i class="fas fa-user-cog fa-2x mb-2"></i>
                            <h5>Profile</h5>
                            <small>Account Settings</small>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-8">
            <div class="glass-card p-4">
                <h4><i class="fas fa-history me-2"></i>Recent Activity</h4>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>Time</th>
                                <th>User</th>
                                <th>Action</th>
                                <th>Details</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in recent_logs %}
                            <tr>
                                <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M') }}</td>
                                <td>{{ log.user_id }}</td>
                                <td>
                                    <span class="badge bg-{% if log.action == 'UPDATE' %}warning{% elif log.action == 'DELETE' %}danger{% elif log.action == 'ADD' %}success{% else %}info{% endif %}">
                                        {{ log.action }}
                                    </span>
                                </td>
                                <td>{{ log.table_name or 'N/A' }}</td>
                                <td>{{ log.description or 'No description' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="glass-card p-4">
                <h4><i class="fas fa-info-circle me-2"></i>System Info</h4>
                <div class="mb-3">
                    <strong>Role:</strong> <span class="badge bg-primary">{{ role }}</span>
                </div>
                <div class="mb-3">
                    <strong>Last Login:</strong> {{ last_login }}
                </div>
                <div class="mb-3">
                    <strong>Current Time:</strong> {{ current_time }}
                </div>
                <div class="mb-3">
                    <strong>Status:</strong> <span class="badge bg-success">Active</span>
                </div>
                <div class="mt-4">
                    <a href="{{ url_for('visualizations') }}" class="btn btn-realistic w-100">
                        <i class="fas fa-rocket me-2"></i>Start Exploring
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''

    # Enhanced Visualizations template with 12 chart types
    visualizations_template = '''{% extends "base.html" %}
{% block title %}Visualizations - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="glass-card p-4 mb-4">
        <div class="d-flex justify-content-between align-items-center flex-wrap">
            <div>
                <h2><i class="fas fa-chart-bar me-2"></i>Advanced Visualizations</h2>
                <p class="text-muted mb-0">12+ Interactive Chart Types with Real-time Streaming</p>
            </div>
            <div class="mt-2">
                <a href="{{ url_for('stream_visuals') }}" class="btn btn-realistic me-2" id="streamBtn">
                    <i class="fas fa-sync me-2"></i>
                    <span id="streamText">{% if auto_refresh %}Stop Streaming{% else %}Start Streaming{% endif %}</span>
                </a>
                <a href="{{ url_for('download_data') }}" class="btn btn-success">
                    <i class="fas fa-download me-2"></i>Export Data
                </a>
            </div>
        </div>
    </div>

    <div class="glass-card p-4 mb-4">
        <h4>Select Chart Type</h4>
        <div class="row g-2 mb-4">
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='bar') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'bar' %}active{% endif %}">
                    <i class="fas fa-chart-bar me-2"></i>Bar Chart
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='pie') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'pie' %}active{% endif %}">
                    <i class="fas fa-chart-pie me-2"></i>Pie Chart
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='line') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'line' %}active{% endif %}">
                    <i class="fas fa-chart-line me-2"></i>Line Chart
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='heatmap') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'heatmap' %}active{% endif %}">
                    <i class="fas fa-map me-2"></i>Heatmap
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='scatter') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'scatter' %}active{% endif %}">
                    <i class="fas fa-dot-circle me-2"></i>Scatter Plot
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='area') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'area' %}active{% endif %}">
                    <i class="fas fa-chart-area me-2"></i>Area Chart
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='box') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'box' %}active{% endif %}">
                    <i class="fas fa-chart-box me-2"></i>Box Plot
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='violin') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'violin' %}active{% endif %}">
                    <i class="fas fa-guitar me-2"></i>Violin Plot
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='histogram') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'histogram' %}active{% endif %}">
                    <i class="fas fa-chart-histogram me-2"></i>Histogram
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='3d_scatter') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == '3d_scatter' %}active{% endif %}">
                    <i class="fas fa-cube me-2"></i>3D Scatter
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='sunburst') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'sunburst' %}active{% endif %}">
                    <i class="fas fa-sun me-2"></i>Sunburst
                </a>
            </div>
            <div class="col-md-3 col-6">
                <a href="{{ url_for('visualizations', type='treemap') }}" class="btn btn-outline-primary w-100 chart-btn {% if current_chart == 'treemap' %}active{% endif %}">
                    <i class="fas fa-tree me-2"></i>Treemap
                </a>
            </div>
        </div>

        <div class="chart-container" id="chartContainer">
            {{ chart_html|safe }}
        </div>
        
        {% if auto_refresh %}
        <div class="mt-3 text-center">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="text-muted mt-2">Live streaming visuals - updating every 5 seconds</p>
        </div>
        {% endif %}
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
let streamInterval;
const streamBtn = document.getElementById('streamBtn');
const streamText = document.getElementById('streamText');
const chartContainer = document.getElementById('chartContainer');

{% if auto_refresh %}
// Start auto-refresh if streaming is enabled
startStreaming();
{% endif %}

streamBtn.addEventListener('click', function(e) {
    e.preventDefault();
    const isStreaming = streamText.textContent === 'Stop Streaming';
    
    if (isStreaming) {
        stopStreaming();
    } else {
        startStreaming();
    }
});

function startStreaming() {
    streamText.textContent = 'Stop Streaming';
    streamBtn.classList.add('btn-danger');
    streamBtn.classList.remove('btn-realistic');
    
    streamInterval = setInterval(updateChart, 5000);
    updateChart(); // Initial update
}

function stopStreaming() {
    streamText.textContent = 'Start Streaming';
    streamBtn.classList.remove('btn-danger');
    streamBtn.classList.add('btn-realistic');
    
    if (streamInterval) {
        clearInterval(streamInterval);
    }
}

function updateChart() {
    fetch('/stream-visuals?type={{ current_chart }}')
        .then(response => response.json())
        .then(data => {
            chartContainer.innerHTML = data.chart_html;
            // Re-initialize Plotly if needed
            if (typeof Plotly !== 'undefined') {
                Plotly.purge(chartContainer);
                Plotly.react(chartContainer, JSON.parse(data.chart_html));
            }
        })
        .catch(error => console.error('Error updating chart:', error));
}

// Add animation to chart container
chartContainer.style.transition = 'all 0.5s ease';
setInterval(() => {
    chartContainer.style.transform = chartContainer.style.transform === 'scale(1.02)' ? 'scale(1)' : 'scale(1.02)';
}, 2000);
</script>
{% endblock %}'''

    # Enhanced Data Management template with CRUD operations
    data_management_template = '''{% extends "base.html" %}
{% block title %}Data Management - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="glass-card p-4 mb-4">
        <div class="d-flex justify-content-between align-items-center flex-wrap">
            <div>
                <h2><i class="fas fa-database me-2"></i>Advanced Data Management</h2>
                <p class="text-muted mb-0">Complete CRUD Operations with Real-time Editing</p>
            </div>
            <div class="mt-2">
                <button class="btn btn-realistic me-2" data-bs-toggle="modal" data-bs-target="#uploadModal">
                    <i class="fas fa-upload me-2"></i>Upload CSV
                </button>
                <button class="btn btn-success me-2" data-bs-toggle="modal" data-bs-target="#addRecordModal">
                    <i class="fas fa-plus me-2"></i>Add Record
                </button>
                <a href="{{ url_for('download_data') }}" class="btn btn-info">
                    <i class="fas fa-download me-2"></i>Export CSV
                </a>
            </div>
        </div>
    </div>

    <div class="glass-card p-4">
        {% if records %}
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Year</th>
                        <th>State</th>
                        <th>Rape</th>
                        <th>Kidnap</th>
                        <th>Domestic Violence</th>
                        <th>Dowry Deaths</th>
                        <th>Assault Women</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for record in records %}
                    <tr id="record-{{ record.id }}">
                        <td>{{ record.id }}</td>
                        <td>{{ record.YEAR }}</td>
                        <td>{{ record.STATE }}</td>
                        <td>{{ record.RAPE }}</td>
                        <td>{{ record.KIDNAP_ABDUCTION }}</td>
                        <td>{{ record.DOMESTIC_VIOLENCE }}</td>
                        <td>{{ record.DOWRY_DEATHS }}</td>
                        <td>{{ record.ASSAULT_WOMEN }}</td>
                        <td>
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-warning" onclick="editRecord({{ record.id }})" data-bs-toggle="tooltip" title="Edit Record">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-danger" onclick="deleteRecord({{ record.id }})" data-bs-toggle="tooltip" title="Delete Record">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="text-center py-5">
            <i class="fas fa-database fa-4x text-muted mb-3"></i>
            <h4>No Data Available</h4>
            <p class="text-muted">Upload a CSV file or add records to get started.</p>
            <div class="mt-3">
                <button class="btn btn-realistic me-2" data-bs-toggle="modal" data-bs-target="#uploadModal">
                    <i class="fas fa-upload me-2"></i>Upload CSV
                </button>
                <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#addRecordModal">
                    <i class="fas fa-plus me-2"></i>Add Record
                </button>
            </div>
        </div>
        {% endif %}
    </div>
</div>

<!-- Upload Modal -->
<div class="modal fade" id="uploadModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content glass-card">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-upload me-2"></i>Upload CSV File</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload_csv">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Select CSV File</label>
                        <input type="file" class="form-control" name="csv_file" accept=".csv" required>
                        <div class="form-text">
                            CSV must contain columns: YEAR, STATE, RAPE, KIDNAP_ABDUCTION, DOMESTIC_VIOLENCE, DOWRY_DEATHS, ASSAULT_WOMEN
                        </div>
                    </div>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        <strong>Note:</strong> Uploading a new CSV will replace all existing data.
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-realistic">Upload & Process</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Add Record Modal -->
<div class="modal fade" id="addRecordModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content glass-card">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-plus me-2"></i>Add New Record</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="add_record">
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Year</label>
                            <input type="number" class="form-control" name="year" min="2000" max="2030" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">State</label>
                            <input type="text" class="form-control" name="state" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Rape Cases</label>
                            <input type="number" class="form-control" name="rape" min="0" step="1" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Kidnap Cases</label>
                            <input type="number" class="form-control" name="kidnap" min="0" step="1" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Domestic Violence</label>
                            <input type="number" class="form-control" name="domestic_violence" min="0" step="1" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Dowry Deaths</label>
                            <input type="number" class="form-control" name="dowry_deaths" min="0" step="1" required>
                        </div>
                        <div class="col-12 mb-3">
                            <label class="form-label">Assault on Women</label>
                            <input type="number" class="form-control" name="assault_women" min="0" step="1" required>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-success">Add Record</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Edit Record Modal -->
<div class="modal fade" id="editRecordModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content glass-card">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Edit Record</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="update_record">
                <input type="hidden" name="record_id" id="editRecordId">
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Year</label>
                            <input type="number" class="form-control" name="year" id="editYear" min="2000" max="2030" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">State</label>
                            <input type="text" class="form-control" name="state" id="editState" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Rape Cases</label>
                            <input type="number" class="form-control" name="rape" id="editRape" min="0" step="1" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Kidnap Cases</label>
                            <input type="number" class="form-control" name="kidnap" id="editKidnap" min="0" step="1" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Domestic Violence</label>
                            <input type="number" class="form-control" name="domestic_violence" id="editDomesticViolence" min="0" step="1" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Dowry Deaths</label>
                            <input type="number" class="form-control" name="dowry_deaths" id="editDowryDeaths" min="0" step="1" required>
                        </div>
                        <div class="col-12 mb-3">
                            <label class="form-label">Assault on Women</label>
                            <input type="number" class="form-control" name="assault_women" id="editAssaultWomen" min="0" step="1" required>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-warning">Update Record</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function deleteRecord(recordId) {
    if (confirm('Are you sure you want to delete this record? This action cannot be undone.')) {
        fetch('/data/delete/' + recordId, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Add deletion animation
                const row = document.getElementById('record-' + recordId);
                row.style.transition = 'all 0.5s ease';
                row.style.opacity = '0';
                row.style.transform = 'translateX(100px)';
                
                setTimeout(() => {
                    location.reload();
                }, 500);
            }
        })
        .catch(error => console.error('Error:', error));
    }
}

async function editRecord(recordId) {
    try {
        const response = await fetch('/data/edit/' + recordId);
        const record = await response.json();
        
        // Populate edit form
        document.getElementById('editRecordId').value = record.id;
        document.getElementById('editYear').value = record.YEAR;
        document.getElementById('editState').value = record.STATE;
        document.getElementById('editRape').value = record.RAPE;
        document.getElementById('editKidnap').value = record.KIDNAP_ABDUCTION;
        document.getElementById('editDomesticViolence').value = record.DOMESTIC_VIOLENCE;
        document.getElementById('editDowryDeaths').value = record.DOWRY_DEATHS;
        document.getElementById('editAssaultWomen').value = record.ASSAULT_WOMEN;
        
        // Show edit modal
        const editModal = new bootstrap.Modal(document.getElementById('editRecordModal'));
        editModal.show();
        
    } catch (error) {
        console.error('Error fetching record:', error);
        alert('Error loading record data');
    }
}

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
</script>
{% endblock %}'''

    # Enhanced Audit Logs template
    audit_logs_template = '''{% extends "base.html" %}
{% block title %}Audit History - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="glass-card p-4 mb-4">
        <h2><i class="fas fa-history me-2"></i>Complete Audit History</h2>
        <p class="text-muted">Detailed log of all user activities and system operations</p>
    </div>

    <div class="glass-card p-4">
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>Timestamp</th>
                        <th>User ID</th>
                        <th>Action</th>
                        <th>Table</th>
                        <th>Record ID</th>
                        <th>IP Address</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs.items %}
                    <tr>
                        <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                        <td>{{ log.user_id }}</td>
                        <td>
                            <span class="badge bg-{% if log.action == 'UPDATE_RECORD' %}warning{% elif log.action == 'DELETE_RECORD' %}danger{% elif log.action == 'ADD_RECORD' %}success{% elif log.action == 'DATA_UPLOAD' %}info{% elif 'USER' in log.action %}primary{% else %}secondary{% endif %}">
                                {{ log.action }}
                            </span>
                        </td>
                        <td>{{ log.table_name or 'N/A' }}</td>
                        <td>{{ log.record_id or 'N/A' }}</td>
                        <td>{{ log.ip_address or 'N/A' }}</td>
                        <td>{{ log.description or 'No description' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <!-- Pagination -->
        <nav aria-label="Audit logs pagination" class="mt-4">
            <ul class="pagination justify-content-center">
                {% if logs.has_prev %}
                <li class="page-item">
                    <a class="page-link" href="{{ url_for('audit_logs', page=logs.prev_num) }}">Previous</a>
                </li>
                {% endif %}
                
                {% for page_num in logs.iter_pages() %}
                    {% if page_num %}
                        <li class="page-item {% if page_num == logs.page %}active{% endif %}">
                            <a class="page-link" href="{{ url_for('audit_logs', page=page_num) }}">{{ page_num }}</a>
                        </li>
                    {% else %}
                        <li class="page-item disabled"><span class="page-link">…</span></li>
                    {% endif %}
                {% endfor %}
                
                {% if logs.has_next %}
                <li class="page-item">
                    <a class="page-link" href="{{ url_for('audit_logs', page=logs.next_num) }}">Next</a>
                </li>
                {% endif %}
            </ul>
        </nav>
        
        <div class="text-center mt-3">
            <p class="text-muted">
                Showing page {{ logs.page }} of {{ logs.pages }} - Total {{ logs.total }} records
            </p>
        </div>
    </div>
</div>
{% endblock %}'''

    # Enhanced Profile template with user history
    profile_template = '''{% extends "base.html" %}
{% block title %}User Profile - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="glass-card p-4 mb-4">
        <h2><i class="fas fa-user me-2"></i>User Profile & Activity</h2>
        <p class="text-muted">Your account information and recent activities</p>
    </div>

    <div class="row">
        <div class="col-md-4">
            <div class="glass-card p-4 mb-4">
                <div class="text-center">
                    <div class="rounded-circle bg-primary d-inline-flex align-items-center justify-content-center mb-3" style="width: 100px; height: 100px;">
                        <i class="fas fa-user fa-3x text-white"></i>
                    </div>
                    <h4>{{ user.username }}</h4>
                    <p class="text-muted">{{ user.email }}</p>
                    <span class="badge bg-{% if user.role == 'admin' %}danger{% else %}primary{% endif %} mb-3">
                        {{ user.role|upper }}
                    </span>
                </div>
                
                <div class="mt-4">
                    <h5>Account Details</h5>
                    <div class="mb-2">
                        <strong>Member Since:</strong> {{ user.created_at.strftime('%B %d, %Y') }}
                    </div>
                    <div class="mb-2">
                        <strong>Last Login:</strong> {{ user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never' }}
                    </div>
                    <div class="mb-2">
                        <strong>Status:</strong> 
                        <span class="badge bg-{% if user.is_active %}success{% else %}secondary{% endif %}">
                            {% if user.is_active %}Active{% else %}Inactive{% endif %}
                        </span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-8">
            <div class="glass-card p-4">
                <h4><i class="fas fa-history me-2"></i>Recent Activities</h4>
                <p class="text-muted">Your last 10 actions in the system</p>
                
                {% if user_logs %}
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Action</th>
                                <th>Target</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in user_logs %}
                            <tr>
                                <td>{{ log.timestamp.strftime('%m/%d %H:%M') }}</td>
                                <td>
                                    <span class="badge bg-{% if log.action == 'UPDATE_RECORD' %}warning{% elif log.action == 'DELETE_RECORD' %}danger{% elif log.action == 'ADD_RECORD' %}success{% elif log.action == 'DATA_UPLOAD' %}info{% else %}primary{% endif %}">
                                        {{ log.action }}
                                    </span>
                                </td>
                                <td>{{ log.table_name or 'System' }}</td>
                                <td>{{ log.description or 'No description' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center py-4">
                    <i class="fas fa-clipboard-list fa-3x text-muted mb-3"></i>
                    <p class="text-muted">No recent activities found.</p>
                </div>
                {% endif %}
                
                <div class="mt-4">
                    <a href="{{ url_for('audit_logs') }}" class="btn btn-realistic w-100">
                        <i class="fas fa-list-alt me-2"></i>View Complete History
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''

    # Login template
    login_template = '''{% extends "base.html" %}
{% block title %}Login - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-5">
            <div class="glass-card p-5 mt-5">
                <div class="text-center mb-4">
                    <i class="fas fa-shield-alt fa-4x text-primary mb-3"></i>
                    <h2>Crime Analytics Pro</h2>
                    <p class="text-muted">Sign in to your account</p>
                </div>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" placeholder="Enter your username" required>
                    </div>
                    <div class="mb-4">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" placeholder="Enter your password" required>
                    </div>
                    <button type="submit" class="btn btn-realistic w-100 py-3">
                        <i class="fas fa-sign-in-alt me-2"></i>Sign In
                    </button>
                </form>
                <div class="text-center mt-4">
                    <p class="mb-0">Don't have an account? 
                        <a href="{{ url_for('register') }}" class="text-decoration-none fw-bold">Register here</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''

    # Register template
    register_template = '''{% extends "base.html" %}
{% block title %}Register - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-5">
            <div class="glass-card p-5 mt-5">
                <div class="text-center mb-4">
                    <i class="fas fa-user-plus fa-4x text-primary mb-3"></i>
                    <h2>Create Account</h2>
                    <p class="text-muted">Join Crime Analytics Pro platform</p>
                </div>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" placeholder="Choose a username" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="email" name="email" class="form-control" placeholder="Enter your email" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" placeholder="Create a password" required>
                    </div>
                    <div class="mb-4">
                        <label class="form-label">Confirm Password</label>
                        <input type="password" name="confirm_password" class="form-control" placeholder="Confirm your password" required>
                    </div>
                    <button type="submit" class="btn btn-realistic w-100 py-3">
                        <i class="fas fa-user-plus me-2"></i>Create Account
                    </button>
                </form>
                <div class="text-center mt-4">
                    <p class="mb-0">Already have an account? 
                        <a href="{{ url_for('login') }}" class="text-decoration-none fw-bold">Login here</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''

    # Admin Panel template
    admin_panel_template = '''{% extends "base.html" %}
{% block title %}Admin Panel - Crime Analytics Pro{% endblock %}
{% block content %}
<div class="container">
    <div class="glass-card p-4 mb-4">
        <h2><i class="fas fa-cogs me-2"></i>Administrator Panel</h2>
        <p class="text-muted">User management and system administration</p>
    </div>

    <div class="row mb-4">
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-users fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ stats.total_users }}</h2>
                <p class="mb-0">Total Users</p>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-database fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ stats.total_records }}</h2>
                <p class="mb-0">Data Records</p>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-history fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ stats.recent_activity }}</h2>
                <p class="mb-0">Audit Logs</p>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stat-card text-center">
                <i class="fas fa-shield-alt fa-3x mb-3"></i>
                <h2 class="display-6 fw-bold">{{ users|selectattr('role', 'equalto', 'admin')|list|length }}</h2>
                <p class="mb-0">Admins</p>
            </div>
        </div>
    </div>

    <div class="glass-card p-4">
        <h4 class="mb-4"><i class="fas fa-users me-2"></i>User Management</h4>
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Joined</th>
                        <th>Last Login</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.id }}</td>
                        <td>{{ user.username }}</td>
                        <td>{{ user.email }}</td>
                        <td>
                            <span class="badge bg-{% if user.role == 'admin' %}danger{% else %}primary{% endif %}">
                                {{ user.role }}
                            </span>
                        </td>
                        <td>
                            <span class="badge bg-{% if user.is_active %}success{% else %}secondary{% endif %}">
                                {% if user.is_active %}Active{% else %}Inactive{% endif %}
                            </span>
                        </td>
                        <td>{{ user.created_at.strftime('%Y-%m-%d') }}</td>
                        <td>{{ user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}'''

    # Save all templates
    templates = {
        'base.html': base_template,
        'dashboard.html': dashboard_template,
        'visualizations.html': visualizations_template,
        'data_management.html': data_management_template,
        'login.html': login_template,
        'register.html': register_template,
        'audit_logs.html': audit_logs_template,
        'admin_panel.html': admin_panel_template,
        'profile.html': profile_template
    }
    
    for filename, content in templates.items():
        filepath = os.path.join(templates_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Created template: {filename}")

if __name__ == '__main__':
    # Create templates first
    create_templates()
    
    # Initialize database
    init_db()
    
    print("🚀 Starting Crime Analytics Pro Application...")
    print("📍 Access the application at: http://localhost:5000")
    print("🔑 Admin credentials: admin / admin123")
    print("✨ Features included:")
    print("   - 12+ Interactive Chart Types")
    print("   - Real-time Streaming Visuals")
    print("   - Complete CRUD Operations")
    print("   - Advanced Audit History")
    print("   - Responsive Design with Animations")
    print("   - Sound Effects & Visual Feedback")
    
    app.run(debug=True, host='0.0.0.0', port=5000)