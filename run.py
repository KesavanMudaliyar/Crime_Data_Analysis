# ------------- Streamlit Power BI–Style Dashboard (Enhanced with all visuals) -------------
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import altair as alt
import sqlite3
from datetime import datetime
import io, zipfile, time, os
from wordcloud import WordCloud
import matplotlib.pyplot as plt
from fpdf import FPDF

# ----------------------- Backend / History DB -----------------------
DB_PATH = "dashboard_history.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    timestamp TEXT,
    details TEXT
)
''')
conn.commit()

def log_action(action, details=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO history (action, timestamp, details) VALUES (?, ?, ?)", (action, ts, details))
    conn.commit()

# ----------------------- Utilities -----------------------
def to_excel_bytes(df):
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="data")
    return buffer.getvalue()

def df_from_upload(uploaded_file):
    if uploaded_file is None:
        return None
    name = uploaded_file.name.lower()
    if name.endswith('.csv'):
        return pd.read_csv(uploaded_file)
    else:
        return pd.read_excel(uploaded_file)

@st.cache_data
def load_demo_data():
    df = px.data.gapminder()
    df['region'] = df['continent']
    df['category'] = np.where(df['gdpPercap']>10000, 'High', 'Low')
    return df

# ----------------------- UI Setup -----------------------
st.set_page_config(layout="wide", page_title="PowerBI-Style Dashboard", page_icon="📊")

# Top header
col_left, col_center, col_right = st.columns([1,6,1])
with col_center:
    st.markdown("<h1 style='text-align:center;margin-bottom:0'>📊 Crimes Dashboard Template (Python)</h1>", unsafe_allow_html=True)

# ----------------------- File Upload -----------------------
st.sidebar.header("Data Controls")
uploaded = st.sidebar.file_uploader("Upload CSV or Excel", type=["csv","xlsx","xls"])
if uploaded:
    try:
        df = df_from_upload(uploaded)
        st.sidebar.success(f"Loaded {uploaded.name}")
        log_action("File Uploaded", uploaded.name)
    except Exception as e:
        st.sidebar.error("Failed to read file: " + str(e))
        df = load_demo_data()
else:
    df = load_demo_data()

# ----------------------- Sidebar Filters -----------------------
st.sidebar.subheader("Filters")
categorical_cols = df.select_dtypes(include='object').columns.tolist()
numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
for col in categorical_cols:
    selected = st.sidebar.multiselect(f"{col} filter", options=df[col].unique(), default=df[col].unique())
    df = df[df[col].isin(selected)]

# ----------------------- KPIs -----------------------
st.subheader("🔹 KPIs")
cols = st.columns(min(3, len(numeric_cols)))
for i, col in enumerate(numeric_cols[:3]):
    with cols[i]:
        st.metric(label=f"Avg {col}", value=round(df[col].mean(),2), delta=round(df[col].max()-df[col].mean(),2))

# ----------------------- Tabs -----------------------
tab_home, tab_visuals, tab_data, tab_history, tab_reports = st.tabs(["Home","Visuals Library","Data Manager","History","Reports"])

# ---------- HOME ----------
with tab_home:
    st.subheader("Template Preview")
    st.markdown("Responsive grid preview. Add visuals from Visuals Library.")

# ---------- VISUALS LIBRARY ----------
with tab_visuals:
    st.subheader("Visuals Library — Add to Canvas")
    if 'canvas' not in st.session_state:
        st.session_state.canvas = []

    # Live Stream Button
    if st.button("Start Live Stream"):
        log_action("Start Live Stream")
        placeholder = st.empty()
        for i in range(12):
            val = int((np.sin(time.time()+i) + 1.5) * 1000)
            with placeholder.container():
                st.metric("Live Visitors", val, delta=f"{np.random.randint(-50,50)}")
            time.sleep(0.5)
        log_action("End Live Stream")
        st.success("Live stream ended")

    vis_type = st.selectbox("Visual Type", [
        "Bar Chart","Line Chart","Area Chart","Pie Chart","Donut Chart","Treemap","Sunburst",
        "Scatter","Bubble","Histogram","Boxplot","Violin","Heatmap","Choropleth","Radar","Gauge","Waterfall","Funnel","Sankey","Wordcloud"
    ])
    x_col = st.selectbox("X axis / Category", options=list(df.columns))
    y_col = st.selectbox("Y axis / Value", options=list(df.select_dtypes(include=[np.number]).columns) if numeric_cols else list(df.columns))
    color_col = st.selectbox("Color (optional)", options=[None]+list(df.columns))
    chart_title = st.text_input("Chart Title", value=vis_type)
    
    if st.button("Add Visual"):
        config = dict(type=vis_type, x=x_col, y=y_col, color=color_col, title=chart_title, id=len(st.session_state.canvas)+1)
        st.session_state.canvas.append(config)
        log_action("Add Visual", str(config))
        st.success(f"Added {vis_type} to canvas")

    # Render canvas with dynamic/live metrics simulation
    st.subheader("Canvas")
    if not st.session_state.canvas:
        st.info("No visuals yet.")
    else:
        for v in st.session_state.canvas:
            cols = st.columns([1,4,1])
            cols[0].markdown(f"**#{v['id']}**")
            with cols[1]:
                st.markdown(f"### {v['title']}")
                try:
                    # ---------------- VISUALS HANDLER ----------------
                    if v['type']=="Bar Chart":
                        st.plotly_chart(px.bar(df, x=v['x'], y=v['y'], color=v['color']), use_container_width=True)

                    elif v['type']=="Line Chart":
                        st.plotly_chart(px.line(df, x=v['x'], y=v['y'], color=v['color']), use_container_width=True)

                    elif v['type']=="Area Chart":
                        st.plotly_chart(px.area(df, x=v['x'], y=v['y'], color=v['color']), use_container_width=True)

                    elif v['type']=="Pie Chart":
                        st.plotly_chart(px.pie(df, names=v['x'], values=v['y']), use_container_width=True)

                    elif v['type']=="Donut Chart":
                        fig = px.pie(df, names=v['x'], values=v['y'])
                        fig.update_traces(hole=0.5)
                        st.plotly_chart(fig, use_container_width=True)

                    elif v['type']=="Treemap":
                        st.plotly_chart(px.treemap(df, path=[v['x']], values=v['y'], color=v['color']), use_container_width=True)

                    elif v['type']=="Sunburst":
                        st.plotly_chart(px.sunburst(df, path=[v['x']], values=v['y'], color=v['color']), use_container_width=True)

                    elif v['type']=="Scatter":
                        st.plotly_chart(px.scatter(df, x=v['x'], y=v['y'], color=v['color'], size=v['y']), use_container_width=True)

                    elif v['type']=="Bubble":
                        st.plotly_chart(px.scatter(df, x=v['x'], y=v['y'], color=v['color'], size=v['y'], size_max=60), use_container_width=True)

                    elif v['type']=="Histogram":
                        st.plotly_chart(px.histogram(df, x=v['x'], color=v['color']), use_container_width=True)

                    elif v['type']=="Boxplot":
                        st.plotly_chart(px.box(df, x=v['x'], y=v['y'], color=v['color']), use_container_width=True)

                    elif v['type']=="Violin":
                        st.plotly_chart(px.violin(df, x=v['x'], y=v['y'], color=v['color'], box=True, points="all"), use_container_width=True)

                    elif v['type']=="Heatmap":
                        fig = go.Figure(data=go.Heatmap(z=df.pivot_table(index=v['x'], columns=v['color'], values=v['y'], aggfunc='mean').values))
                        st.plotly_chart(fig, use_container_width=True)

                    elif v['type']=="Choropleth":
                        fig = px.choropleth(df, locations="country", locationmode="country names", color=v['y'], hover_name=v['x'], projection="natural earth")
                        st.plotly_chart(fig, use_container_width=True)

                    elif v['type']=="Radar":
                        categories = df[v['x']].astype(str).tolist()[:10]
                        values = df[v['y']].tolist()[:10]
                        fig = go.Figure(data=go.Scatterpolar(r=values, theta=categories, fill='toself'))
                        st.plotly_chart(fig, use_container_width=True)

                    elif v['type']=="Gauge":
                        value = df[v['y']].mean()
                        fig = go.Figure(go.Indicator(mode="gauge+number", value=value, title={'text': v['y']}))
                        st.plotly_chart(fig, use_container_width=True)

                    elif v['type']=="Waterfall":
                        fig = go.Figure(go.Waterfall(x=df[v['x']], y=df[v['y']]))
                        st.plotly_chart(fig, use_container_width=True)

                    elif v['type']=="Funnel":
                        st.plotly_chart(px.funnel(df, x=v['x'], y=v['y'], color=v['color']), use_container_width=True)

                    elif v['type']=="Sankey":
                        if len(df[v['x']].unique())>1 and len(df[v['y']].unique())>1:
                            fig = go.Figure(go.Sankey(
                                node=dict(label=list(df[v['x']].unique())+list(df[v['y']].unique())),
                                link=dict(source=list(range(len(df[v['x']]))), target=list(range(len(df[v['y']]))), value=[1]*len(df))
                            ))
                            st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.warning("Not enough categories for Sankey")

                    elif v['type']=="Wordcloud":
                        if df[v['x']].dtype==object:
                            text=' '.join(df[v['x']].dropna().astype(str))
                            wc = WordCloud(width=600,height=300).generate(text)
                            plt.figure(figsize=(8,4))
                            plt.imshow(wc, interpolation='bilinear'); plt.axis('off'); st.pyplot(plt)
                        else:
                            st.warning("Wordcloud requires text column")

                except Exception as e:
                    st.error(f"Chart render failed: {e}")

            with cols[2]:
                if st.button(f"Delete #{v['id']}", key=f"del_{v['id']}"):
                    st.session_state.canvas = [c for c in st.session_state.canvas if c['id']!=v['id']]
                    log_action("Delete Visual", str(v))
                    st.experimental_rerun()

# ---------- DATA MANAGER ----------
with tab_data:
    st.header("Data Manager")
    st.dataframe(df.head(200))

    st.subheader("Add / Modify / Delete Rows")
    # Add random row
    if st.button("Add Random Row"):
        row = df.iloc[0].copy()
        for c in numeric_cols:
            row[c] = np.nan
        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
        log_action("Add Row","random")
        st.success("Row added")

    # Delete by index
    idx_del = st.text_input("Comma-separated indices to delete")
    if st.button("Delete Rows"):
        try:
            indices = [int(x.strip()) for x in idx_del.split(',') if x.strip()!='']
            df = df.drop(indices).reset_index(drop=True)
            log_action("Delete Rows", str(indices))
            st.success("Rows deleted")
        except Exception as e:
            st.error("Delete failed: " + str(e))

    # Modify row
    st.subheader("Modify Row")
    row_idx = st.number_input("Row index to modify", min_value=0, max_value=len(df)-1, step=1)
    col_name = st.selectbox("Column", options=list(df.columns))
    new_val = st.text_input("New Value")
    if st.button("Apply Modification"):
        try:
            if df[col_name].dtype in [np.int64, np.float64]:
                df.at[row_idx, col_name] = float(new_val)
            else:
                df.at[row_idx, col_name] = new_val
            log_action("Modify Row", f"Row {row_idx}, Column {col_name}, Value {new_val}")
            st.success("Row modified")
        except Exception as e:
            st.error("Modification failed: " + str(e))

# ---------- HISTORY ----------
with tab_history:
    st.header("History / Audit Trail")
    hist_df = pd.read_sql("SELECT * FROM history ORDER BY id DESC", conn)
    st.dataframe(hist_df)
    if st.button("Export History CSV"):
        st.download_button("Download History CSV", hist_df.to_csv(index=False).encode('utf-8'), "history.csv")
        log_action("Export History CSV")

# ---------- REPORTS ----------
with tab_reports:
    st.header("Report Generation")
    if st.button("Generate Report ZIP"):
        temp_dir="_temp_report"; os.makedirs(temp_dir, exist_ok=True)
        df.to_csv(os.path.join(temp_dir,"data.csv"), index=False)
        zip_buf=io.BytesIO(); 
        with zipfile.ZipFile(zip_buf,'w') as zf:
            for root,_,files in os.walk(temp_dir):
                for f in files: zf.write(os.path.join(root,f), arcname=f)
        zip_buf.seek(0)
        st.download_button("Download ZIP", zip_buf, "report.zip")
        log_action("Generate Report ZIP")
        for f in os.listdir(temp_dir): os.remove(os.path.join(temp_dir,f))
        os.rmdir(temp_dir)

st.markdown("---")
st.caption("Template built with Streamlit + Plotly + Altair. Extend visuals by editing render blocks.")