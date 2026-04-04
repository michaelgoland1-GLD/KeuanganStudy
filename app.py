import streamlit as st
import json
import os
import pandas as pd
from datetime import datetime
import calendar

# Konfigurasi Halaman
st.set_page_config(page_title="GOLAND Finance Tracker", layout="wide")

FILE = "finance_data.json"
DEFAULT = {
    "income": 1200000,
    "categories": {
        "Gym": {"budget": 150000, "spent": 0},
        "Potong Rambut": {"budget": 45000, "spent": 0},
        "Kuota": {"budget": 60000, "spent": 0},
        "Ngopi/Tugas": {"budget": 300000, "spent": 0},
        "Self Reward": {"budget": 545000, "spent": 0},
        "Tabungan": {"budget": 100000, "spent": 0}
    },
    "history": []
}

# --- FUNGSI DATA ---
def load_data():
    if os.path.exists(FILE):
        with open(FILE, "r") as f:
            return json.load(f)
    return DEFAULT

def save_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=4)

# Inisialisasi State (Agar data tidak hilang saat refresh)
if 'data' not in st.session_state:
    st.session_state.data = load_data()

data = st.session_state.data

def format_rp(x):
    return f"Rp {x:,.0f}".replace(",", ".")

# --- UI SIDEBAR (INCOME) ---
st.sidebar.title("💰 Pengaturan Income")
new_income = st.sidebar.number_input("Set Income", value=float(data["income"]), step=10000.0)
if st.sidebar.button("Update Income"):
    data["income"] = new_income
    save_data(data)
    st.sidebar.success("Income diperbarui!")

# --- UI UTAMA ---
st.title("🚀 GOLAND Finance Tracker ULTIMATE")
st.markdown("---")

# Row 1: Input Transaksi
col1, col2, col3 = st.columns([2, 2, 1])

with col1:
    cat_option = st.selectbox("Pilih Kategori", list(data["categories"].keys()))
with col2:
    amount_input = st.number_input("Nominal Pengeluaran", min_value=0, step=1000)
with col3:
    date_input = st.date_input("Tanggal", datetime.now())

if st.button("Tambah Pengeluaran", use_container_width=True):
    if amount_input > 0:
        data["categories"][cat_option]["spent"] += amount_input
        new_entry = {
            "date": str(date_input),
            "category": cat_option,
            "amount": amount_input
        }
        data["history"].insert(0, new_entry)
        save_data(data)
        st.success(f"Berhasil menambah pengeluaran untuk {cat_option}!")
        st.rerun()

st.markdown("### 📊 Status Anggaran")

# Menghitung Total
total_spent = sum(c["spent"] for c in data["categories"].values())
sisa_saldo = data["income"] - total_spent

# Tampilan Metrik Utama
m1, m2, m3 = st.columns(3)
m1.metric("Total Income", format_rp(data["income"]))
m2.metric("Total Terpakai", format_rp(total_spent), delta=format_rp(total_spent), delta_color="inverse")
m3.metric("Sisa Saldo", format_rp(sisa_saldo))

# Tabel Kategori & Progress Bar
for name, info in data["categories"].items():
    remain = info["budget"] - info["spent"]
    percent = min(info["spent"] / info["budget"], 1.0) if info["budget"] > 0 else 0
    
    col_n, col_b, col_s, col_r, col_btn = st.columns([2, 2, 2, 2, 1])
    col_n.write(f"**{name}**")
    col_b.write(f"Budget: {format_rp(info['budget'])}")
    col_s.write(f"Pakai: {format_rp(info['spent'])}")
    col_r.write(f"Sisa: {format_rp(remain)}")
    
    if col_btn.button("Reset", key=name):
        data["categories"][name]["spent"] = 0
        save_data(data)
        st.rerun()
    
    st.progress(percent)

# --- ANALISA & HISTORY ---
st.markdown("---")
tab1, tab2 = st.tabs(["🕒 History Transaksi", "📈 Analisis"])

with tab1:
    if st.button("Hapus Semua History"):
        data["history"] = []
        save_data(data)
        st.rerun()
        
    if data["history"]:
        df = pd.DataFrame(data["history"])
        st.table(df)
    else:
        st.info("Belum ada riwayat transaksi.")

with tab2:
    if data["history"]:
        df_history = pd.DataFrame(data["history"])
        # Analisis Hari Ini
        today_str = str(date_input)
        today_total = df_history[df_history['date'] == today_str]['amount'].sum()
        
        # Analisis Bulan Ini
        month_str = today_str[:7]
        month_total = df_history[df_history['date'].str.contains(month_str)]['amount'].sum()
        
        c_an1, c_an2 = st.columns(2)
        c_an1.info(f"**Total Hari Ini ({today_str}):**\n\n {format_rp(today_total)}")
        c_an2.info(f"**Total Bulan Ini:**\n\n {format_rp(month_total)}")
    else:
        st.write("Data tidak cukup untuk analisis.")