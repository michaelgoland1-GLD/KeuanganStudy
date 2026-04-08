"""
TeleTriage Web App
Python 3.11.15 + Streamlit

Purpose:
- Pre-hospital teletriage before patient arrives to ED/IGD
- Patient-facing intake with symptom/vital/photo/location capture
- Conservative emergency triage engine (rule-based + semi-AI scoring)
- Admin dashboard with alerts, filters, statistics, and case review
- JSON persistence for patients and users

Important:
- This is NOT a diagnosis engine.
- This must be clinically reviewed and validated before real-world use.
- Default rules are intentionally conservative to avoid under-triage.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import statistics
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
from PIL import Image, ImageOps, ImageStat
from streamlit_autorefresh import st_autorefresh

from streamlit_folium import st_folium
import folium

import streamlit.components.v1 as components


# ============================================================
# CONFIGURATION
# ============================================================

APP_TITLE = "TeleTriage IGD System"
APP_ICON = "🚑"
DATA_DIR = Path("data")
UPLOAD_DIR = DATA_DIR / "uploads"
PATIENTS_FILE = DATA_DIR / "patients.json"
USERS_FILE = DATA_DIR / "users.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

EMERGENCY_PHONE_DEFAULT = os.getenv("TELETRIAGE_EMERGENCY_PHONE", "119")
ADMIN_DEFAULT_USER = os.getenv("TELETRIAGE_ADMIN_USER", "admin")
ADMIN_DEFAULT_PASSWORD = os.getenv("TELETRIAGE_ADMIN_PASS", "ChangeMe123!")
SESSION_AUTH_KEY = "teletriage_authenticated"
SESSION_USER_KEY = "teletriage_user"
SESSION_ALERT_KEY = "teletriage_alert_ack"


# ============================================================
# BASIC DATA MODELS
# ============================================================

TRIAGE_LABELS = {
    1: "ESI 1-RESUSITASI / DARURAT SEKALI",
    2: "ESI 2-SANGAT MENDESAK",
    3: "ESI 3-MENDESAK SEDANG",
    4: "ESI 4-RINGAN",
    5: "ESI 5-SANGAT RINGAN",
}

TRIAGE_COLORS_HINT = {
    1: "🔴",
    2: "🟠",
    3: "🟡",
    4: "🟢",
    5: "🔵",
}

SYMPTOM_OPTIONS = [
    "Nyeri dada",
    "Sesak napas",
    "Bibir kebiruan",
    "Pingsan / hampir pingsan",
    "Kejang sedang berlangsung",
    "Kejang sudah berhenti",
    "Lemah satu sisi tubuh",
    "Bicara pelo / sulit bicara",
    "Wajah mencong",
    "Perdarahan hebat",
    "Luka terbuka berat",
    "Trauma / kecelakaan",
    "Nyeri hebat",
    "Demam tinggi",
    "Muntah berulang",
    "Dehidrasi berat",
    "Alergi berat / bengkak wajah",
    "Ruam menyeluruh / gatal hebat",
    "Nyeri perut hebat",
    "Hamil dengan perdarahan / nyeri hebat",
    "Penurunan kesadaran",
    "Kebingungan / perubahan perilaku",
    "Sulit menelan / tersedak",
    "Luka bakar luas",
    "Keluhan lain",
]

RISK_FACTOR_OPTIONS = [
    "Riwayat penyakit jantung",
    "Riwayat stroke / TIA",
    "Diabetes",
    "Hipertensi",
    "Asma / PPOK",
    "Gangguan ginjal",
    "Hamil",
    "Usia lanjut",
    "Tidak ada faktor risiko yang diketahui",
]

VITAL_PRESETS = [
    "Tidak ada",
    "Sedang diukur / belum tahu",
    "Diketahui dari keluarga / pasien",
]


# ============================================================
# UTILS: JSON / FILES
# ============================================================


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def safe_load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def safe_save_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(path)


def load_patients() -> List[Dict[str, Any]]:
    return safe_load_json(PATIENTS_FILE, [])


def save_patients(patients: List[Dict[str, Any]]) -> None:
    safe_save_json(PATIENTS_FILE, patients)


def load_users() -> List[Dict[str, Any]]:
    return safe_load_json(USERS_FILE, [])


def save_users(users: List[Dict[str, Any]]) -> None:
    safe_save_json(USERS_FILE, users)


def load_settings() -> Dict[str, Any]:
    default = {
        "emergency_phone": EMERGENCY_PHONE_DEFAULT,
        "organization_name": "TeleTriage IGD",
        "auto_refresh_seconds": 8,
        "photo_quality_min_side": 300,
        "photo_quality_min_brightness": 40,
    }
    settings = safe_load_json(SETTINGS_FILE, default)
    for k, v in default.items():
        settings.setdefault(k, v)
    return settings


def save_settings(settings: Dict[str, Any]) -> None:
    safe_save_json(SETTINGS_FILE, settings)


# ============================================================
# SECURITY / AUTH
# ============================================================


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    if isinstance(salt, str):
        salt = bytes.fromhex(salt)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"{salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def ensure_default_admin() -> None:
    users = load_users()
    if users:
        return
    users = [
        {
            "username": ADMIN_DEFAULT_USER,
            "display_name": "System Administrator",
            "role": "admin",
            "password_hash": hash_password(ADMIN_DEFAULT_PASSWORD),
            "created_at": now_iso(),
            "must_change_password": True,
        }
    ]
    save_users(users)


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    for user in load_users():
        if user.get("username") == username and verify_password(password, user.get("password_hash", "")):
            return user
    return None


def set_session_auth(user: Dict[str, Any]) -> None:
    st.session_state[SESSION_AUTH_KEY] = True
    st.session_state[SESSION_USER_KEY] = user


def logout() -> None:
    st.session_state[SESSION_AUTH_KEY] = False
    st.session_state[SESSION_USER_KEY] = None


# ============================================================
# CLINICAL / TRIAGE ENGINE
# ============================================================

@dataclass
class TriageResult:
    level: int
    label: str
    emoji: str
    urgency_text: str
    summary: str
    recommended_action: str
    ambulance_now: bool
    red_flags: List[str]
    factors: List[str]
    score: int
    evidence: List[str]


CRITICAL_RED_FLAGS = {
    "Breathing": [
        "Sesak napas",
        "Bibir kebiruan",
        "Sulit menelan / tersedak",
        "Penurunan kesadaran",
    ],
    "Circulation": [
        "Perdarahan hebat",
        "Pingsan / hampir pingsan",
        "Nyeri dada",
        "Trauma / kecelakaan",
    ],
    "Neurology": [
        "Kejang sedang berlangsung",
        "Lemah satu sisi tubuh",
        "Bicara pelo / sulit bicara",
        "Wajah mencong",
        "Kebingungan / perubahan perilaku",
    ],
    "Allergy": [
        "Alergi berat / bengkak wajah",
        "Ruam menyeluruh / gatal hebat",
    ],
}

def get_gps_location():
    st.markdown("### 📍 Ambil Lokasi Otomatis (GPS HP)")

    gps_html = """
    <script>
    function sendLocation(position) {
        const lat = position.coords.latitude;
        const lon = position.coords.longitude;

        const data = {lat: lat, lon: lon};
        window.parent.postMessage(data, "*");
    }

    function error(err) {
        console.log(err);
    }

    navigator.geolocation.getCurrentPosition(sendLocation, error);
    </script>
    """

    components.html(gps_html, height=0)

    lat = st.session_state.get("lat", None)
    lon = st.session_state.get("lon", None)

    return lat, lon


# def get_location():
#     st.markdown("### 📍 Ambil Lokasi Pasien")

#     location = st.experimental_get_query_params()

#     # fallback manual
#     lat = st.number_input("Latitude", value=0.0)
#     lon = st.number_input("Longitude", value=0.0)

#     return lat, lon

def show_map(lat, lon):
    m = folium.Map(location=[lat, lon], zoom_start=15)

    folium.Marker(
        [lat, lon],
        tooltip="Lokasi Pasien",
        popup="Pasien di sini"
    ).add_to(m)

    st_folium(m, width=700, height=500)


def normalize_text_items(items: List[str]) -> List[str]:
    return [str(i).strip().lower() for i in items if str(i).strip()]


def analyze_photo(image_file) -> Dict[str, Any]:
    """
    Lightweight image-quality + visual-clue analysis.
    This is NOT a medical diagnosis and intentionally conservative.
    """
    try:
        img = Image.open(image_file).convert("RGB")
        img = ImageOps.exif_transpose(img)
        width, height = img.size
        stat = ImageStat.Stat(img)
        r_mean, g_mean, b_mean = stat.mean
        gray = ImageOps.grayscale(img)
        gray_stat = ImageStat.Stat(gray)
        brightness = gray_stat.mean[0]
        contrast = gray_stat.stddev[0]
        red_dominance = max(0.0, r_mean - ((g_mean + b_mean) / 2.0))
        blue_dominance = max(0.0, b_mean - ((r_mean + g_mean) / 2.0))

        quality_flags = []
        if min(width, height) < 300:
            quality_flags.append("Resolusi gambar rendah")
        if brightness < 40:
            quality_flags.append("Gambar terlalu gelap")
        if contrast < 15:
            quality_flags.append("Kontras gambar rendah")

        visual_clues = []
        if red_dominance > 18:
            visual_clues.append("Warna merah dominan terlihat pada foto")
        if blue_dominance > 10:
            visual_clues.append("Warna kebiruan dominan terlihat pada foto")

        return {
            "ok": True,
            "width": width,
            "height": height,
            "brightness": round(brightness, 2),
            "contrast": round(contrast, 2),
            "quality_flags": quality_flags,
            "visual_clues": visual_clues,
            "red_dominance": round(red_dominance, 2),
            "blue_dominance": round(blue_dominance, 2),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "quality_flags": ["Gagal membaca foto"],
            "visual_clues": [],
        }


def triage_engine(
    symptoms: List[str],
    vital_signs: Dict[str, Any],
    risk_factors: List[str],
    photo_analysis: Optional[Dict[str, Any]] = None,
    age: Optional[int] = None,
    complaint: str = "",
    pregnancy: bool = False,
) -> TriageResult:
    symptoms_n = normalize_text_items(symptoms)
    risks_n = normalize_text_items(risk_factors)
    complaint_n = complaint.strip().lower()

    score = 0
    evidence: List[str] = []
    red_flags: List[str] = []
    action_lines: List[str] = []
    ambulance_now = False

    def add_score(points: int, reason: str) -> None:
        nonlocal score
        score += points
        evidence.append(reason)

    # --- Immediate physiologic danger ---
    spo2 = _to_float(vital_signs.get("spo2"))
    rr = _to_float(vital_signs.get("respiratory_rate"))
    hr = _to_float(vital_signs.get("heart_rate"))
    sbp = _to_float(vital_signs.get("sbp"))
    dbp = _to_float(vital_signs.get("dbp"))
    temp = _to_float(vital_signs.get("temperature"))
    gcs = _to_float(vital_signs.get("gcs"))
    pain = _to_float(vital_signs.get("pain_score"))

    if spo2 is not None:
        if spo2 < 90:
            add_score(8, f"SpO2 sangat rendah ({spo2}%)")
            red_flags.append("SpO2 < 90%")
        elif spo2 < 94:
            add_score(4, f"SpO2 rendah ({spo2}%)")

    if rr is not None:
        if rr > 30:
            add_score(6, f"Frekuensi napas sangat tinggi ({rr}/menit)")
            red_flags.append("Tachypnea berat")
        elif rr < 8:
            add_score(7, f"Frekuensi napas sangat rendah ({rr}/menit)")
            red_flags.append("Bradypnea berat")

    if hr is not None:
        if hr > 130:
            add_score(4, f"Nadi sangat cepat ({hr}/menit)")
        elif hr < 40:
            add_score(6, f"Nadi sangat lambat ({hr}/menit)")
            red_flags.append("Bradycardia berat")

    if sbp is not None:
        if sbp < 90:
            add_score(6, f"Sistolik rendah ({sbp} mmHg)")
            red_flags.append("Hipotensi")
        elif sbp > 220:
            add_score(4, f"Sistolik sangat tinggi ({sbp} mmHg)")

    if dbp is not None and dbp > 130:
        add_score(3, f"Diastolik sangat tinggi ({dbp} mmHg)")

    if temp is not None and temp >= 40.0:
        add_score(4, f"Demam sangat tinggi ({temp}°C)")

    if gcs is not None:
        if gcs <= 8:
            add_score(8, f"Penurunan kesadaran berat (GCS {gcs})")
            red_flags.append("GCS rendah")
        elif gcs <= 12:
            add_score(4, f"Penurunan kesadaran sedang (GCS {gcs})")

    if pain is not None and pain >= 8:
        add_score(3, f"Nyeri sangat berat ({pain}/10)")

    # --- Core symptom red flags ---
    if "Nyeri dada".lower() in symptoms_n or "chest pain" in complaint_n:
        add_score(5, "Keluhan nyeri dada")
        red_flags.append("Chest pain")
        evidence.append("Perlu evaluasi sindrom koroner akut bila gejala konsisten")

    if "Sesak napas".lower() in symptoms_n or "bibir kebiruan".lower() in symptoms_n:
        add_score(5, "Gejala gangguan napas")
        red_flags.append("Gangguan napas")

    if any(x in symptoms_n for x in ["pingsan / hampir pingsan", "penurunan kesadaran"]):
        add_score(6, "Sinkop / penurunan kesadaran")
        red_flags.append("Altered consciousness")

    if any(x in symptoms_n for x in ["kejang sedang berlangsung", "kejang sudah berhenti"]):
        add_score(5, "Riwayat kejang")
        if "kejang sedang berlangsung" in symptoms_n:
            red_flags.append("Active seizure")

    if any(x in symptoms_n for x in ["lemah satu sisi tubuh", "bicara pelo / sulit bicara", "wajah mencong"]):
        add_score(6, "Tanda neurologis fokal / FAST positif")
        red_flags.append("Stroke suspected")

    if any(x in symptoms_n for x in ["perdarahan hebat", "luka terbuka berat", "trauma / kecelakaan", "luka bakar luas"]):
        add_score(5, "Trauma atau perdarahan signifikan")
        red_flags.append("Trauma / hemorrhage")

    if any(x in symptoms_n for x in ["alergi berat / bengkak wajah", "ruam menyeluruh / gatal hebat"]):
        add_score(5, "Reaksi alergi berat mungkin")
        red_flags.append("Anaphylaxis suspected")

    if any(x in symptoms_n for x in ["nyeri perut hebat", "hamil dengan perdarahan / nyeri hebat"]):
        add_score(4, "Nyeri abdomen / obstetri berisiko")
        if pregnancy:
            red_flags.append("Pregnancy-related emergency")

    if any(x in symptoms_n for x in ["demam tinggi", "muntah berulang", "dehidrasi berat"]):
        add_score(3, "Sistemik / risiko dehidrasi / infeksi")

    if age is not None and age >= 65:
        add_score(1, "Usia lanjut meningkatkan risiko")
    if "Riwayat penyakit jantung".lower() in risks_n:
        add_score(2, "Riwayat penyakit jantung")
    if "Riwayat stroke / TIA".lower() in risks_n:
        add_score(2, "Riwayat stroke / TIA")
    if "Diabetes".lower() in risks_n:
        add_score(1, "Diabetes")
    if "Hipertensi".lower() in risks_n:
        add_score(1, "Hipertensi")
    if "Asma / PPOK".lower() in risks_n:
        add_score(1, "Asma / PPOK")
    if pregnancy:
        add_score(2, "Kehamilan meningkatkan kewaspadaan")

    # --- Photo-assisted risk boost (non-diagnostic) ---
    if photo_analysis and photo_analysis.get("ok"):
        if photo_analysis.get("quality_flags"):
            evidence.extend([f"Foto: {x}" for x in photo_analysis["quality_flags"]])
        if photo_analysis.get("visual_clues"):
            evidence.extend([f"Foto: {x}" for x in photo_analysis["visual_clues"]])
        if photo_analysis.get("blue_dominance", 0) > 12:
            add_score(2, "Petunjuk visual kebiruan pada foto")
        if photo_analysis.get("red_dominance", 0) > 20 and any(x in symptoms_n for x in ["perdarahan hebat", "luka terbuka berat", "trauma / kecelakaan"]):
            add_score(2, "Petunjuk visual merah dominan + trauma/perdarahan")

    # --- Conservative triage decision tree ---
    if (
        any(x in red_flags for x in ["SpO2 < 90%", "GCS rendah", "Stroke suspected", "Anaphylaxis suspected", "Trauma / hemorrhage", "Active seizure"])
        or (pain is not None and pain >= 9 and ("nyeri dada" in symptoms_n or "sesak napas" in symptoms_n))
        or (sbp is not None and sbp < 90 and (hr is not None and hr > 120))
    ):
        level = 1
    elif score >= 8 or any(x in red_flags for x in ["Chest pain", "Gangguan napas", "Altered consciousness", "Pregnancy-related emergency"]):
        level = 2
    elif score >= 4:
        level = 3
    elif score >= 2:
        level = 4
    else:
        level = 5

    ambulance_now = level in (1, 2)

    if level == 1:
        urgency_text = "Ambulans / IGD segera. Prioritas resusitasi."
        action_lines = [
            "Hubungi ambulans / layanan gawat darurat sekarang.",
            "Pastikan jalan napas, pernapasan, dan sirkulasi.",
            "Jangan tinggalkan pasien sendirian.",
            "Siapkan lokasi, usia, gejala, obat yang diminum, dan waktu mulai gejala.",
        ]
        summary = "Pasien tampak sangat berisiko mengalami kegawatan kritis."
    elif level == 2:
        urgency_text = "Segera ke IGD / ambulans bila kondisi memburuk."
        action_lines = [
            "Rujuk ke IGD segera dengan pengawasan ketat.",
            "Pantau napas, kesadaran, dan nyeri.",
            "Kurangi aktivitas dan siapkan transportasi medis.",
        ]
        summary = "Pasien berisiko tinggi dan membutuhkan penilaian darurat cepat."
    elif level == 3:
        urgency_text = "Perlu evaluasi klinis segera, tetapi tidak selalu ambulans."
        action_lines = [
            "Segera konsultasi ke fasilitas kesehatan terdekat.",
            "Pantau perburukan gejala.",
            "Jika muncul nyeri dada, sesak napas, pingsan, atau lemah satu sisi, naikkan ke darurat."
        ]
        summary = "Pasien membutuhkan penilaian medis dalam waktu singkat."
    elif level == 4:
        urgency_text = "Keluhan ringan-sedang, evaluasi terjadwal."
        action_lines = [
            "Disarankan kontrol/telekonsultasi.",
            "Bila gejala memburuk, ulangi triase.",
        ]
        summary = "Pasien cenderung stabil saat ini."
    else:
        urgency_text = "Keluhan ringan, edukasi dan observasi mandiri."
        action_lines = [
            "Monitor gejala.",
            "Cari bantuan medis jika muncul red flag.",
        ]
        summary = "Pasien tampak paling rendah risiko saat ini."

    if not evidence:
        evidence.append("Tidak ada red flag mayor terdeteksi dari input awal")

    return TriageResult(
        level=level,
        label=TRIAGE_LABELS[level],
        emoji=TRIAGE_COLORS_HINT[level],
        urgency_text=urgency_text,
        summary=summary,
        recommended_action=" ".join(action_lines),
        ambulance_now=ambulance_now,
        red_flags=red_flags,
        factors=evidence,
        score=score,
        evidence=evidence 
    )


def _to_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


# ============================================================
# UI HELPERS
# ============================================================


# def inject_refresh(seconds: int) -> None:
#     """Simple full-page refresh for live-ish admin updates."""
#     seconds = max(5, int(seconds))
#     st.markdown(
#         f'<meta http-equiv="refresh" content="{seconds}">',
#         unsafe_allow_html=True,
#     )

def inject_refresh(seconds: int):
    st_autorefresh(interval=seconds * 1000, key="admin_refresh")


def fmt_value(v: Any) -> str:
    return "-" if v in (None, "", []) else str(v)


def download_json_button(data: Any, file_name: str, label: str) -> None:
    payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    st.download_button(label=label, data=payload, file_name=file_name, mime="application/json")


def short_id() -> str:
    return uuid.uuid4().hex[:8].upper()


# ============================================================
# PATIENT STORAGE
# ============================================================


def build_patient_record(
    name: str,
    age: int,
    sex: str,
    complaint: str,
    symptoms: List[str],
    risk_factors: List[str],
    vitals: Dict[str, Any],
    photo_meta: Optional[Dict[str, Any]],
    image_path: Optional[str],
    location_text: str,
    gps_lat: Optional[float],
    gps_lon: Optional[float],
    pregnancy: bool,
    triage: TriageResult,
    contact_phone: str,
    source: str = "patient_web",
) -> Dict[str, Any]:
    patient_id = f"PT-{short_id()}"
    return {
        "patient_id": patient_id,
        "created_at": now_iso(),
        "source": source,
        "name": name,
        "age": age,
        "sex": sex,
        "pregnancy": pregnancy,
        "chief_complaint": complaint,
        "symptoms": symptoms,
        "risk_factors": risk_factors,
        "vitals": vitals,
        "photo_meta": photo_meta,
        "image_path": image_path,
        "location_text": location_text,
        "gps_lat": gps_lat,
        "gps_lon": gps_lon,
        "emergency_phone": contact_phone,
        "triage": asdict(triage),
        "status": "NEW",
        "reviewed_by": None,
        "notes": "",
    }


# ============================================================
# PAGES
# ============================================================


def render_header(settings: Dict[str, Any]) -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon=APP_ICON, layout="wide")
    st.title(f"{APP_ICON} {settings['organization_name']}")
    st.caption(
        "Pre-hospital teletriage untuk membantu menentukan tingkat kegawatan sebelum pasien tiba di IGD."
    )
    st.warning(
        "Sistem ini hanya untuk triase awal dan dukungan keputusan. Bukan pengganti tenaga medis atau diagnosis final."
    )


def patient_page(settings: Dict[str, Any]) -> None:
    st.subheader("Input Pasien")

    lat, lon = get_gps_location()

    if lat and lon:
        st.success(f"Lokasi terdeteksi: {lat}, {lon}")
    else:
        st.warning("Klik izinkan lokasi di browser")


    col1, col2, col3 = st.columns(3)
    with col1:
        name = st.text_input("Nama pasien", placeholder="Contoh: Budi")
        age = st.number_input("Umur", min_value=0, max_value=120, value=30, step=1)
        sex = st.selectbox("Jenis kelamin", ["Laki-laki", "Perempuan", "Lainnya / tidak ingin menyebutkan"])
    with col2:
        complaint = st.text_area(
            "Keluhan utama",
            placeholder="Contoh: nyeri dada sejak 30 menit, menjalar ke lengan kiri",
            height=120,
        )
        pregnancy = st.checkbox("Sedang hamil / kemungkinan hamil", value=False)
        location_text = st.text_input("Lokasi pasien / alamat", placeholder="Contoh: Jl. ..., Depok")
    with col3:
        emergency_phone = st.text_input("Nomor ambulans darurat", value=settings["emergency_phone"])
        gps_lat = st.text_input("Latitude (opsional)")
        gps_lon = st.text_input("Longitude (opsional)")

    st.markdown("---")
    st.markdown("### Gejala")
    symptoms = st.multiselect("Pilih gejala yang sesuai", SYMPTOM_OPTIONS)
    custom_symptom = st.text_input("Tambahkan gejala lain (opsional)")
    if custom_symptom.strip():
        symptoms = symptoms + [custom_symptom.strip()]

    st.markdown("### Faktor risiko")
    risk_factors = st.multiselect("Pilih faktor risiko", RISK_FACTOR_OPTIONS)
    if "Tidak ada faktor risiko yang diketahui" in risk_factors and len(risk_factors) > 1:
        risk_factors = [x for x in risk_factors if x != "Tidak ada faktor risiko yang diketahui"]

    st.markdown("### Pemeriksaan awal")
    input_mode = st.radio(
        "Mode input",
        ["Awam / keluarga pasien", "Medis / tenaga kesehatan"],
        horizontal=True,
        help="Pilih mode yang paling sesuai. Mode awam memakai bahasa sederhana dan isian yang lebih mudah dimengerti.",
    )

    vitals = {}

    if input_mode == "Awam / keluarga pasien":
        st.info(
            "Isi yang paling mudah dulu: suhu tubuh, tekanan darah, detak jantung. Bila ada, tambahkan juga apakah pasien sesak napas dan apakah pasien sadar penuh."
        )
        v1, v2, v3 = st.columns(3)
        with v1:
            temp = st.number_input("Suhu tubuh (°C)", min_value=30.0, max_value=45.0, value=36.8, step=0.1)
            bp_known = st.checkbox("Tekanan darah diketahui", value=True)
            if bp_known:
                sbp = st.number_input("Tensi atas / sistolik (mmHg)", min_value=0, max_value=300, value=120, step=1)
                dbp = st.number_input("Tensi bawah / diastolik (mmHg)", min_value=0, max_value=200, value=80, step=1)
            else:
                sbp = None
                dbp = None
        with v2:
            hr = st.number_input("Detak jantung per menit", min_value=0, max_value=250, value=80, step=1)
            spo2_known = st.checkbox("Saturasi oksigen diketahui", value=False)
            if spo2_known:
                spo2 = st.number_input("Saturasi oksigen (%)", min_value=0, max_value=100, value=98, step=1)
            else:
                spo2 = None
            pain_score = st.slider("Nyeri berat atau tidak?", min_value=0, max_value=10, value=0, help="0 = tidak nyeri, 10 = nyeri sangat berat")
        with v3:
            breath_simple = st.radio(
                "Apakah pasien sesak napas?",
                ["Tidak", "Ya, ringan", "Ya, sedang", "Ya, berat"],
                index=0,
            )
            conscious_simple = st.radio(
                "Apakah pasien sadar penuh?",
                ["Ya, sadar penuh", "Agak bingung / mengantuk", "Tidak sadar / sulit dibangunkan"],
                index=0,
            )
            gcs = 15 if conscious_simple == "Ya, sadar penuh" else (12 if conscious_simple == "Agak bingung / mengantuk" else 7)
            rr = None

        if breath_simple == "Tidak":
            breath_score = 0
        elif breath_simple == "Ya, ringan":
            breath_score = 1
        elif breath_simple == "Ya, sedang":
            breath_score = 2
        else:
            breath_score = 3

        if spo2 is None:
            spo2 = 98 if breath_score == 0 else (95 if breath_score == 1 else (92 if breath_score == 2 else 88))

        vitals = {
            "spo2": spo2,
            "heart_rate": hr,
            "respiratory_rate": rr,
            "sbp": sbp,
            "dbp": dbp,
            "temperature": temp,
            "gcs": gcs,
            "pain_score": pain_score,
            "source_preset": "Awam / keluarga pasien",
            "breath_simple": breath_simple,
            "breath_score": breath_score,
            "conscious_simple": conscious_simple,
        }

    else:
        st.markdown("**Silakan isi parameter medis lengkap bila Anda tenaga kesehatan.**")
        v1, v2, v3 = st.columns(3)
        with v1:
            spo2 = st.number_input("SpO2 (%)", min_value=0, max_value=100, value=98, step=1)
            hr = st.number_input("Nadi / menit", min_value=0, max_value=250, value=80, step=1)
            rr = st.number_input("RR / menit", min_value=0, max_value=60, value=18, step=1)
        with v2:
            sbp = st.number_input("Sistolik (mmHg)", min_value=0, max_value=300, value=120, step=1)
            dbp = st.number_input("Diastolik (mmHg)", min_value=0, max_value=200, value=80, step=1)
            temp = st.number_input("Suhu (°C)", min_value=30.0, max_value=45.0, value=36.8, step=0.1)
        with v3:
            gcs = st.number_input("GCS (3-15)", min_value=3, max_value=15, value=15, step=1)
            pain_score = st.number_input("Nyeri (0-10)", min_value=0, max_value=10, value=0, step=1)
            breath_simple = st.radio(
                "Kondisi napas (ringkas)",
                ["Tidak", "Ringan", "Sedang", "Berat"],
                index=0,
            )

        vitals = {
            "spo2": spo2,
            "heart_rate": hr,
            "respiratory_rate": rr,
            "sbp": sbp,
            "dbp": dbp,
            "temperature": temp,
            "gcs": gcs,
            "pain_score": pain_score,
            "source_preset": "Medis / tenaga kesehatan",
            "breath_simple": breath_simple,
        }

    st.markdown("### Foto kondisi pasien")
    uploaded_file = st.file_uploader(
        "Upload foto (luka, ruam, pucat, sianosis, perdarahan, trauma, dll.)",
        type=["jpg", "jpeg", "png", "webp"],
    )

    photo_meta = None
    image_path = None

    if uploaded_file is not None:
        preview = Image.open(uploaded_file)
        st.image(preview, caption="Preview foto yang diunggah", use_container_width=True)

    col_left, col_right = st.columns([1, 1])
    with col_left:
        submitted = st.button("🔍 Proses Teletriase", type="primary", use_container_width=True)
    with col_right:
        st.info(f"Nomor darurat default: {settings['emergency_phone']}")

    if submitted:
        if not name.strip():
            st.error("Nama pasien wajib diisi.")
            return
        if not complaint.strip() and not symptoms:
            st.error("Isi keluhan utama atau pilih gejala minimal satu.")
            return

        if uploaded_file is not None:
            try:
                saved_name = f"{short_id()}_{uploaded_file.name}"
                image_path = str(UPLOAD_DIR / saved_name)
                with open(image_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                photo_meta = analyze_photo(image_path)
            except Exception as exc:
                st.warning(f"Foto tersimpan gagal dianalisis: {exc}")

        photo_for_engine = photo_meta if photo_meta else None
        result = triage_engine(
            symptoms=symptoms,
            vital_signs=vitals,
            risk_factors=risk_factors,
            photo_analysis=photo_for_engine,
            age=int(age),
            complaint=complaint,
            pregnancy=pregnancy,
        )

        lat_val = _to_float(gps_lat)
        lon_val = _to_float(gps_lon)

        record = build_patient_record(
            name=name.strip(),
            age=int(age),
            sex=sex,
            complaint=complaint.strip(),
            symptoms=symptoms,
            risk_factors=risk_factors,
            vitals=vitals,
            photo_meta=photo_meta,
            image_path=image_path,
            location_text=location_text.strip(),
            gps_lat=lat_val,
            gps_lon=lon_val,
            pregnancy=pregnancy,
            triage=result,
            contact_phone=emergency_phone.strip() or settings["emergency_phone"],
        )

        patients = load_patients()
        patients.append(record)
        save_patients(patients)

        render_triage_result(record)


def render_triage_result(record: Dict[str, Any]) -> None:
    triage = record["triage"]
    level = triage["level"]
    emoji = triage["emoji"]

    st.markdown("---")
    st.subheader("Hasil Teletriase")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Level", f"{level}")
    c2.metric("Label", triage["label"])
    c3.metric("Skor Risiko", triage["score"])
    c4.metric("Ambulans segera", "YA" if triage["ambulance_now"] else "TIDAK")

    if level == 1:
        st.error(f"{emoji} {triage['urgency_text']}")
    elif level == 2:
        st.warning(f"{emoji} {triage['urgency_text']}")
    elif level == 3:
        st.info(f"{emoji} {triage['urgency_text']}")
    else:
        st.success(f"{emoji} {triage['urgency_text']}")

    st.write("**Ringkasan:**", triage["summary"])
    st.write("**Tindakan yang disarankan:**", triage["recommended_action"])

    if triage["red_flags"]:
        st.markdown("### Red flags")
        for item in triage["red_flags"]:
            st.error(item)

    st.markdown("### Alasan penilaian")
    for item in triage["factors"]:
        st.write(f"- {item}")

    if record.get("image_path") and Path(record["image_path"]).exists():
        st.markdown("### Foto tersimpan")
        st.image(record["image_path"], caption="Dokumentasi kondisi pasien", use_container_width=True)

    st.markdown("### Data pasien tersimpan")
    st.json(record)

    st.markdown("### Tindakan cepat")
    if triage["ambulance_now"]:
        st.error(f"🚑 Hubungi ambulans sekarang: {record['emergency_phone']}")
    else:
        st.info("Pantau kondisi pasien. Bila muncul perburukan, ulangi triase dan naikkan prioritas.")


# ============================================================
# ADMIN DASHBOARD
# ============================================================


def admin_page(settings: Dict[str, Any]) -> None:
    inject_refresh(settings["auto_refresh_seconds"])

    st.subheader("Dashboard Admin / IGD")
    patients = load_patients()[::-1]

    # Alerts
    urgent_cases = [p for p in patients if p.get("triage", {}).get("level") in (1, 2)]
    if urgent_cases:
        st.error(f"🚨 {len(urgent_cases)} pasien membutuhkan perhatian cepat")
        for case in urgent_cases[:5]:
            triage = case.get("triage", {})
            st.write(f"- {case.get('patient_id')} | {case.get('name')} | {triage.get('label')} | {case.get('emergency_phone')}")
    else:
        st.success("Tidak ada kasus darurat tinggi saat ini.")

    total = len(patients)
    level_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for p in patients:
        lvl = int(p.get("triage", {}).get("level", 5))
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Pasien", total)
    m2.metric("Level 1", level_counts[1])
    m3.metric("Level 2", level_counts[2])
    m4.metric("Level 3", level_counts[3])
    m5.metric("Level 4-5", level_counts[4] + level_counts[5])

    st.markdown("---")

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        filter_status = st.selectbox("Filter triage", ["Semua", "ESI 1", "ESI 2", "ESI 3", "ESI 4", "ESI 5"])
    with col_b:
        search_query = st.text_input("Cari nama / ID / keluhan")
    with col_c:
        only_urgent = st.checkbox("Hanya level 1-2", value=False)

    filtered = []
    for p in patients:
        triage = p.get("triage", {})
        level = int(triage.get("level", 5))
        if filter_status != "Semua" and triage.get("label", "") != filter_status.replace("ESI ", "ESI "):
            if filter_status != "Semua" and f"ESI {level}" != filter_status:
                continue
        if only_urgent and level not in (1, 2):
            continue
        hay = f"{p.get('patient_id', '')} {p.get('name', '')} {p.get('chief_complaint', '')}".lower()
        if search_query and search_query.lower() not in hay:
            continue
        filtered.append(p)

    st.caption(f"Menampilkan {len(filtered)} dari {total} data pasien.")

    # Export section
    colx, coly = st.columns(2)
    with colx:
        download_json_button(filtered, "teletriage_filtered.json", "Unduh data terfilter (JSON)")
    with coly:
        download_json_button(patients, "teletriage_all_patients.json", "Unduh semua data pasien (JSON)")

    st.markdown("---")

    # Patient list and detailed cards
    for p in filtered:
        triage = p.get("triage", {})
        level = int(triage.get("level", 5))
        badge = TRIAGE_COLORS_HINT.get(level, "⚪")
        title = f"{badge} {p.get('patient_id')} | {p.get('name')} | {triage.get('label')}"
        with st.expander(title, expanded=level in (1, 2)):
            c1, c2, c3, c4 = st.columns(4)
            c1.write(f"**Umur:** {p.get('age')}")
            c2.write(f"**Jenis kelamin:** {p.get('sex')}")
            c3.write(f"**Status:** {p.get('status')}")
            c4.write(f"**Waktu:** {p.get('created_at')}")

            st.write("**Keluhan utama:**", p.get("chief_complaint", "-"))
            st.write("**Lokasi:**", p.get("location_text", "-"))
            if p.get("gps_lat") is not None or p.get("gps_lon") is not None:
                st.write(f"**GPS:** {p.get('gps_lat', '-')}, {p.get('gps_lon', '-')}")

            st.write("**Gejala:**", ", ".join(p.get("symptoms", [])) or "-")
            st.write("**Faktor risiko:**", ", ".join(p.get("risk_factors", [])) or "-")
            st.write("**Hasil triage:**", triage.get("urgency_text", "-"))
            st.write("**Tindakan:**", triage.get("recommended_action", "-"))
            st.write("**Alasan:**")
            for item in triage.get("factors", []):
                st.write(f"- {item}")

            if triage.get("red_flags"):
                st.markdown("**Red flags:**")
                for flag in triage.get("red_flags", []):
                    st.error(flag)

            if p.get("photo_meta"):
                st.markdown("**Analisis foto (non-diagnostik):**")
                st.json(p["photo_meta"])
            if p.get("image_path") and Path(p["image_path"]).exists():
                st.image(p["image_path"], caption="Foto pasien", use_container_width=True)

            st.markdown("**Catatan admin:**")
            note_key = f"note_{p.get('patient_id')}"
            current_note = p.get("notes", "")
            new_note = st.text_area("Tulis catatan", value=current_note, key=note_key, height=120)
            coln1, coln2, coln3 = st.columns(3)
            with coln1:
                update_status = st.selectbox(
                    "Update status",
                    ["NEW", "REVIEWED", "REFERRED", "ARRIVED", "CLOSED"],
                    index=["NEW", "REVIEWED", "REFERRED", "ARRIVED", "CLOSED"].index(p.get("status", "NEW"))
                    if p.get("status", "NEW") in ["NEW", "REVIEWED", "REFERRED", "ARRIVED", "CLOSED"]
                    else 0,
                    key=f"status_{p.get('patient_id')}",
                )
            with coln2:
                reviewer = st.text_input("Reviewed by", value=p.get("reviewed_by") or "", key=f"rev_{p.get('patient_id')}")
            with coln3:
                save_btn = st.button("Simpan perubahan", key=f"save_{p.get('patient_id')}")

            if save_btn:
                all_patients = load_patients()
                for idx, item in enumerate(all_patients):
                    if item.get("patient_id") == p.get("patient_id"):
                        all_patients[idx]["notes"] = new_note
                        all_patients[idx]["status"] = update_status
                        all_patients[idx]["reviewed_by"] = reviewer
                        all_patients[idx]["updated_at"] = now_iso()
                        break
                save_patients(all_patients)
                st.success("Perubahan disimpan.")
                st.rerun()

    st.markdown("---")
    st.subheader("Ringkasan operasional")
    st.write(
        "Sistem ini mendukung review pra-IGD, memudahkan identifikasi pasien prioritas tinggi, dan menampilkan foto/lokasi agar tim dapat bersiap sebelum pasien tiba."
    )


# ============================================================
# SETTINGS / SECURITY PANEL
# ============================================================


def security_page(settings: Dict[str, Any]) -> None:
    st.subheader("Keamanan & Pengaturan")
    users = load_users()

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("### Ubah pengaturan sistem")
        org_name = st.text_input("Nama organisasi", value=settings["organization_name"])
        phone = st.text_input("Nomor darurat", value=settings["emergency_phone"])
        refresh = st.number_input("Auto-refresh admin (detik)", min_value=5, max_value=60, value=int(settings["auto_refresh_seconds"]), step=1)
        min_side = st.number_input("Minimal sisi foto (px)", min_value=100, max_value=2000, value=int(settings["photo_quality_min_side"]), step=50)
        min_brightness = st.number_input("Minimal brightness foto", min_value=0, max_value=255, value=int(settings["photo_quality_min_brightness"]), step=5)
        if st.button("Simpan pengaturan"):
            settings["organization_name"] = org_name.strip() or settings["organization_name"]
            settings["emergency_phone"] = phone.strip() or settings["emergency_phone"]
            settings["auto_refresh_seconds"] = int(refresh)
            settings["photo_quality_min_side"] = int(min_side)
            settings["photo_quality_min_brightness"] = int(min_brightness)
            save_settings(settings)
            st.success("Pengaturan disimpan.")

    with c2:
        st.markdown("### Akun admin")
        st.caption("Default akun pertama dibuat otomatis saat instalasi. Sebaiknya ganti password segera.")
        st.table([
            {
                "username": u.get("username"),
                "display_name": u.get("display_name"),
                "role": u.get("role"),
                "must_change_password": u.get("must_change_password", False),
            }
            for u in users
        ])

        with st.expander("Buat akun admin baru"):
            new_user = st.text_input("Username baru", key="new_user")
            new_name = st.text_input("Nama tampilan", key="new_name")
            new_pass = st.text_input("Password baru", type="password", key="new_pass")
            if st.button("Tambah akun"):
                if not new_user or not new_pass:
                    st.error("Username dan password wajib diisi.")
                else:
                    if any(u.get("username") == new_user for u in users):
                        st.error("Username sudah ada.")
                    else:
                        users.append(
                            {
                                "username": new_user,
                                "display_name": new_name or new_user,
                                "role": "admin",
                                "password_hash": hash_password(new_pass),
                                "created_at": now_iso(),
                                "must_change_password": False,
                            }
                        )
                        save_users(users)
                        st.success("Akun admin ditambahkan.")

        with st.expander("Ganti password akun aktif"):
            if st.session_state.get(SESSION_USER_KEY):
                current_user = st.session_state[SESSION_USER_KEY]
                old_pass = st.text_input("Password lama", type="password", key="old_pass")
                new_pass1 = st.text_input("Password baru", type="password", key="new_pass1")
                new_pass2 = st.text_input("Ulangi password baru", type="password", key="new_pass2")
                if st.button("Update password"):
                    if new_pass1 != new_pass2:
                        st.error("Password baru tidak sama.")
                    else:
                        users = load_users()
                        updated = False
                        for u in users:
                            if u.get("username") == current_user.get("username"):
                                if not verify_password(old_pass, u.get("password_hash", "")):
                                    st.error("Password lama salah.")
                                    break
                                u["password_hash"] = hash_password(new_pass1)
                                u["must_change_password"] = False
                                updated = True
                                break
                        if updated:
                            save_users(users)
                            st.success("Password berhasil diubah.")
            else:
                st.info("Login admin terlebih dahulu untuk mengganti password.")

    st.markdown("---")
    st.markdown("### Catatan keselamatan klinis")
    st.info(
        "Gunakan protokol yang sudah direview dokter, perawat IGD, dan komite mutu. Aturan dalam aplikasi ini bersifat konservatif, bukan pengganti SOP rumah sakit."
    )


# ============================================================
# LOGIN PANEL
# ============================================================


def login_panel() -> None:
    with st.sidebar:
        st.markdown("### Admin Login")
        if st.session_state.get(SESSION_AUTH_KEY) and st.session_state.get(SESSION_USER_KEY):
            user = st.session_state[SESSION_USER_KEY]
            st.success(f"Login: {user.get('display_name')} ({user.get('username')})")
            if st.button("Logout"):
                logout()
                st.rerun()
            return

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Masuk"):
            user = authenticate(username, password)
            if user:
                set_session_auth(user)
                st.success("Login berhasil.")
                st.rerun()
            else:
                st.error("Username atau password salah.")


# ============================================================
# MAIN APP
# ============================================================
def receive_location():
    query_params = st.query_params

    if "lat" in query_params and "lon" in query_params:
        st.session_state["lat"] = float(query_params["lat"])
        st.session_state["lon"] = float(query_params["lon"])

def main() -> None:
    ensure_default_admin()
    settings = load_settings()
    render_header(settings)
    login_panel()
    receive_location()

    menu = st.sidebar.radio("Menu", ["Pasien", "Admin", "Keamanan", "Panduan"])

    st.sidebar.markdown("---")
    st.sidebar.write("**Nomor darurat:**", settings["emergency_phone"])
    st.sidebar.write("**Prinsip triase:**")
    st.sidebar.write("- Lebih aman mengetahui sebelum dibawa IGD")
    # st.sidebar.write("- Nyeri dada + sesak + sinkop = curiga emergensi")
    # st.sidebar.write("- FAST positif = curiga stroke")
    # st.sidebar.write("- Saturasi < 90% = red flag")

    if menu == "Pasien":
        patient_page(settings)
    elif menu == "Admin":
        if st.session_state.get(SESSION_AUTH_KEY):
            admin_page(settings)
        else:
            st.error("Admin hanya bisa diakses setelah login.")
    elif menu == "Keamanan":
        if st.session_state.get(SESSION_AUTH_KEY):
            security_page(settings)
        else:
            st.error("Halaman keamanan hanya bisa diakses setelah login.")
    elif menu == "Panduan":
        guidance_page(settings)

    st.sidebar.markdown("---")
    st.sidebar.caption("Prototype teletriage pre-hospital. Dibuat Oleh Michael Goland")


# ============================================================
# GUIDANCE PAGE
# ============================================================


def guidance_page(settings: Dict[str, Any]) -> None:
    st.subheader("Panduan penggunaan")
    st.write("1. Pasien atau keluarga membuka halaman Pasien.")
    st.write("2. Isi keluhan, gejala, tanda vital, lokasi, dan foto bila ada.")
    st.write("3. Sistem menghitung level triase dengan prinsip konservatif.")
    st.write("4. Admin memantau daftar pasien dan prioritas tinggi sebelum pasien tiba di IGD.")
    st.write("5. Bila level 1 atau 2, hubungi ambulans sesuai nomor darurat yang tersedia.")

    st.markdown("### Contoh red flag utama")
    st.write("- Nyeri dada dengan sesak napas / keringat dingin")
    st.write("- Lemah satu sisi tubuh, bicara pelo, atau wajah mencong")
    st.write("- Penurunan kesadaran atau kejang aktif")
    st.write("- SpO2 rendah, perdarahan berat, reaksi alergi berat")

    st.markdown("### Rekomendasi implementasi lanjutan")
    st.write("- Integrasi FastAPI untuk backend API")
    st.write("- PostgreSQL untuk data klinis terstruktur")
    st.write("- Audit log dan role-based access control")
    st.write("- Validasi SOP oleh dokter IGD / komite medis")
    st.write("- Integrasi peta dan routing ambulans")

    st.markdown("### Disclaimer")
    st.warning(
        "Konten klinis dalam aplikasi ini bersifat dukungan keputusan awal. Untuk pemakaian nyata, setiap algoritma harus direview dan disetujui oleh tenaga medis berwenang."
    )


if __name__ == "__main__":
    main()
