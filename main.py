from fastapi import FastAPI

# Inisialisasi aplikasi
app = FastAPI()

# Membuat endpoint pertama (Route)
@app.get("/")
def read_root():
    return {"pesan": "Halo, Server FocusTalk Berjalan!"}

# Membuat endpoint untuk cek soal (Contoh)
@app.get("/soal")
def ambil_soal():
    return {
        "id": 1,
        "pertanyaan": "What is the synonym of 'Delay'?",
        "jawaban": "Procrastinate"
    }