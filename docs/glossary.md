# Glossary - Kamus Istilah SDN Anomaly Detection

## Istilah SDN dan Jaringan

- **SDN (Software-Defined Networking)**: Arsitektur jaringan yang memisahkan control plane dari data plane, memungkinkan pengontrol jaringan terpusat.

- **Control Plane**: Bagian jaringan yang membuat keputusan tentang bagaimana lalu lintas harus diarahkan, termasuk algoritma routing.

- **Data Plane**: Bagian jaringan yang meneruskan paket berdasarkan keputusan yang dibuat oleh control plane.

- **OpenFlow**: Protokol komunikasi yang memberikan akses ke forwarding plane perangkat jaringan seperti switch dan router.

- **Ryu**: Framework controller SDN berbasis Python.

- **Flow**: Serangkaian paket jaringan yang memiliki attribut yang sama (source/destination IP, port, protocol).

- **Flow Entry**: Aturan yang diterapkan pada switch untuk menentukan bagaimana paket dalam flow tertentu harus ditangani.

- **Flow Table**: Tabel dalam switch OpenFlow yang berisi flow entries.

- **OVS (Open vSwitch)**: Implementasi switch virtual yang mendukung OpenFlow.

- **Mininet**: Emulator jaringan yang membuat virtual hosts, switches, controllers, dan links.

## Istilah Machine Learning dan Deteksi Anomali

- **CNN (Convolutional Neural Network)**: Jenis jaringan saraf yang cocok untuk mengenali pola spasial dalam data.

- **LSTM (Long Short-Term Memory)**: Jenis jaringan saraf rekuren (RNN) yang dapat mempelajari dependensi jangka panjang dalam data sekuensial.

- **Sequence Length**: Jumlah langkah waktu atau titik data berurutan yang diproses dalam satu contoh data untuk model sekuensial.

- **Inference**: Proses menggunakan model terlatih untuk membuat prediksi pada data baru.

- **Edge Computing**: Pemrosesan data di dekat lokasi data dihasilkan, bukan di pusat data terpusat atau di cloud.

- **TensorFlow Lite**: Framework ML ringan untuk inferensi pada perangkat edge dan mobile.

- **Anomaly**: Pola dalam data yang tidak sesuai dengan perilaku yang diharapkan/normal.

- **True Positive (TP)**: Anomali yang terdeteksi dengan benar.

- **False Positive (FP)**: Data normal yang salah terdeteksi sebagai anomali.

- **True Negative (TN)**: Data normal yang terdeteksi dengan benar sebagai normal.

- **False Negative (FN)**: Anomali yang tidak terdeteksi (salah terdeteksi sebagai normal).

- **Precision**: Persentase deteksi anomali yang benar dari semua data yang diklasifikasikan sebagai anomali (TP/(TP+FP)).

- **Recall**: Persentase anomali yang berhasil terdeteksi dari semua anomali yang sebenarnya (TP/(TP+FN)).

- **F1-Score**: Rata-rata harmonik dari precision dan recall, memberikan satu metrik untuk mengevaluasi model.

## Istilah Serangan Jaringan

- **DDoS (Distributed Denial of Service)**: Serangan yang menggunakan banyak sumber untuk membanjiri target dengan lalu lintas.

- **SYN Flood**: Serangan DDoS yang mengirimkan banyak paket TCP SYN tanpa menyelesaikan handshake.

- **Port Scanning**: Teknik untuk menentukan port terbuka pada sistem target dengan mengirim paket ke berbagai port.

- **Zero-day Attack**: Serangan yang memanfaatkan kerentanan sebelum tersedia patch atau pertahanan.

- **Flow-based Detection**: Metode deteksi anomali berdasarkan analisis karakteristik flow jaringan.

## Istilah Fitur Flow

- **Flow Duration**: Waktu dari paket pertama hingga paket terakhir dalam flow.

- **IAT (Inter-Arrival Time)**: Interval waktu antara kedatangan paket berurutan.

- **Forward Direction**: Aliran paket dari inisiator koneksi ke responder.

- **Backward Direction**: Aliran paket dari responder ke inisiator.

- **TCP Flags**: Flag dalam header TCP (SYN, ACK, FIN, RST, PSH, URG).

- **Packet Length**: Ukuran paket dalam byte, termasuk header dan payload.

- **Subflow**: Bagian dari flow yang memiliki karakteristik konsisten.
