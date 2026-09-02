# CSI fixtures — provenance

Two 60-second ESP32-C6 channel-state-information captures from the
Universidad de Cuenca Wi-Fi sensing dataset (HeliosSm), used as the external
oracle for `radar::csi`:

| file | dataset file | label |
|---|---|---|
| `c6_empty_room_iter1.csv` | `Escenario 1/linea_base_iter_1_20260513_122505.csv` | empty static room, nobody, no traffic |
| `c6_walking_person_iter1.csv` | `Escenario 2/movimiento_humano_iter_1_20260520_152220.csv` | one person walking across the line of sight |

- Source: https://github.com/HeliosSm/wifi-sensing-csi-network-traffic
  (code MIT); the data snapshot is Zenodo record 10.5281/zenodo.21148028
  (concept DOI 10.5281/zenodo.21148027), licence **CC BY 4.0**.
- Citation: Ramón E., Vinces M., González Martínez S. R., "Análisis
  Experimental del Impacto del Tráfico de Red en Mediciones CSI para Wi-Fi
  Sensing", IEEE Access, 2026.
- Setup (their README): two ESP32-C6; the transmitter injects raw 802.11
  frames at 50 Hz, the receiver captures CSI in promiscuous mode; 2.4 GHz
  channel 6, 20 MHz; 3000 rows per file.
- Row format, no header: `CSI_DATA,<rssi dBm>,128,<128 × int8>` — 64
  entries of `imaginary, real` (the ESP-IDF order). Entries 0–3, 32 and
  61–63 are always zero in every file: 56 live subcarriers in natural
  −32..+31 order (guards, DC, guards), i.e. `Layout::C6_HT20_NATURAL`.

The files are unmodified copies. A third and fourth file of the same
dataset (`iter_2` of each label) are held out of the repository and used
only to check that thresholds chosen here transfer; the ledger reports both.
