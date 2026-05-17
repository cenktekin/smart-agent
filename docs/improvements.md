# Smart-Agent İyileştirme Önerileri

> Tarih: 2026-04-07 21:00
> Güncelleme: 2026-04-08 13:15 — systemd service kuruldu, monitoring başladı
> Öncelik sıralaması ile not edildi.

## 1. Zaman-Bazlı Baseline'lar (Yüksek Öncelik)
- Hafta içi / hafta sonu ayrı profiller
- Mesai saatleri (09-17) / gece (00-06) / akşam (18-00) dilimleri
- "Pazartesi 10:00'da bu CPU normal, Cumartesi 10:00'da anormal"
- baseline.json → baseline-weekday-09-17.json, baseline-weekend.json vb.
- Zaman etiketi: `{"day_of_week": 1, "hour_bucket": 10}`

## 2. Süreç Grupları & Service Mapping (Yüksek Öncelik)
- systemd unit bilgisi: `journalctl -u <service>` otomatik eşleştirme
- Browser process'lerini grupla (chrome, firefox → "browser" kategorisi)
- Kernel thread'leri ayrı tut / ignore (kworker sürekli dinamik)
- `/proc/<pid>/cgroup` → container process tespiti
- Process tree: parent-child grouping (PID tek başına anlamsız)

## 3. Adaptive Scan Interval (Orta Öncelik)
- Normal durumda: 5 dakikada bir scan
- Anomali tespitinde: 30 saniyeye düş (burst mode, 10 dk)
- 10 dk stabil → tekrar normale dön
- `scan_interval = base_interval / (risk_score * 10)` formülü

## 4. Trend Analizi (Orta Öncelik)
- Memory leak tespiti: RAM kullanımı günler içinde artıyor mu?
- Process count drift: Süreç sayısı yavaş yavaş artıyor mu?
- `scan-log.jsonl` üzerinde moving average (7d, 30d)
- Linear regression slope > threshold → "potential memory leak" warning

## 5. Whitelist / Allowlist (Orta Öncelik)
- `~/.config/smart-agent/ignore.json` → kalıcı ignore list
- `smart-agent ignore add <process_name>` / `smart-agent ignore list` / `smart-agent ignore rm <name>`
- Docker/Podman container'larını ayrı değerlendir
- Regex desteği: `kworker/.*`, `chrome_crashpad_handler`

## 6. Log Correlation (Düşük Öncelik)
- Anomali tespitinde otomatik `journalctl --since "5 min ago" --priority warning`
- `dmesg` OOM killer, segfault, hardware error kontrolü
- Network: `ss -tlnp` + `conntrack -L` dump
- Sonuç: scan-log.jsonl'e `related_logs` alanı ekle

## 7. SQLite Migration (Düşük Öncelik)
- JSONL → SQLite (daha iyi sorgulama, aggregasyon, index)
- Tablolar: `snapshots`, `scans`, `baselines`, `ignore_list`
- `SELECT AVG(risk_score) FROM scans WHERE hour BETWEEN 9 AND 17`
- Migration: mevcut JSONL → SQLite import scripti
- JSONL'den vazgeçme — backward compat ile birlikte

## 8. Rolling Baseline Update (Düşük Öncelik)
- Haftalık baseline refresh (eski veri ağırlıkça düşer)
- Exponential moving average ile snapshot ağırlıkları
- `smart-agent recalibrate` → mevcut scan-log'dan yeni baseline
- Baseline drift detection: baseline değişmişse log'la

## 9. Health Dashboard (Düşük Öncelik)
- `smart-agent dashboard` → live terminal UI (Rich live display)
- Son 24 saat risk skor grafiği (ASCII chart veya Rich sparkline)
- Top process offenders, port changes
- `smart-agent dashboard --watch 10` (her 10 sn refresh)

## Öncelik Sıralaması (Uygulama)
1. ~~**#2 Kernel thread fix**~~ ✅ DONE — `_KERNEL_THREAD_PATTERNS` (30+ regex), `_HIGH_MEMORY_TOLERANCE` per-process
2. ~~**#1 Time-based baseline**~~ ✅ DONE — v2.1.0 (Weekend/Weekday)
3. ~~**#5 Whitelist**~~ ✅ DONE — v2.1.1/v2.1.2 (Process + Port ignore)
4. ~~**#3 Adaptive scan**~~ ✅ DONE — v2.1.0 (Burst Mode)
5. **#4 Trend analysis** — Uzun vadeli tespitler (MED)
6. **#6 Log correlation** — Investigation kolaylığı (LOW)
7. **#7 SQLite** — Altyapı değişikliği (LOW)
8. **#8 Rolling baseline** — Maintenance reduction (LOW)
9. **#9 Dashboard** — Nice-to-have UI (LOW)
