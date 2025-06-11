use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Instant;
use crate::protocol::ack::SaoParams;
use crate::protocol::constants::*;

/// Метрики для одной партии
#[derive(Debug, Clone)]
pub struct BatchMetrics {
    pub batch_number: u32,
    pub send_time: Instant,
    pub ack_time: Option<Instant>,
    pub packets_sent: u16,
    pub packets_lost: u16,
    pub bytes_sent: u64,
}

impl BatchMetrics {
    pub fn new(batch_number: u32, packets_sent: u16, bytes_sent: u64) -> Self {
        Self {
            batch_number,
            send_time: Instant::now(),
            ack_time: None,
            packets_sent,
            packets_lost: 0,
            bytes_sent,
        }
    }

    pub fn complete(&mut self, packets_lost: u16) {
        self.ack_time = Some(Instant::now());
        self.packets_lost = packets_lost;
    }

    pub fn rtt_ms(&self) -> Option<f64> {
        self.ack_time.map(|ack| {
            (ack - self.send_time).as_secs_f64() * 1000.0
        })
    }

    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        }
    }
}

/// Система автоматической оптимизации
pub struct SaoSystem {
    params: Arc<RwLock<SaoParams>>,
    metrics_history: Arc<RwLock<Vec<BatchMetrics>>>,
    last_update_batch: Arc<RwLock<u32>>,
    start_time: Instant,
}

impl SaoSystem {
    pub fn new() -> Self {
        Self {
            params: Arc::new(RwLock::new(SaoParams::default())),
            metrics_history: Arc::new(RwLock::new(Vec::with_capacity(SAO_RECALC_INTERVAL as usize))),
            last_update_batch: Arc::new(RwLock::new(0)),
            start_time: Instant::now(),
        }
    }

    /// Добавление метрик новой партии
    pub fn add_batch_metrics(&self, metrics: BatchMetrics) {
        let mut history = self.metrics_history.write();
        history.push(metrics);

        // Храним только последние SAO_RECALC_INTERVAL записей
        if history.len() > SAO_RECALC_INTERVAL as usize {
            history.remove(0);
        }
    }

    /// Обновление параметров на основе полученного ACK
    pub fn update_from_ack(&self, control_ack: &crate::protocol::ack::ControlAck) {
        let mut params = self.params.write();
        params.avg_rtt_ms = control_ack.ping_ms;

        // Обновляем метрики для партий в диапазоне ACK
        let mut history = self.metrics_history.write();
        for metric in history.iter_mut() {
            if metric.batch_number >= control_ack.batch_range_start
                && metric.batch_number <= control_ack.batch_range_end {

                let lost_in_batch = control_ack.lost_packets.iter()
                    .filter(|p| p.batch_number == metric.batch_number)
                    .count() as u16;

                metric.complete(lost_in_batch);
            }
        }
    }

    /// Пересчет оптимальных параметров
    pub fn recalculate(&self, current_batch: u32) -> bool {
        let mut last_update = self.last_update_batch.write();

        // Проверяем, нужен ли пересчет
        if current_batch - *last_update < SAO_RECALC_INTERVAL {
            return false;
        }

        *last_update = current_batch;
        drop(last_update);

        let history = self.metrics_history.read();
        if history.len() < 10 {
            return false; // Недостаточно данных
        }

        // Рассчитываем средние метрики
        let (total_rtt, rtt_count, total_loss, total_packets) = history.iter()
            .fold((0.0, 0usize, 0u16, 0u16), |(rtt_sum, rtt_cnt, loss, packets), metric| {
                let new_rtt = metric.rtt_ms().map_or((rtt_sum, rtt_cnt), |rtt| (rtt_sum + rtt, rtt_cnt + 1));
                (new_rtt.0, new_rtt.1, loss + metric.packets_lost, packets + metric.packets_sent)
            });

        let avg_rtt = if rtt_count > 0 { total_rtt / rtt_count as f64 } else { 0.0 };
        let loss_rate = if total_packets > 0 { total_loss as f64 / total_packets as f64 } else { 0.0 };

        // Рассчитываем пропускную способность
        let elapsed_secs = self.start_time.elapsed().as_secs_f64();
        let total_bytes: u64 = history.iter().map(|m| m.bytes_sent).sum();
        let bandwidth_mbps = (total_bytes as f64 * 8.0) / (elapsed_secs * 1_000_000.0);
        let bandwidth_utilization = (bandwidth_mbps / 1000.0).min(1.0); // Предполагаем 1 Гбит/с максимум

        // Рассчитываем score по формуле
        let score = (1.0 - loss_rate) * bandwidth_utilization * (1.0 / (1.0 + avg_rtt / 100.0));

        let mut params = self.params.write();
        params.avg_rtt_ms = avg_rtt;
        params.loss_rate = loss_rate;
        params.bandwidth_utilization = bandwidth_utilization;
        params.current_score = score;

        // Корректируем размер партии
        let old_batch_size = params.batch_size;
        if score > SAO_SCORE_INCREASE_THRESHOLD && params.batch_size < MAX_BATCH_SIZE {
            params.batch_size = (params.batch_size + SAO_BATCH_SIZE_STEP).min(MAX_BATCH_SIZE);
            params.optimized_mode = true;
        } else if score < SAO_SCORE_DECREASE_THRESHOLD && params.batch_size > MIN_BATCH_SIZE {
            params.batch_size = (params.batch_size.saturating_sub(SAO_BATCH_SIZE_STEP)).max(MIN_BATCH_SIZE);
            params.optimized_mode = params.batch_size > INITIAL_BATCH_SIZE;
        }

        tracing::info!(
            "SAO recalculated: score={:.3}, rtt={:.1}ms, loss={:.2}%, bandwidth={:.1}%, batch_size: {} -> {}",
            score, avg_rtt, loss_rate * 100.0, bandwidth_utilization * 100.0,
            old_batch_size, params.batch_size
        );

        old_batch_size != params.batch_size
    }

    /// Получение текущих параметров
    pub fn get_params(&self) -> SaoParams {
        *self.params.read()
    }

    /// Установка параметров (для восстановления после разрыва)
    pub fn set_params(&self, params: SaoParams) {
        *self.params.write() = params;
    }

    /// Проверка, работаем ли в оптимизированном режиме
    pub fn is_optimized(&self) -> bool {
        self.params.read().optimized_mode
    }

    /// Получение текущего размера партии
    pub fn batch_size(&self) -> u16 {
        self.params.read().batch_size
    }
}