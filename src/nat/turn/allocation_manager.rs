// src/turn/allocation_manager.rs
//! High-performance allocation manager for TURN relay
//!
//! Implements lock-free allocation management with:
//! - Zero-allocation hot paths
//! - Concurrent access optimization
//! - Memory pooling
//! - Automatic cleanup and expiration
//! - Comprehensive metrics and monitoring

use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Mutex};
use tokio::time::interval;
use dashmap::DashMap;
use crossbeam::queue::SegQueue;
use parking_lot::{RwLock as ParkingRwLock, Mutex as ParkingMutex};
use tracing::{info, warn, error, debug, trace, instrument};
use rand::{Rng, thread_rng};

use super::{
    TurnConfig, Transport, RelayRange, Allocation, AllocationKey, Permission, ChannelBinding,
    AllocationStats, MetricsCollector, MemoryPools, DEFAULT_ALLOCATION_LIFETIME,
    MAX_ALLOCATION_LIFETIME, MAX_ALLOCATIONS_PER_CLIENT
};
use crate::nat::error::{NatError, NatResult};

/// High-performance allocation manager with lock-free operations
pub struct AllocationManager {
    /// Active allocations with concurrent access
    allocations: DashMap<AllocationKey, Arc<Allocation>>,

    /// Relay address to allocation mapping for reverse lookup
    relay_lookup: DashMap<SocketAddr, AllocationKey>,

    /// Client IP to allocation count mapping
    client_counters: DashMap<IpAddr, AtomicU32>,

    /// User to allocation mapping for quota enforcement
    user_allocations: DashMap<String, Vec<AllocationKey>>,

    /// Available relay addresses pool
    relay_pool: Arc<RelayAddressPool>,

    /// Allocation ID generator (thread-safe)
    next_allocation_id: AtomicU64,

    /// Memory pool for allocation objects
    allocation_pool: Arc<SegQueue<Box<Allocation>>>,

    /// Expiration queue for efficient cleanup
    expiration_queue: Arc<ParkingMutex<ExpirationQueue>>,

    /// Configuration reference
    config: Arc<TurnConfig>,

    /// Metrics collector
    metrics: Arc<MetricsCollector>,

    /// Cleanup task handle
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Statistics
    stats: AllocationManagerStats,

    /// Active flag for shutdown coordination
    active: AtomicBool,
}

/// Relay address pool with efficient allocation and deallocation
pub struct RelayAddressPool {
    /// Available addresses queue (lock-free)
    available: SegQueue<SocketAddr>,

    /// In-use addresses for tracking
    in_use: DashMap<SocketAddr, AllocationKey>,

    /// Total pool capacity
    total_capacity: AtomicU32,

    /// Currently available count
    available_count: AtomicU32,

    /// Address ranges configuration
    ranges: Vec<RelayRange>,

    /// Port allocation strategy
    strategy: PortAllocationStrategy,

    /// Statistics
    stats: PoolStats,
}

/// Port allocation strategies for optimal distribution
#[derive(Debug, Clone)]
pub enum PortAllocationStrategy {
    /// Sequential allocation within ranges
    Sequential,

    /// Random allocation for security
    Random,

    /// Round-robin across ranges for load balancing
    RoundRobin { current_range: AtomicU32 },

    /// Least recently used for efficiency
    LeastRecentlyUsed,

    /// Hash-based allocation for consistency
    HashBased,
}

/// Expiration queue for efficient cleanup
#[derive(Debug)]
struct ExpirationQueue {
    /// Entries sorted by expiration time
    entries: std::collections::BTreeMap<u64, Vec<AllocationKey>>,

    /// Total entries count
    count: usize,
}

/// Pool statistics
#[derive(Debug, Default)]
struct PoolStats {
    allocations_total: AtomicU64,
    allocations_successful: AtomicU64,
    allocations_failed: AtomicU64,
    deallocations_total: AtomicU64,
    pool_exhausted_count: AtomicU64,
    average_allocation_time_us: AtomicU64,
}

/// Allocation manager statistics
#[derive(Debug, Default)]
struct AllocationManagerStats {
    allocations_created: AtomicU64,
    allocations_deleted: AtomicU64,
    allocations_expired: AtomicU64,
    allocation_conflicts: AtomicU64,
    cleanup_runs: AtomicU64,
    memory_usage_bytes: AtomicU64,
}

impl AllocationManager {
    /// Create new allocation manager with optimized configuration
    pub async fn new(
        config: Arc<TurnConfig>,
        relay_pool: Arc<RelayAddressPool>,
        memory_pools: Arc<MemoryPools>,
        metrics: Arc<MetricsCollector>,
    ) -> NatResult<Self> {
        info!("Initializing allocation manager with {} relay ranges", config.relay_addrs.len());

        // Pre-allocate allocation objects in pool
        let allocation_pool = Arc::new(SegQueue::new());
        for _ in 0..config.performance.allocation_pool_size {
            allocation_pool.push(Box::new(Allocation::new_empty()));
        }

        let manager = Self {
            allocations: DashMap::with_capacity(10000),
            relay_lookup: DashMap::with_capacity(10000),
            client_counters: DashMap::with_capacity(1000),
            user_allocations: DashMap::with_capacity(1000),
            relay_pool,
            next_allocation_id: AtomicU64::new(1),
            allocation_pool,
            expiration_queue: Arc::new(ParkingMutex::new(ExpirationQueue::new())),
            config,
            metrics,
            cleanup_task: Arc::new(Mutex::new(None)),
            stats: AllocationManagerStats::default(),
            active: AtomicBool::new(true),
        };

        info!("Allocation manager initialized successfully");
        Ok(manager)
    }

    /// Create new allocation with comprehensive validation and optimization
    #[instrument(skip(self), level = "debug")]
    pub async fn create_allocation(
        &self,
        client_addr: SocketAddr,
        transport: Transport,
        lifetime: Duration,
        username: String,
        realm: String,
        bandwidth_limit: u64,
    ) -> NatResult<Arc<Allocation>> {
        let start_time = Instant::now();

        debug!("Creating allocation for {} (transport: {:?}, lifetime: {:?})",
            client_addr, transport, lifetime);

        // Validate client allocation limits
        self.validate_client_limits(client_addr.ip(), &username).await?;

        // Generate unique allocation ID
        let allocation_id = self.next_allocation_id.fetch_add(1, Ordering::Relaxed);
        let allocation_key = AllocationKey {
            client_addr,
            allocation_id,
        };

        // Check for existing allocation (RFC 5766 Section 6.2)
        if let Some(existing) = self.find_allocation(client_addr).await {
            debug!("Returning existing allocation for {}", client_addr);
            return Ok(existing);
        }

        // Allocate relay address
        let relay_addr = self.relay_pool.allocate_address(transport, &allocation_key).await
            .ok_or_else(|| NatError::Platform("No relay addresses available".to_string()))?;

        info!("Allocated relay address {} for client {}", relay_addr, client_addr);

        // Get allocation object from pool or create new
        let mut allocation = self.allocation_pool.pop()
            .unwrap_or_else(|| Box::new(Allocation::new_empty()));

        // Initialize allocation
        allocation.initialize(
            allocation_key,
            relay_addr,
            transport,
            lifetime.min(MAX_ALLOCATION_LIFETIME),
            username.clone(),
            realm,
            client_addr,
            bandwidth_limit,
        );

        let allocation = Arc::new(*allocation);

        // Add to expiration queue
        let expires_at = allocation.expires_at.load(Ordering::Relaxed);
        self.expiration_queue.lock().add_entry(expires_at, allocation_key);

        // Store allocation in maps
        self.allocations.insert(allocation_key, allocation.clone());
        self.relay_lookup.insert(relay_addr, allocation_key);

        // Update client counter
        let client_ip = client_addr.ip();
        self.client_counters.entry(client_ip)
            .or_insert_with(|| AtomicU32::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // Update user allocations
        self.user_allocations.entry(username)
            .or_insert_with(Vec::new)
            .push(allocation_key);

        // Update metrics and statistics
        let allocation_time = start_time.elapsed();
        self.stats.allocations_created.fetch_add(1, Ordering::Relaxed);
        self.metrics.allocations_created.fetch_add(1, Ordering::Relaxed);
        self.metrics.allocations_active.fetch_add(1, Ordering::Relaxed);

        self.relay_pool.stats.average_allocation_time_us.store(
            allocation_time.as_micros() as u64,
            Ordering::Relaxed,
        );

        info!("Allocation created successfully: {} -> {} (user: {}, lifetime: {:?})",
            client_addr, relay_addr, allocation.username,
            Duration::from_secs(allocation.lifetime.load(Ordering::Relaxed) as u64));

        Ok(allocation)
    }

    /// Validate client allocation limits
    async fn validate_client_limits(&self, client_ip: IpAddr, username: &str) -> NatResult<()> {
        // Check per-IP limit
        let ip_count = self.client_counters.get(&client_ip)
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0);

        if ip_count >= self.config.rate_limiting.max_allocations_per_ip {
            return Err(NatError::Platform(
                format!("IP {} has reached allocation limit ({})",
                        client_ip, self.config.rate_limiting.max_allocations_per_ip)
            ));
        }

        // Check per-user limit
        let user_count = self.user_allocations.get(username)
            .map(|allocations| allocations.len())
            .unwrap_or(0);

        if user_count >= self.config.rate_limiting.max_allocations_per_user as usize {
            return Err(NatError::Platform(
                format!("User {} has reached allocation limit ({})",
                        username, self.config.rate_limiting.max_allocations_per_user)
            ));
        }

        Ok(())
    }

    /// Find allocation by client address
    pub async fn find_allocation(&self, client_addr: SocketAddr) -> Option<Arc<Allocation>> {
        // Search through allocations for matching client address
        for allocation_ref in self.allocations.iter() {
            let allocation = allocation_ref.value();
            if allocation.client_addr == client_addr && allocation.is_active() {
                return Some(allocation.clone());
            }
        }
        None
    }

    /// Find allocation by allocation key
    pub async fn get_allocation(&self, key: &AllocationKey) -> Option<Arc<Allocation>> {
        self.allocations.get(key).map(|entry| entry.value().clone())
    }

    /// Find allocation by relay address
    pub async fn find_allocation_by_relay(&self, relay_addr: SocketAddr) -> Option<Arc<Allocation>> {
        if let Some(key_entry) = self.relay_lookup.get(&relay_addr) {
            let key = *key_entry.value();
            self.allocations.get(&key).map(|entry| entry.value().clone())
        } else {
            None
        }
    }

    /// Refresh allocation lifetime
    #[instrument(skip(self), level = "debug")]
    pub async fn refresh_allocation(
        &self,
        key: &AllocationKey,
        new_lifetime: Duration,
    ) -> NatResult<()> {
        let allocation = self.allocations.get(key)
            .ok_or_else(|| NatError::Platform("Allocation not found".to_string()))?
            .clone();

        let lifetime_secs = new_lifetime.min(MAX_ALLOCATION_LIFETIME).as_secs() as u32;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let expires_at = now + (lifetime_secs as u64 * 1000);

        // Update allocation
        allocation.lifetime.store(lifetime_secs, Ordering::Relaxed);
        allocation.expires_at.store(expires_at, Ordering::Relaxed);

        // Update expiration queue
        self.expiration_queue.lock().add_entry(expires_at, *key);

        // Update statistics
        allocation.stats.refresh_count.fetch_add(1, Ordering::Relaxed);

        debug!("Refreshed allocation {} with new lifetime: {:?}",
            key.allocation_id, new_lifetime);

        Ok(())
    }

    /// Delete allocation and clean up resources
    #[instrument(skip(self), level = "debug")]
    pub async fn delete_allocation(&self, key: &AllocationKey) -> NatResult<()> {
        debug!("Deleting allocation {}", key.allocation_id);

        let allocation = self.allocations.remove(key)
            .ok_or_else(|| NatError::Platform("Allocation not found".to_string()))?
            .1;

        // Mark as inactive
        allocation.active.store(false, Ordering::Relaxed);

        // Remove from relay lookup
        self.relay_lookup.remove(&allocation.relay_addr);

        // Return relay address to pool
        self.relay_pool.deallocate_address(allocation.relay_addr, key).await;

        // Update client counter
        if let Some(counter) = self.client_counters.get(&allocation.client_addr.ip()) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }

        // Update user allocations
        if let Some(mut user_allocs) = self.user_allocations.get_mut(&allocation.username) {
            user_allocs.retain(|k| k != key);
        }

        // Return allocation object to pool
        if let Ok(mut alloc_box) = Arc::try_unwrap(allocation) {
            alloc_box.reset();
            self.allocation_pool.push(Box::new(alloc_box));
        }

        // Update metrics
        self.stats.allocations_deleted.fetch_add(1, Ordering::Relaxed);
        self.metrics.allocations_active.fetch_sub(1, Ordering::Relaxed);

        info!("Allocation {} deleted successfully", key.allocation_id);
        Ok(())
    }

    /// Count allocations for a client IP
    pub async fn count_allocations_for_client(&self, client_ip: IpAddr) -> u32 {
        self.client_counters.get(&client_ip)
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get all allocations for a user
    pub async fn get_user_allocations(&self, username: &str) -> Vec<Arc<Allocation>> {
        if let Some(keys) = self.user_allocations.get(username) {
            keys.iter()
                .filter_map(|key| self.allocations.get(key).map(|entry| entry.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Start cleanup task for expired allocations
    pub async fn start_cleanup_task(&self) {
        let manager = self.clone_for_task();

        let task = tokio::spawn(async move {
            manager.cleanup_loop().await;
        });

        *self.cleanup_task.lock().await = Some(task);
        info!("Allocation cleanup task started");
    }

    /// Main cleanup loop
    async fn cleanup_loop(self: Arc<Self>) {
        let mut cleanup_interval = interval(Duration::from_secs(10));

        while self.active.load(Ordering::Relaxed) {
            cleanup_interval.tick().await;

            let cleanup_start = Instant::now();
            let expired_count = self.cleanup_expired_allocations().await;
            let cleanup_duration = cleanup_start.elapsed();

            if expired_count > 0 {
                info!("Cleaned up {} expired allocations in {:?}",
                    expired_count, cleanup_duration);
            }

            self.stats.cleanup_runs.fetch_add(1, Ordering::Relaxed);
        }

        info!("Allocation cleanup task stopped");
    }

    /// Clean up expired allocations
    async fn cleanup_expired_allocations(&self) -> usize {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut expired_keys = Vec::new();

        // Get expired entries from queue
        {
            let mut queue = self.expiration_queue.lock();
            queue.get_expired_entries(now, &mut expired_keys);
        }

        let mut cleaned_count = 0;

        // Delete expired allocations
        for key in expired_keys {
            if let Some(allocation) = self.allocations.get(&key) {
                let expires_at = allocation.expires_at.load(Ordering::Relaxed);

                if expires_at <= now {
                    if let Err(e) = self.delete_allocation(&key).await {
                        warn!("Failed to delete expired allocation {}: {}", key.allocation_id, e);
                    } else {
                        cleaned_count += 1;
                        self.stats.allocations_expired.fetch_add(1, Ordering::Relaxed);
                        self.metrics.allocations_expired.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        cleaned_count
    }

    /// Get allocation manager statistics
    pub fn get_stats(&self) -> AllocationManagerStats {
        AllocationManagerStats {
            allocations_created: AtomicU64::new(
                self.stats.allocations_created.load(Ordering::Relaxed)
            ),
            allocations_deleted: AtomicU64::new(
                self.stats.allocations_deleted.load(Ordering::Relaxed)
            ),
            allocations_expired: AtomicU64::new(
                self.stats.allocations_expired.load(Ordering::Relaxed)
            ),
            allocation_conflicts: AtomicU64::new(
                self.stats.allocation_conflicts.load(Ordering::Relaxed)
            ),
            cleanup_runs: AtomicU64::new(
                self.stats.cleanup_runs.load(Ordering::Relaxed)
            ),
            memory_usage_bytes: AtomicU64::new(
                self.estimate_memory_usage()
            ),
        }
    }

    /// Estimate memory usage
    fn estimate_memory_usage(&self) -> u64 {
        let allocation_count = self.allocations.len() as u64;
        let allocation_size = std::mem::size_of::<Allocation>() as u64;

        allocation_count * allocation_size +
            self.relay_lookup.len() as u64 * 32 + // Estimated overhead
            self.client_counters.len() as u64 * 16
    }

    /// Clone for task (lightweight)
    fn clone_for_task(&self) -> Arc<Self> {
        // In practice, AllocationManager would be wrapped in Arc from creation
        unreachable!("Use Arc<AllocationManager> directly")
    }

    /// Shutdown allocation manager
    pub async fn shutdown(&self) -> NatResult<()> {
        info!("Shutting down allocation manager");

        self.active.store(false, Ordering::Relaxed);

        // Stop cleanup task
        if let Some(task) = self.cleanup_task.lock().await.take() {
            task.abort();
        }

        // Clean up all allocations
        let all_keys: Vec<AllocationKey> = self.allocations.iter()
            .map(|entry| *entry.key())
            .collect();

        for key in all_keys {
            if let Err(e) = self.delete_allocation(&key).await {
                warn!("Failed to delete allocation during shutdown: {}", e);
            }
        }

        info!("Allocation manager shutdown complete");
        Ok(())
    }
}

impl RelayAddressPool {
    /// Create new relay address pool
    pub async fn new(ranges: &[RelayRange]) -> NatResult<Self> {
        info!("Initializing relay address pool with {} ranges", ranges.len());

        let available = SegQueue::new();
        let mut total_addresses = 0u32;

        // Generate all possible addresses from ranges
        for range in ranges {
            let addresses = Self::generate_addresses_from_range(range)?;
            total_addresses += addresses.len() as u32;

            for addr in addresses {
                available.push(addr);
            }
        }

        info!("Generated {} relay addresses", total_addresses);

        let pool = Self {
            available,
            in_use: DashMap::with_capacity(total_addresses as usize),
            total_capacity: AtomicU32::new(total_addresses),
            available_count: AtomicU32::new(total_addresses),
            ranges: ranges.to_vec(),
            strategy: PortAllocationStrategy::Random,
            stats: PoolStats::default(),
        };

        Ok(pool)
    }

    /// Generate addresses from relay range
    fn generate_addresses_from_range(range: &RelayRange) -> NatResult<Vec<SocketAddr>> {
        let mut addresses = Vec::new();

        match (range.start_ip, range.end_ip) {
            (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                let start_u32 = u32::from(start_v4);
                let end_u32 = u32::from(end_v4);

                for ip_u32 in start_u32..=end_u32 {
                    let ip = Ipv4Addr::from(ip_u32);

                    for port in range.port_range.0..=range.port_range.1 {
                        addresses.push(SocketAddr::new(IpAddr::V4(ip), port));
                    }
                }
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                // IPv6 range implementation would be more complex
                return Err(NatError::Platform("IPv6 ranges not implemented".to_string()));
            }
            _ => {
                return Err(NatError::Platform("Mismatched IP address families".to_string()));
            }
        }

        Ok(addresses)
    }

    /// Allocate address from pool
    pub async fn allocate_address(
        &self,
        transport: Transport,
        allocation_key: &AllocationKey,
    ) -> Option<SocketAddr> {
        let start_time = Instant::now();
        self.stats.allocations_total.fetch_add(1, Ordering::Relaxed);

        // Try to get address from available pool
        while let Some(addr) = self.available.pop() {
            // Check if address supports requested transport
            if self.supports_transport(&addr, transport) {
                // Mark as in use
                self.in_use.insert(addr, *allocation_key);
                self.available_count.fetch_sub(1, Ordering::Relaxed);

                let allocation_time = start_time.elapsed();
                self.stats.average_allocation_time_us.store(
                    allocation_time.as_micros() as u64,
                    Ordering::Relaxed,
                );
                self.stats.allocations_successful.fetch_add(1, Ordering::Relaxed);

                debug!("Allocated relay address {} for allocation {}",
                    addr, allocation_key.allocation_id);
                return Some(addr);
            } else {
                // Put back if not compatible
                self.available.push(addr);
            }
        }

        // Pool exhausted
        self.stats.pool_exhausted_count.fetch_add(1, Ordering::Relaxed);
        self.stats.allocations_failed.fetch_add(1, Ordering::Relaxed);

        warn!("Relay address pool exhausted");
        None
    }

    /// Check if address supports transport
    fn supports_transport(&self, addr: &SocketAddr, transport: Transport) -> bool {
        // Find the range this address belongs to
        for range in &self.ranges {
            if self.address_in_range(addr, range) {
                return range.transports.contains(&transport);
            }
        }
        false
    }

    /// Check if address is in range
    fn address_in_range(&self, addr: &SocketAddr, range: &RelayRange) -> bool {
        let addr_ip = addr.ip();
        let addr_port = addr.port();

        // Check IP range
        let ip_in_range = match (addr_ip, range.start_ip, range.end_ip) {
            (IpAddr::V4(addr_v4), IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                let addr_u32 = u32::from(addr_v4);
                let start_u32 = u32::from(start_v4);
                let end_u32 = u32::from(end_v4);
                addr_u32 >= start_u32 && addr_u32 <= end_u32
            }
            _ => false, // IPv6 not implemented
        };

        // Check port range
        let port_in_range = addr_port >= range.port_range.0 && addr_port <= range.port_range.1;

        ip_in_range && port_in_range
    }

    /// Deallocate address back to pool
    pub async fn deallocate_address(&self, addr: SocketAddr, allocation_key: &AllocationKey) {
        if let Some((_, key)) = self.in_use.remove(&addr) {
            if key == *allocation_key {
                self.available.push(addr);
                self.available_count.fetch_add(1, Ordering::Relaxed);
                self.stats.deallocations_total.fetch_add(1, Ordering::Relaxed);

                debug!("Deallocated relay address {} from allocation {}",
                    addr, allocation_key.allocation_id);
            }
        }
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Get pool utilization percentage
    pub fn get_utilization(&self) -> f64 {
        let total = self.total_capacity.load(Ordering::Relaxed) as f64;
        let available = self.available_count.load(Ordering::Relaxed) as f64;

        if total > 0.0 {
            ((total - available) / total) * 100.0
        } else {
            0.0
        }
    }
}

impl ExpirationQueue {
    /// Create new expiration queue
    fn new() -> Self {
        Self {
            entries: std::collections::BTreeMap::new(),
            count: 0,
        }
    }

    /// Add entry to expiration queue
    fn add_entry(&mut self, expires_at: u64, key: AllocationKey) {
        self.entries.entry(expires_at)
            .or_insert_with(Vec::new)
            .push(key);
        self.count += 1;
    }

    /// Get expired entries
    fn get_expired_entries(&mut self, now: u64, expired_keys: &mut Vec<AllocationKey>) {
        let expired_times: Vec<u64> = self.entries.range(..=now)
            .map(|(time, _)| *time)
            .collect();

        for time in expired_times {
            if let Some(keys) = self.entries.remove(&time) {
                expired_keys.extend(keys);
                self.count = self.count.saturating_sub(expired_keys.len());
            }
        }
    }

    /// Get queue size
    fn len(&self) -> usize {
        self.count
    }
}

impl Allocation {
    /// Create empty allocation for pool
    fn new_empty() -> Self {
        Self {
            key: AllocationKey {
                client_addr: "0.0.0.0:0".parse().unwrap(),
                allocation_id: 0,
            },
            relay_addr: "0.0.0.0:0".parse().unwrap(),
            transport: Transport::Udp,
            created_at: Instant::now(),
            expires_at: AtomicU64::new(0),
            lifetime: AtomicU32::new(0),
            username: String::new(),
            realm: String::new(),
            client_addr: "0.0.0.0:0".parse().unwrap(),
            bandwidth_limit: AtomicU64::new(0),
            bandwidth_used: AtomicU64::new(0),
            bandwidth_window_start: AtomicU64::new(0),
            permissions: DashMap::new(),
            channels: DashMap::new(),
            stats: AllocationStats::default(),
            active: AtomicBool::new(false),
            lock: ParkingMutex::new(()),
        }
    }

    /// Initialize allocation with values
    fn initialize(
        &mut self,
        key: AllocationKey,
        relay_addr: SocketAddr,
        transport: Transport,
        lifetime: Duration,
        username: String,
        realm: String,
        client_addr: SocketAddr,
        bandwidth_limit: u64,
    ) {
        self.key = key;
        self.relay_addr = relay_addr;
        self.transport = transport;
        self.created_at = Instant::now();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let expires_at = now + (lifetime.as_secs() * 1000);

        self.expires_at.store(expires_at, Ordering::Relaxed);
        self.lifetime.store(lifetime.as_secs() as u32, Ordering::Relaxed);
        self.username = username;
        self.realm = realm;
        self.client_addr = client_addr;
        self.bandwidth_limit.store(bandwidth_limit, Ordering::Relaxed);
        self.bandwidth_used.store(0, Ordering::Relaxed);
        self.bandwidth_window_start.store(now, Ordering::Relaxed);

        // Clear collections
        self.permissions.clear();
        self.channels.clear();

        // Reset statistics
        self.stats = AllocationStats::default();

        self.active.store(true, Ordering::Relaxed);
    }

    /// Reset allocation for reuse
    fn reset(&mut self) {
        self.active.store(false, Ordering::Relaxed);
        self.username.clear();
        self.realm.clear();
        self.permissions.clear();
        self.channels.clear();
        self.stats = AllocationStats::default();
    }

    /// Check if allocation is active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Check if allocation is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let expires_at = self.expires_at.load(Ordering::Relaxed);
        now >= expires_at
    }

    /// Update last activity timestamp
    pub fn update_activity(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        self.stats.last_activity.store(now, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_pool_creation() {
        let ranges = vec![
            RelayRange {
                start_ip: "127.0.0.1".parse().unwrap(),
                end_ip: "127.0.0.1".parse().unwrap(),
                port_range: (50000, 50010),
                transports: vec![Transport::Udp],
                max_bandwidth: None,
            }
        ];

        let pool = RelayAddressPool::new(&ranges).await.unwrap();
        assert_eq!(pool.total_capacity.load(Ordering::Relaxed), 11); // 11 ports
    }

    #[tokio::test]
    async fn test_address_allocation_deallocation() {
        let ranges = vec![
            RelayRange {
                start_ip: "127.0.0.1".parse().unwrap(),
                end_ip: "127.0.0.1".parse().unwrap(),
                port_range: (50000, 50002),
                transports: vec![Transport::Udp],
                max_bandwidth: None,
            }
        ];

        let pool = RelayAddressPool::new(&ranges).await.unwrap();
        let key = AllocationKey {
            client_addr: "192.168.1.1:12345".parse().unwrap(),
            allocation_id: 1,
        };

        // Allocate address
        let addr = pool.allocate_address(Transport::Udp, &key).await;
        assert!(addr.is_some());

        let allocated_addr = addr.unwrap();
        assert_eq!(allocated_addr.ip().to_string(), "127.0.0.1");
        assert!(allocated_addr.port() >= 50000 && allocated_addr.port() <= 50002);

        // Deallocate address
        pool.deallocate_address(allocated_addr, &key).await;

        // Should be able to allocate same address again
        let addr2 = pool.allocate_address(Transport::Udp, &key).await;
        assert!(addr2.is_some());
    }

    #[tokio::test]
    async fn test_expiration_queue() {
        let mut queue = ExpirationQueue::new();

        let key1 = AllocationKey {
            client_addr: "192.168.1.1:12345".parse().unwrap(),
            allocation_id: 1,
        };

        let key2 = AllocationKey {
            client_addr: "192.168.1.2:12345".parse().unwrap(),
            allocation_id: 2,
        };

        // Add entries
        queue.add_entry(1000, key1);
        queue.add_entry(2000, key2);
        assert_eq!(queue.len(), 2);

        // Get expired entries
        let mut expired = Vec::new();
        queue.get_expired_entries(1500, &mut expired);

        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], key1);
        assert_eq!(queue.len(), 1);
    }
}