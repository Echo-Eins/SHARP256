use anyhow::{Context, Result};
use memmap2::MmapMut;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;

#[cfg(target_os = "windows")]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(target_os = "windows")]

use winapi::um::winbase::FILE_FLAG_RANDOM_ACCESS;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use libc;

/// Менеджер файлов с поддержкой sparse файлов
pub struct FileManager {
    file_path: PathBuf,
    file_size: u64,
    file: Arc<RwLock<File>>,
    mmap: Arc<RwLock<Option<MmapMut>>>,
}

impl FileManager {
    /// Создание нового файла для записи (получатель)
    pub fn create_for_receive(path: &Path, size: u64) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(true);
        
        // Включаем sparse файлы на Windows
        #[cfg(target_os = "windows")]
        {
            options.custom_flags(FILE_FLAG_RANDOM_ACCESS);
        }
        
        let file = options.open(path)
            .with_context(|| format!("Failed to create file: {:?}", path))?;
        
        // Устанавливаем размер файла для резервирования места
        file.set_len(size)
            .with_context(|| "Failed to set file size")?;
        
        // На Linux делаем файл sparse явно
        #[cfg(target_os = "linux")]
        {
            use libc::{fallocate, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_KEEP_SIZE};
            let fd = file.as_raw_fd();
            unsafe {
                fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, size as i64);
            }
        }
        
        Ok(Self {
            file_path: path.to_path_buf(),
            file_size: size,
            file: Arc::new(RwLock::new(file)),
            mmap: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Открытие существующего файла для чтения (отправитель)
    pub fn open_for_send(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("Failed to open file: {:?}", path))?;
        
        let metadata = file.metadata()?;
        let file_size = metadata.len();
        
        Ok(Self {
            file_path: path.to_path_buf(),
            file_size,
            file: Arc::new(RwLock::new(file)),
            mmap: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Инициализация memory-mapped доступа
    pub fn init_mmap(&self) -> Result<()> {
        let file = self.file.read();
        
        // Безопасное создание mmap
        let mmap = unsafe { MmapMut::map_mut(&file.try_clone()?) }
            .with_context(|| "Failed to create memory map")?;
        
        *self.mmap.write() = Some(mmap);
        Ok(())
    }
    /// Запись данных в определенную позицию файла
    pub fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        if offset + data.len() as u64 > self.file_size {
            anyhow::bail!("Write would exceed file size");
        }
        
        // Попытка записи через mmap
        if let Some(ref mut mmap) = *self.mmap.write() {
            let start = offset as usize;
            let end = start + data.len();
            mmap[start..end].copy_from_slice(data);
            return Ok(());
        }
        
        // Fallback на обычную запись
        let mut file = self.file.write();
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        file.flush()?;
        
        Ok(())
    }
    
    /// Асинхронная запись данных в определенную позицию файла
    pub async fn write_at_async(&self, offset: u64, data: &[u8]) -> Result<()> {
        // Для асинхронности используем tokio::task::spawn_blocking
        let file_size = self.file_size;
        let mmap = self.mmap.clone();
        let file = self.file.clone();
        let data = data.to_vec();
        
        tokio::task::spawn_blocking(move || {
            if offset + data.len() as u64 > file_size {
                return Err(anyhow::anyhow!("Write would exceed file size"));
            }
            
            // Попытка записи через mmap
            if let Some(ref mut mmap) = *mmap.write() {
                let start = offset as usize;
                let end = start + data.len();
                mmap[start..end].copy_from_slice(&data);
                return Ok(());
            }
            
            // Fallback на обычную запись
            let mut file = file.write();
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&data)?;
            file.flush()?;
            
            Ok(())
        }).await?
    }
    
    /// Чтение данных из определенной позиции файла
    pub fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if offset + length as u64 > self.file_size {
            anyhow::bail!("Read would exceed file size");
        }
        
        // Попытка чтения через mmap
        if let Some(ref mmap) = *self.mmap.read() {
            let start = offset as usize;
            let end = start + length;
            return Ok(mmap[start..end].to_vec());
        }
        
        // Fallback на обычное чтение
        let mut file = self.file.write();
        file.seek(SeekFrom::Start(offset))?;
        
        let mut buffer = vec![0u8; length];
        use std::io::Read;
        file.read_exact(&mut buffer)?;
        
        Ok(buffer)
    }
    
    /// Синхронизация данных на диск
    pub fn sync(&self) -> Result<()> {
        if let Some(ref mmap) = *self.mmap.read() {
            mmap.flush()?;
        }
        
        self.file.read().sync_all()?;
        Ok(())
    }
    
    /// Асинхронная синхронизация данных на диск
    pub async fn sync_async(&self) -> Result<()> {
        let mmap = self.mmap.clone();
        let file = self.file.clone();
        
        tokio::task::spawn_blocking(move || {
            if let Some(ref mmap) = *mmap.read() {
                mmap.flush()?;
            }
            
            file.read().sync_all()?;
            Ok(())
        }).await?
    }
    
    /// Получение размера файла
    pub fn size(&self) -> u64 {
        self.file_size
    }
    
    /// Получение пути к файлу
    pub fn path(&self) -> &Path {
        &self.file_path
    }
    
    /// Проверка доступного места на диске
    pub fn check_disk_space() -> Result<u64> {
        #[cfg(target_os = "windows")]
        {
            use winapi::um::fileapi::GetDiskFreeSpaceExW;
            use winapi::shared::ntdef::ULARGE_INTEGER;
            use std::ptr;
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            
            let path: Vec<u16> = OsStr::new(".")
                .encode_wide()
                .chain(Some(0))
                .collect();
            
            let mut free_bytes: u64 = 0;
            
            unsafe {
                if GetDiskFreeSpaceExW(
                    path.as_ptr(),
                    &mut free_bytes as *mut u64 as *mut ULARGE_INTEGER,
                    ptr::null_mut(),
                    ptr::null_mut()
                ) == 0 {
                    return Err(anyhow::anyhow!("Failed to get disk space"));
                }
            }
            
            Ok(free_bytes)
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            use std::fs;
            let stat = fs::metadata(".")?;
            
            // Для Unix систем используем statvfs
            #[cfg(target_os = "linux")]
            {
                use libc::{statvfs, c_char};
                use std::ffi::CString;
                
                let path = CString::new(".").unwrap();
                let mut stat: statvfs = unsafe { std::mem::zeroed() };
                
                unsafe {
                    if libc::statvfs(path.as_ptr() as *const c_char, &mut stat) != 0 {
                        return Err(anyhow::anyhow!("Failed to get disk space"));
                    }
                }
                
                Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
            }
            
            #[cfg(not(target_os = "linux"))]
            {
                // Для других платформ возвращаем условное значение
                Ok(1024 * 1024 * 1024 * 10) // 10 GB
            }
        }
    }
}

impl Drop for FileManager {
    fn drop(&mut self) {
        // Убеждаемся, что данные записаны на диск
        let _ = self.sync();
    }
}