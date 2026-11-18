import type { ScanResult } from '@/scanner/types';

export interface StoredScanReport {
  id: string;
  scannedAt: string;
  result: ScanResult;
}

const DB_NAME = 'static_vuln_scanner_db';
const DB_VERSION = 1;
const STORE_NAME = 'scan_reports';
const MAX_STORED_REPORTS = 50;

function isIndexedDbAvailable(): boolean {
  return typeof window !== 'undefined' && 'indexedDB' in window;
}

function generateReportId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `scan-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!isIndexedDbAvailable()) {
      reject(new Error('IndexedDB is unavailable in this environment.'));
      return;
    }

    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        store.createIndex('by_scannedAt', 'scannedAt', { unique: false });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error('Failed to open IndexedDB database.'));
  });
}

export async function listScanReports(): Promise<StoredScanReport[]> {
  if (!isIndexedDbAvailable()) return [];

  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.getAll();

    req.onsuccess = () => {
      const records = (req.result as StoredScanReport[]) ?? [];
      records.sort((a, b) => b.scannedAt.localeCompare(a.scannedAt));
      resolve(records);
    };
    req.onerror = () => reject(req.error ?? new Error('Failed to load scan history.'));
    tx.oncomplete = () => db.close();
  });
}

export async function saveScanReport(result: ScanResult): Promise<StoredScanReport> {
  const entry: StoredScanReport = {
    id: generateReportId(),
    scannedAt: result.scannedAt || new Date().toISOString(),
    result,
  };

  if (!isIndexedDbAvailable()) {
    return entry;
  }

  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.put(entry);

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('Failed to save scan report.'));
  });

  // Prune oldest records if exceeding MAX_STORED_REPORTS
  try {
    const allReq = await new Promise<StoredScanReport[]>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).getAll();
      req.onsuccess = () => resolve((req.result as StoredScanReport[]) ?? []);
      req.onerror = () => reject(req.error);
    });

    if (allReq.length > MAX_STORED_REPORTS) {
      allReq.sort((a, b) => b.scannedAt.localeCompare(a.scannedAt));
      const toDelete = allReq.slice(MAX_STORED_REPORTS);
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        for (const item of toDelete) {
          store.delete(item.id);
        }
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    }
  } finally {
    db.close();
  }

  return entry;
}

export async function deleteScanReport(id: string): Promise<void> {
  if (!isIndexedDbAvailable()) return;

  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(id);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error('Failed to delete scan report.'));
    };
  });
}

export async function clearScanHistory(): Promise<void> {
  if (!isIndexedDbAvailable()) return;

  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).clear();
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error('Failed to clear scan history.'));
    };
  });
}
