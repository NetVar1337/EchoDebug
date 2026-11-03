// Minimal IndexedDB key/value store for data too large for localStorage (big snapshots).
const kDb = "echodebug";
const kStore = "blobs";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return reject(new Error("IndexedDB is unavailable"));
    const r = indexedDB.open(kDb, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(kStore);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await open();
  return new Promise<T>((resolve, reject) => {
    const req = f(db.transaction(kStore, mode).objectStore(kStore));
    req.onsuccess = () => resolve(req.result as T);
    req.onerror = () => reject(req.error);
  });
}

export const idbGet = (key: string) => tx<Uint8Array | undefined>("readonly", (s) => s.get(key));
export const idbSet = (key: string, value: Uint8Array) => tx<IDBValidKey>("readwrite", (s) => s.put(value, key));
export const idbDel = (key: string) => tx<undefined>("readwrite", (s) => s.delete(key));
