#include "log.h"
#include "ws_client.h"
#include "monitors.h"
#include "net_worker.h"
#include "checknet.h"
#include <WiFi.h>
#ifdef MMU_IRAM_HEAP
#include <umm_malloc/umm_heap_select.h>
#endif

static uint32_t s_min_largest = 0xFFFFFFFF;

void log_heap_sample() {
    uint32_t b = ESP.getMaxFreeBlockSize();
    if (b < s_min_largest) s_min_largest = b;
}

uint32_t log_heap_min() { return s_min_largest == 0xFFFFFFFF ? 0 : s_min_largest; }

void log_health() {
    // free/largest now, min largest since boot (fragmentation floor), link + subsystems.
    LOGI("health",
         "up=%lus heap=%uk blk=%uk min=%uk rssi=%d ws=%s mon=%u lag=%.2f busy=%u%% cn=%s",
         (unsigned long)(millis() / 1000),
         (unsigned)(ESP.getFreeHeap()      / 1024),
         (unsigned)(ESP.getMaxFreeBlockSize()  / 1024),
         (unsigned)(log_heap_min()         / 1024),
         WiFi.RSSI(),
         ws_client_connected() ? "up" : "down",
         (unsigned)monitors_count(),
         monitors_qlag(),
         (unsigned)net_worker_last_busy(),
         checknet_busy() ? "run" : "idle");
    // Druga linia [mem]: fragmentacja DRAM + (gdy MMU second heap aktywny) wolny IRAM.
    // CELOWO bez wzorca "heap <N>k" — HEAP_RE w tools/gate_heap.py zassalby te liczby
    // do min_heap. Wartosci IRAM w bajtach, nie kB.
#ifdef MMU_IRAM_HEAP
    uint32_t iram_free = 0, iram_blk = 0;
    {
        HeapSelectIram ephemeral;
        iram_free = ESP.getFreeHeap();
        iram_blk  = ESP.getMaxFreeBlockSize();
    }
    LOGI("mem", "frag=%u%% iram_free=%u iram_blk=%u",
         (unsigned)ESP.getHeapFragmentation(), (unsigned)iram_free, (unsigned)iram_blk);
#else
    LOGI("mem", "frag=%u%%", (unsigned)ESP.getHeapFragmentation());
#endif
}
