// Stub implementation for __chkstk_ms and __chkstk
// Required when using -nostdlib with large stack allocations

extern "C" {
    // Stack probe stub for large stack allocations
    // In nostdlib mode, we just return since we trust our stack usage
    void ___chkstk_ms(void) {
        // Stack probe not needed in our shellcode context
        return;
    }

    void __chkstk(void) {
        // Stack probe not needed in our shellcode context
        return;
    }
}
