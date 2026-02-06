use core::ffi::c_void;
use esp_idf_sys as sys;

static mut UART_TASK_HANDLE: sys::TaskHandle_t = core::ptr::null_mut();

extern "C" fn uart_task_entry(_arg: *mut c_void) {
    let _ = crate::software_link::test_com::uart_proto_task();
    unsafe { sys::vTaskDelete(core::ptr::null_mut()); }
}

pub fn start_uart_task(core_id: sys::BaseType_t) -> Result<(), i32> {
    unsafe {
        let name = b"uart_proto\0";

        // 8192 words = 32 KB stack (safe pour logs/crypto)
        let stack_words: u32 = 8192;

        let prio: sys::UBaseType_t = 10;

        let ok = sys::xTaskCreatePinnedToCore(
            Some(uart_task_entry),
            name.as_ptr() as *const u8,
            stack_words,
            core::ptr::null_mut(),
            prio,
            &raw mut UART_TASK_HANDLE,
            core_id,
        );

        // pdPASS est généralement 1
        if ok != 1 {
            return Err(sys::ESP_FAIL);
        }

        Ok(())
    }
}
