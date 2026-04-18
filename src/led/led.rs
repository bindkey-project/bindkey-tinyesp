use esp_idf_sys::*;

const LED_GPIO: i32 = 38;

pub struct LedGuard;

impl LedGuard{
    pub fn new() -> Self{
        unsafe{
            gpio_reset_pin(LED_GPIO);
            gpio_set_direction(LED_GPIO, gpio_mode_t_GPIO_MODE_OUTPUT);
            gpio_set_level(LED_GPIO, 1);
        }
        Self
    }
}

impl Drop for LedGuard{
    fn drop(&mut self){
        unsafe{
            gpio_set_level(LED_GPIO, 0);
        }
    }
}