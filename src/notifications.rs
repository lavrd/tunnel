#[cfg(not(target_os = "macos"))]
use log::warn;

#[cfg(target_os = "macos")]
pub(crate) fn send_notification() {
    macos::send_notification()
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn send_notification() {
    warn!("Notifications are working only on macOS right now")
}

#[cfg(target_os = "macos")]
mod macos {
    use log::{error, info};

    const NOTIFICATION_IDENTIFIER: &str = include_str!("../identifier.txt");
    const NOTIFICATION_TITLE: &str = "Test";
    const NOTIFICATION_DESCRIPTION: &str = "Notification";

    unsafe extern "C" {
        fn notify(
            identifier_ptr: *const u8,
            identifier_len: u64,
            title_ptr: *const u8,
            title_len: u64,
            description_ptr: *const u8,
            description_len: u64,
        ) -> u8;
    }

    pub(super) fn send_notification() {
        let result: u8 = unsafe {
            notify(
                NOTIFICATION_IDENTIFIER.as_ptr(),
                NOTIFICATION_IDENTIFIER.len() as u64,
                NOTIFICATION_TITLE.as_ptr(),
                NOTIFICATION_TITLE.len() as u64,
                NOTIFICATION_DESCRIPTION.as_ptr(),
                NOTIFICATION_DESCRIPTION.len() as u64,
            )
        };
        match result {
            0 => info!("Notification successfully sent"),
            101 => error!("User didn't grant a notification access to our application"),
            result => error!("Unknown notification result: {result}"),
        }
    }
}
