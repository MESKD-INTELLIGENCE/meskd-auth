use std::time::{Duration, Instant};

use zeroize::Zeroizing;

#[derive(Default)]
pub struct Clip {
    board: Option<arboard::Clipboard>,
    pending: Option<(Instant, Zeroizing<String>)>,
}

impl Clip {
    fn board(&mut self) -> Option<&mut arboard::Clipboard> {
        if self.board.is_none() {
            self.board = arboard::Clipboard::new().ok();
        }
        self.board.as_mut()
    }

    pub fn copy_secret(&mut self, text: &str, clear_after: u32) -> bool {
        let Some(board) = self.board() else {
            return false;
        };
        let set = board.set();
        #[cfg(windows)]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_history()
        };
        #[cfg(all(unix, not(target_os = "macos")))]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        };
        if set.text(text.to_owned()).is_err() {
            return false;
        }
        self.pending = (clear_after > 0).then(|| {
            (
                Instant::now() + Duration::from_secs(u64::from(clear_after)),
                Zeroizing::new(text.to_owned()),
            )
        });
        true
    }

    pub fn image(&mut self) -> Option<(usize, usize, Vec<u8>)> {
        let image = self.board()?.get_image().ok()?;
        Some((image.width, image.height, image.bytes.into_owned()))
    }

    pub fn text(&mut self) -> Option<String> {
        self.board()?.get_text().ok()
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.as_ref().map(|(at, _)| *at)
    }

    pub fn tick(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|(at, _)| Instant::now() >= *at)
        {
            self.clear_now();
        }
    }

    pub fn clear_now(&mut self) {
        let Some((_, copied)) = self.pending.take() else {
            return;
        };
        if let Some(board) = self.board()
            && board.get_text().is_ok_and(|current| current == *copied)
        {
            let _ = board.clear();
        }
    }
}
