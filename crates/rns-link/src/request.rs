use std::time::{Duration, Instant};

/// State of a request receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Sent,
    /// Response is arriving as a resource transfer rather than a single packet.
    Receiving,
    Delivered,
    Failed,
    /// Response payload has arrived; kept distinct from [`Delivered`] so callers
    /// can distinguish "ack with data" from "ack only".
    ///
    /// [`Delivered`]: RequestState::Delivered
    ResponseReceived,
}

/// Callbacks for request receipt state changes.
#[derive(Default)]
pub struct RequestCallbacks {
    pub response: Option<RequestCallback>,
    pub failed: Option<RequestCallback>,
    pub progress: Option<ProgressCallback>,
}

/// Callback invoked once when a request receives a response or terminal failure.
pub type RequestCallback = Box<dyn FnOnce(&RequestReceipt) + Send>;
/// Progress callback for resource-backed request responses.
pub type ProgressCallback = Box<dyn Fn(f32) + Send + Sync>;

/// Tracks the lifecycle of an outbound request over a link.
pub struct RequestReceipt {
    pub request_id: [u8; 32],
    pub link_id: [u8; 16],
    pub state: RequestState,
    pub sent_at: Instant,
    pub timeout: Duration,
    pub response: Option<Vec<u8>>,
    pub rtt: Option<Duration>,
    /// Transfer progress in [0.0, 1.0]; only meaningful for resource responses.
    pub progress: f32,
    pub callbacks: RequestCallbacks,
}

impl RequestReceipt {
    pub fn new(request_id: [u8; 32], link_id: [u8; 16], timeout: Duration) -> Self {
        Self {
            request_id,
            link_id,
            state: RequestState::Sent,
            sent_at: Instant::now(),
            timeout,
            response: None,
            rtt: None,
            progress: 0.0,
            callbacks: RequestCallbacks::default(),
        }
    }

    /// Record a response payload, transition to `Delivered`, and fire the response callback.
    pub fn deliver(&mut self, response: Vec<u8>) {
        if self.state == RequestState::Sent || self.state == RequestState::Receiving {
            self.rtt = Some(self.sent_at.elapsed());
            self.response = Some(response);
            self.state = RequestState::Delivered;
            self.progress = 1.0;
            if let Some(cb) = self.callbacks.response.take() {
                cb(self);
            }
        }
    }

    /// Transition to `Failed` and fire the failure callback.
    pub fn fail(&mut self) {
        if self.state == RequestState::Sent || self.state == RequestState::Receiving {
            self.state = RequestState::Failed;
            if let Some(cb) = self.callbacks.failed.take() {
                cb(self);
            }
        }
    }

    pub fn is_timed_out(&self) -> bool {
        matches!(self.state, RequestState::Sent | RequestState::Receiving)
            && self.sent_at.elapsed() > self.timeout
    }

    pub fn is_pending(&self) -> bool {
        matches!(self.state, RequestState::Sent | RequestState::Receiving)
    }

    /// Store the response payload and advance to `ResponseReceived`.
    ///
    /// Distinct from `deliver()`: `receive_response` can fire after `mark_delivered()`
    /// for protocols that ack then stream the payload.
    pub fn receive_response(&mut self, data: Vec<u8>) {
        if matches!(
            self.state,
            RequestState::Sent | RequestState::Receiving | RequestState::Delivered
        ) {
            self.rtt = Some(self.sent_at.elapsed());
            self.response = Some(data);
            self.state = RequestState::ResponseReceived;
            self.progress = 1.0;
            if let Some(cb) = self.callbacks.response.take() {
                cb(self);
            }
        }
    }

    /// Transition to `Delivered` without a response payload (ack-only).
    pub fn mark_delivered(&mut self) {
        if self.state == RequestState::Sent {
            self.state = RequestState::Delivered;
        }
    }

    /// Transition to `Failed` without firing the failure callback.
    pub fn mark_failed(&mut self) {
        if self.state == RequestState::Sent {
            self.state = RequestState::Failed;
        }
    }

    /// True once the request has reached a terminal state (delivered, failed, or response received).
    pub fn concluded(&self) -> bool {
        matches!(
            self.state,
            RequestState::Delivered | RequestState::Failed | RequestState::ResponseReceived
        )
    }

    pub fn get_response_time(&self) -> Option<Duration> {
        self.rtt
    }

    pub fn get_progress(&self) -> f32 {
        self.progress
    }

    pub fn update_progress(&mut self, progress: f32) {
        self.progress = progress;
        if let Some(ref cb) = self.callbacks.progress {
            cb(progress);
        }
    }

    pub fn set_response_callback(&mut self, cb: impl FnOnce(&RequestReceipt) + Send + 'static) {
        self.callbacks.response = Some(Box::new(cb));
    }

    pub fn set_failed_callback(&mut self, cb: impl FnOnce(&RequestReceipt) + Send + 'static) {
        self.callbacks.failed = Some(Box::new(cb));
    }

    pub fn set_progress_callback(&mut self, cb: impl Fn(f32) + Send + Sync + 'static) {
        self.callbacks.progress = Some(Box::new(cb));
    }

    /// Expire the request if past its deadline, firing the failure callback. Returns `true` if expired.
    pub fn check_timeout(&mut self) -> bool {
        if self.is_timed_out() {
            self.fail();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_receipt_lifecycle() {
        let mut receipt = RequestReceipt::new([0xAA; 32], [0xBB; 16], Duration::from_secs(10));

        assert_eq!(receipt.state, RequestState::Sent);
        assert!(receipt.is_pending());
        assert!(receipt.response.is_none());

        receipt.deliver(b"response data".to_vec());
        assert_eq!(receipt.state, RequestState::Delivered);
        assert!(!receipt.is_pending());
        assert!(receipt.response.is_some());
        assert!(receipt.rtt.is_some());
    }

    #[test]
    fn test_request_receipt_fail() {
        let mut receipt = RequestReceipt::new([0xAA; 32], [0xBB; 16], Duration::from_secs(10));

        receipt.fail();
        assert_eq!(receipt.state, RequestState::Failed);
        assert!(!receipt.is_pending());
    }

    #[test]
    fn test_cannot_deliver_after_fail() {
        let mut receipt = RequestReceipt::new([0xAA; 32], [0xBB; 16], Duration::from_secs(10));

        receipt.fail();
        receipt.deliver(b"too late".to_vec());
        assert_eq!(receipt.state, RequestState::Failed);
        assert!(receipt.response.is_none());
    }

    #[test]
    fn test_receive_response() {
        let mut receipt = RequestReceipt::new([0xCC; 32], [0xDD; 16], Duration::from_secs(10));

        assert_eq!(receipt.state, RequestState::Sent);
        receipt.receive_response(b"response payload".to_vec());
        assert_eq!(receipt.state, RequestState::ResponseReceived);
        assert_eq!(
            receipt.response.as_deref(),
            Some(b"response payload".as_slice())
        );
        assert!(receipt.rtt.is_some());
    }

    #[test]
    fn test_mark_delivered_then_response() {
        let mut receipt = RequestReceipt::new([0xEE; 32], [0xFF; 16], Duration::from_secs(10));

        receipt.mark_delivered();
        assert_eq!(receipt.state, RequestState::Delivered);

        receipt.receive_response(b"late response".to_vec());
        assert_eq!(receipt.state, RequestState::ResponseReceived);
        assert!(receipt.response.is_some());
    }

    #[test]
    fn test_mark_failed_method() {
        let mut receipt = RequestReceipt::new([0x11; 32], [0x22; 16], Duration::from_secs(10));

        receipt.mark_failed();
        assert_eq!(receipt.state, RequestState::Failed);
        assert!(!receipt.is_pending());
    }

    #[test]
    fn test_cannot_receive_response_after_fail() {
        let mut receipt = RequestReceipt::new([0x33; 32], [0x44; 16], Duration::from_secs(10));

        receipt.mark_failed();
        receipt.receive_response(b"too late".to_vec());
        assert_eq!(receipt.state, RequestState::Failed);
        assert!(receipt.response.is_none());
    }

    #[test]
    fn test_receive_response_fires_callback_from_receiving_state() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let fired = Arc::new(AtomicBool::new(false));
        let callback_fired = fired.clone();
        let mut receipt = RequestReceipt::new([0x55; 32], [0x66; 16], Duration::from_secs(10));
        receipt.state = RequestState::Receiving;
        receipt.set_response_callback(move |receipt| {
            assert_eq!(receipt.state, RequestState::ResponseReceived);
            callback_fired.store(true, Ordering::SeqCst);
        });

        receipt.receive_response(b"resource response".to_vec());

        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(receipt.get_progress(), 1.0);
    }

    #[test]
    fn test_receiving_request_times_out_and_fires_failure_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let fired = Arc::new(AtomicBool::new(false));
        let callback_fired = fired.clone();
        let mut receipt = RequestReceipt::new([0x77; 32], [0x88; 16], Duration::ZERO);
        receipt.state = RequestState::Receiving;
        receipt.set_failed_callback(move |receipt| {
            assert_eq!(receipt.state, RequestState::Failed);
            callback_fired.store(true, Ordering::SeqCst);
        });

        assert!(receipt.check_timeout());
        assert!(fired.load(Ordering::SeqCst));
        assert!(!receipt.is_pending());
    }
}
