use alloc::collections::vec_deque::VecDeque;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem;
use core::ptr;
use std::sync::{Mutex, OnceLock};
use std::thread::{self, ThreadId};

pub use async_task::Task;
use async_task::{Runnable, ScheduleInfo, WithInfo};
use nginx_sys::{ngx_event_actions, ngx_event_t, ngx_post_event, ngx_posted_next_events};

use crate::log::ngx_cycle_log;
use crate::ngx_log_debug;

static SCHEDULER: Scheduler = Scheduler::new();

struct RunnableQueue(Mutex<VecDeque<Runnable>>);

impl RunnableQueue {
    const fn new() -> Self {
        Self(Mutex::new(VecDeque::new()))
    }

    fn push(&self, runnable: Runnable) {
        self.0.lock().unwrap_or_else(|error| error.into_inner()).push_back(runnable);
    }

    fn take(&self) -> VecDeque<Runnable> {
        mem::take(&mut *self.0.lock().unwrap_or_else(|error| error.into_inner()))
    }
}

struct Scheduler {
    worker: OnceLock<ThreadId>,
    queue: RunnableQueue,
    posted: UnsafeCell<PostedEvent>,
}

// SAFETY: the queue and worker ID are synchronized. The posted event is accessed only from the
// registered nginx worker thread.
unsafe impl Sync for Scheduler {}

impl Scheduler {
    const fn new() -> Self {
        Self {
            worker: OnceLock::new(),
            queue: RunnableQueue::new(),
            posted: UnsafeCell::new(PostedEvent::new()),
        }
    }

    fn register_worker(&self) {
        let current = thread::current().id();
        let worker = self.worker.get_or_init(|| current);
        assert_eq!(*worker, current, "async tasks must be spawned on the nginx worker thread");
    }

    fn schedule(&self, runnable: Runnable) {
        self.queue.push(runnable);

        if self.worker.get().is_some_and(|worker| *worker == thread::current().id()) {
            self.post_event();
            return;
        }

        // SAFETY: nginx initializes the selected event actions before worker modules can spawn
        // tasks and does not replace them while the worker is running.
        let notify = unsafe { ngx_event_actions.notify };
        if let Some(notify) = notify {
            // SAFETY: notify is the selected event module's cross-thread entrypoint. The callback
            // only drains the synchronized queue and polls tasks on the nginx worker thread.
            let _ = unsafe { notify(Some(Self::notification_handler)) };
        }
    }

    fn post_event(&self) {
        let posted = unsafe { &mut *self.posted.get() };
        posted.event.log = ngx_cycle_log().as_ptr();
        if posted.event.data.is_null() {
            posted.event.data = ptr::from_mut(posted).cast();
        }
        // SAFETY: this function is called only from the registered worker thread, which owns both
        // the posted event and nginx's posted-event queue.
        unsafe { ngx_post_event(&raw mut posted.event, &raw mut ngx_posted_next_events) }
    }

    fn process(&self) {
        let mut runnables = self.queue.take();
        ngx_log_debug!(
            ngx_cycle_log().as_ptr(),
            "async: processing {} deferred wakeups",
            runnables.len()
        );

        for runnable in runnables.drain(..) {
            runnable.run();
        }
    }

    unsafe extern "C" fn notification_handler(_event: *mut ngx_event_t) {
        SCHEDULER.process();
    }

    unsafe extern "C" fn posted_handler(_event: *mut ngx_event_t) {
        SCHEDULER.process();
    }
}

#[repr(C)]
struct PostedEvent {
    _ident: [usize; 4], // `ngx_event_ident` compatibility
    event: ngx_event_t,
}

impl PostedEvent {
    const fn new() -> Self {
        let mut event: ngx_event_t = unsafe { mem::zeroed() };
        event.handler = Some(Scheduler::posted_handler);

        Self {
            _ident: [
                0, 0, 0, 0x4153594e, // ASYN
            ],
            event,
        }
    }
}

fn schedule(runnable: Runnable, _info: ScheduleInfo) {
    // Always defer the wake through the nginx event loop; never re-poll synchronously.
    //
    // `Waker::wake()` may fire from arbitrary contexts, including a future's
    // `Drop` while a lock is held (e.g. h2's `Streams::drop` wakes its parked
    // `Connection` task while holding `Arc<Mutex<Inner>>`). A synchronous re-poll would re-enter
    // the task and deadlock on that lock.
    SCHEDULER.schedule(runnable);
}

/// Creates a new task running on the NGINX event loop.
///
/// This function must be called on the nginx worker thread. The task is always polled on that
/// thread even when its waker is invoked from another thread. Prompt cross-thread wakeups require
/// the selected nginx event module to provide its notification hook.
pub fn spawn<F, T>(future: F) -> Task<T>
where
    F: Future<Output = T> + 'static,
    T: 'static,
{
    SCHEDULER.register_worker();
    ngx_log_debug!(ngx_cycle_log().as_ptr(), "async: spawning new task");
    let scheduler = WithInfo(schedule);
    let (runnable, task) = async_task::spawn_local(future, scheduler);
    runnable.schedule();
    task
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    #[test]
    fn runnable_queue_returns_remote_wake_to_owner() {
        let queue = Arc::new(RunnableQueue::new());
        let ready = Arc::new(AtomicBool::new(false));
        let (waker_tx, waker_rx) = mpsc::channel();

        let future_ready = Arc::clone(&ready);
        let future = core::future::poll_fn(move |context| {
            if future_ready.load(Ordering::Acquire) {
                Poll::Ready(7)
            } else {
                waker_tx.send(context.waker().clone()).unwrap();
                Poll::Pending
            }
        });
        let scheduled = Arc::clone(&queue);
        let (runnable, task) =
            async_task::spawn_local(future, move |runnable| scheduled.push(runnable));

        runnable.schedule();
        for runnable in queue.take() {
            runnable.run();
        }

        let remote_ready = Arc::clone(&ready);
        let waker = waker_rx.recv().unwrap();
        thread::spawn(move || {
            remote_ready.store(true, Ordering::Release);
            waker.wake();
        })
        .join()
        .unwrap();

        for runnable in queue.take() {
            runnable.run();
        }

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(7));
    }
}
