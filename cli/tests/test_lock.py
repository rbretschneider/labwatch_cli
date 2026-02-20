"""Tests for the file-based Lock."""

from labwatch.lock import Lock


class TestLock:
    def test_acquire_and_release(self, tmp_path):
        lock = Lock(path=tmp_path / "test.lock")
        assert lock.acquire() is True
        lock.release()

    def test_double_lock_fails(self, tmp_path):
        """A second Lock on the same path cannot acquire while the first holds it."""
        lock_path = tmp_path / "test.lock"
        lock1 = Lock(path=lock_path)
        lock2 = Lock(path=lock_path)

        assert lock1.acquire() is True
        assert lock2.acquire() is False

        lock1.release()

    def test_release_then_reacquire(self, tmp_path):
        """After release, the lock can be acquired again."""
        lock_path = tmp_path / "test.lock"
        lock1 = Lock(path=lock_path)

        assert lock1.acquire() is True
        lock1.release()

        lock2 = Lock(path=lock_path)
        assert lock2.acquire() is True
        lock2.release()

    def test_double_release_safe(self, tmp_path):
        """Calling release() twice must not raise."""
        lock = Lock(path=tmp_path / "test.lock")
        lock.acquire()
        lock.release()
        lock.release()  # Should not raise

    def test_release_without_acquire_safe(self, tmp_path):
        """Calling release() without acquire must not raise."""
        lock = Lock(path=tmp_path / "test.lock")
        lock.release()  # Should not raise

    def test_writes_pid(self, tmp_path):
        """Lock file should contain the current PID for debugging."""
        import os
        lock_path = tmp_path / "test.lock"
        lock = Lock(path=lock_path)
        lock.acquire()
        lock.release()

        # Read after release — Windows blocks reads while the lock is held
        content = lock_path.read_text()
        assert str(os.getpid()) in content

    def test_context_manager(self, tmp_path):
        """Lock works as a context manager."""
        lock_path = tmp_path / "test.lock"
        with Lock(path=lock_path) as lock:
            # Lock should be acquired (fd is not None)
            assert lock._fd is not None
        # After exiting context, fd should be None
        assert lock._fd is None

    def test_creates_parent_directory(self, tmp_path):
        """Lock should create parent directories if they don't exist."""
        lock_path = tmp_path / "nested" / "dir" / "test.lock"
        lock = Lock(path=lock_path)
        assert lock.acquire() is True
        lock.release()
        assert lock_path.parent.exists()
