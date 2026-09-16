import sys
import os
import io
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from progress import Spinner


class TestSpinnerNonTty(unittest.TestCase):
    def test_prints_message_once_and_does_not_animate_on_non_tty_stream(self):
        buf = io.StringIO()  # io.StringIO has no isatty()==True -- non-interactive
        with Spinner("Working", stream=buf):
            pass
        output = buf.getvalue()
        self.assertIn("Working", output)
        # no spinner frame characters should appear on a non-tty stream
        self.assertNotIn("\r", output)

    def test_body_still_executes_normally(self):
        buf = io.StringIO()
        result = []
        with Spinner("Working", stream=buf):
            result.append(1)
        self.assertEqual(result, [1])

    def test_exceptions_in_the_with_block_propagate(self):
        buf = io.StringIO()
        with self.assertRaises(ValueError):
            with Spinner("Working", stream=buf):
                raise ValueError("boom")


class _FakeTtyStream(io.StringIO):
    def isatty(self):
        return True


class TestSpinnerTty(unittest.TestCase):
    def test_animates_and_clears_on_a_tty_stream(self):
        stream = _FakeTtyStream()
        with Spinner("Working", stream=stream, interval=0.01):
            time.sleep(0.05)  # let it spin a few frames
        output = stream.getvalue()
        self.assertIn("\r", output)      # animation used carriage returns
        self.assertIn("Working", output)
        # after exit, the very last thing written should be a clearing line
        # (an entirely-whitespace final segment after the last \r)
        last_segment = output.split("\r")[-1]
        self.assertEqual(last_segment.strip(), "")

    def test_stops_spinning_thread_on_exit(self):
        stream = _FakeTtyStream()
        spinner = Spinner("Working", stream=stream, interval=0.01)
        with spinner:
            time.sleep(0.03)
        self.assertFalse(spinner._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
