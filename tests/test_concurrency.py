import sys
import os
import time
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from concurrency import map_concurrent


class TestMapConcurrent(unittest.TestCase):
    def test_preserves_input_order_regardless_of_completion_order(self):
        # item 0 sleeps longest, so if order weren't preserved by design
        # (not by luck) it would finish last and land at the end
        def slow_square(n):
            time.sleep(0.03 if n == 0 else 0.001)
            return n * n

        result = map_concurrent(slow_square, [0, 1, 2, 3])
        self.assertEqual(result, [0, 1, 4, 9])

    def test_empty_list_returns_empty(self):
        self.assertEqual(map_concurrent(lambda x: x, []), [])

    def test_single_item_runs_without_thread_pool(self):
        calls = []

        def record(x):
            calls.append(threading.current_thread().name)
            return x * 2

        result = map_concurrent(record, [5])
        self.assertEqual(result, [10])
        self.assertEqual(calls, [threading.current_thread().name])  # ran on the calling thread

    def test_multiple_items_actually_run_concurrently(self):
        # if these ran sequentially, total time would be >= 4 * 0.02s;
        # concurrently, wall time should be close to a single sleep
        start = time.time()
        map_concurrent(lambda x: time.sleep(0.02), [1, 2, 3, 4])
        elapsed = time.time() - start
        self.assertLess(elapsed, 0.06)  # well under 4x0.02s if truly concurrent

    def test_propagates_exceptions_from_worker(self):
        def boom(x):
            if x == 2:
                raise ValueError("bad item")
            return x

        with self.assertRaises(ValueError):
            map_concurrent(boom, [1, 2, 3])

    def test_respects_max_workers_cap(self):
        # can't directly observe pool size, but this at minimum shouldn't crash
        # with a workers count larger than the item count
        result = map_concurrent(lambda x: x + 1, [1, 2], max_workers=10)
        self.assertEqual(result, [2, 3])


if __name__ == "__main__":
    unittest.main()
