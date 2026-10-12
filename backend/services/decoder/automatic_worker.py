"""Killable static-analysis worker. Submitted content is data, never code.

Two concurrent workers per API process, no unbounded pending queue. Unlike a
thread timeout, expiration actually terminates the CPU work and reaps the child.
"""
import multiprocessing
import threading

_CAPACITY = threading.BoundedSemaphore(2)
WORKER_SECONDS = 4.0


def _child(connection, text):
    try:
        from .engine import UniversalDecoderEngine
        connection.send(('ok', UniversalDecoderEngine().analyze_automatic(text)))
    except Exception:
        connection.send(('error', 'Static analysis could not complete safely'))
    finally:
        connection.close()


def analyze_isolated(text):
    from .automatic import MAX_INPUT
    if not text.strip() or len(text.encode('utf-8')) > MAX_INPUT:
        raise ValueError('Enter a nonempty command of at most 16 KiB')
    if not _CAPACITY.acquire(blocking=False):
        raise RuntimeError('Command analysis is busy; retry shortly')
    reader = writer = process = None
    try:
        ctx = multiprocessing.get_context('spawn')
        reader, writer = ctx.Pipe(duplex=False)
        process = ctx.Process(target=_child, args=(writer, text), daemon=True)
        process.start()
        writer.close()
        if not reader.poll(WORKER_SECONDS):
            raise TimeoutError('Command analysis exceeded the four-second worker budget; no complete result is available')
        try:
            kind, result = reader.recv()
        except (EOFError, OSError) as exc:
            raise RuntimeError('Static analysis worker stopped without a complete report') from exc
        if kind != 'ok':
            raise RuntimeError(result)
        return result
    finally:
        if process is not None and process.pid:
            process.join(timeout=.05)
            if process.is_alive():
                process.terminate()
                process.join(timeout=.2)
            if process.is_alive():
                process.kill()
                process.join()
        if reader is not None:
            reader.close()
        if writer is not None:
            writer.close()
        _CAPACITY.release()
