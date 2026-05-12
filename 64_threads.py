import threading
import time


def worker(thread_id):
    time.sleep(2)

def main():
    threads = []
    for i in range(64):
        thread = threading.Thread(target=worker, args=(i,))
        threads.append(thread)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
if __name__ == '__main__':
    main()
