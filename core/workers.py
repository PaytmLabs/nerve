import threading

from bin.scanner    import scanner
from bin.attacker   import attacker
from bin.scheduler  import scheduler


def start_workers():
  thread = threading.Thread(target=scanner)
  thread.name = "scanner"
  thread.daemon = True
  thread.start()

  thread = threading.Thread(target=attacker)
  thread.name = "attacker"
  thread.daemon = True
  thread.start()

  thread = threading.Thread(target=scheduler)
  thread.name = "scheduler"
  thread.daemon = True
  thread.start()