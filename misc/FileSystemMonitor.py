#Install watchdog library (pip install watchdog)
#Enter in line 25 directory to monitor

import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileSystemListener(FileSystemEventHandler):
    def __init__(self, directory_to_watch):
        self.directory_to_watch = directory_to_watch

    #This class method can be modified to execute command based on events
    def on_any_event(self, event):
        if event.is_directory:
            return
        event_type = event.event_type
        file_path = event.src_path
        print(f"Event type: {event_type}")
        print(f"File path: {file_path}")
        # Perform desired actions with the file event


#START SCRIPT
# Create an observer and attach the event handler
observer = Observer()
file_system_events = FileSystemListener()

#Specify the directory to monitor
directory_to_watch = ""

#Schedule the observer to watch the directory
observer.schedule(file_system_events, directory_to_watch, recursive=True)

#Start the observer
observer.start()
print(f"Listening directory: {directory_to_watch}")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    #Stop the observer if interrupted
    observer.stop()

#Wait until the observer thread completes
observer.join()

