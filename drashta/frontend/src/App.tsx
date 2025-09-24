const eventSource = new EventSource('http://localhost:3200/drain?event_name=sshd.events');

export default function EventViewer() {
  eventSource.onmessage = (event) => {
    console.log(`Received data: ${event.data}`);
  };

  eventSource.onerror = (error) => {
    console.error('EventSource failed:', error);
  };
}

