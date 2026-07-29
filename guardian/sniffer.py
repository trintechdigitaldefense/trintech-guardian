import socket
import threading
import time

class PortSensor:
    """User-space port listener that detects scanners without requiring raw sockets."""
    
    def __init__(self, callback_function, ports=[21, 22, 23, 80, 443, 3306, 8080]):
        self.callback = callback_function
        self.ports = ports
        self.threads = []

    def _listen_port(self, port):
        try:
            # Create a standard user-space socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            
            while True:
                conn, addr = s.accept()
                src_ip = addr[0]
                
                # Report the threat immediately
                self.callback(src_ip, port)
                
                # Instantly sever the connection (Port Tarpit behavior)
                conn.close()
        except Exception as e:
            # If port is already in use by a real service, fail silently
            pass

    def start(self):
        print(f"[+] Sensor Engine: ONLINE (User-Space Listening on ports {self.ports})")
        for port in self.ports:
            t = threading.Thread(target=self._listen_port, args=(port,), daemon=True)
            t.start()
            self.threads.append(t)
        
        # Keep main thread alive
        while True:
            time.sleep(1)
