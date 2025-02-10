import multiprocessing
import os

bind = '0.0.0.0:5000'
workers = max(2, multiprocessing.cpu_count() + 1)
worker_class = 'sync'
worker_connections = 1000

loglevel = 'info'
capture_output = True

timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50

limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

raw_env = [
    f'DOMAIN=localhost',
    f'PORT=5000',
    'ENV=production'
]

preload_app = True

errorlog = '-'  
accesslog = '-'  
