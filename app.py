import os
import logging
import random
import traceback
import threading
import time
import json
import gzip
import io
import re
import uuid
import socket
import datetime
import concurrent.futures
from functools import wraps
from threading import Lock
import requests
from flask import Flask, jsonify, request, Response, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from marshmallow import Schema, fields, ValidationError
from prometheus_flask_exporter import PrometheusMetrics
from dotenv import load_dotenv
import praw
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import psutil

load_dotenv()

log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(log_dir, 'app.log'), encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

csp = {
    'default-src': "'self'",
    'img-src': ['*', 'data:'],
    'style-src': ["'self'", "'unsafe-inline'"],
    'script-src': ["'self'", "'unsafe-inline'"]
}
talisman = Talisman(app, content_security_policy=csp, force_https=False)

allowed_origins = os.getenv('ALLOWED_ORIGINS')
if allowed_origins:
    origins = allowed_origins.split(',')
    CORS(app, resources={r"/*": {"origins": origins}})
else:
    CORS(app)

metrics = PrometheusMetrics(app)
metrics.info('app_info', 'Cat API', version='1.0.0')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour", "10 per minute"],
    storage_uri=os.getenv('REDIS_URL', 'memory://'),
    strategy="fixed-window"
)

reddit_client_id = os.getenv('REDDIT_CLIENT_ID')
reddit_client_secret = os.getenv('REDDIT_CLIENT_SECRET')
reddit_user_agent = os.getenv('REDDIT_USER_AGENT')

if not all([reddit_client_id, reddit_client_secret, reddit_user_agent]):
    logger.error("Reddit API credentials are not set")
    raise ValueError("Reddit API credentials are not set")

reddit = praw.Reddit(
    client_id=reddit_client_id,
    client_secret=reddit_client_secret,
    user_agent=reddit_user_agent
)

redis_client = None
redis_url = os.getenv('REDIS_URL')
if redis_url:
    try:
        import redis
        redis_client = redis.from_url(redis_url)
        redis_client.ping() 
        logger.info("Redis connected successfully")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}")
        redis_client = None

session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(
    max_retries=retry_strategy,
    pool_connections=10,
    pool_maxsize=100
)
session.mount("http://", adapter)
session.mount("https://", adapter)

cat_subreddits = ['cats', 'Catloaf', 'CatsStandingUp', 'CatsInSinks', 'catpictures', 'kittens', 'IllegallySmolCats']
prefetched_images = {}
prefetch_lock = Lock()
thread_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.getenv('THREAD_POOL_SIZE', '10'))
)

CACHE_TTL = int(os.getenv('CACHE_TTL', '3600')) 
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '5')) 
COMPRESSION_THRESHOLD = int(os.getenv('COMPRESSION_THRESHOLD', '1024')) 
PREFETCH_BATCH_SIZE = int(os.getenv('PREFETCH_BATCH_SIZE', '3')) 
PREFETCH_INTERVAL = int(os.getenv('PREFETCH_INTERVAL', '900')) 

class CatRequestSchema(Schema):
    subreddit = fields.String(required=False)
    limit = fields.Integer(required=False, validate=lambda n: 1 <= n <= 50)
    no_cache = fields.Boolean(required=False)

def compress_response(response):

    if not isinstance(response, Response) and not isinstance(response, str):
        return response
    
    if 'gzip' not in request.headers.get('Accept-Encoding', ''):
        return response
    
    data = response.data if isinstance(response, Response) else response.encode('utf-8')
    
    if len(data) < COMPRESSION_THRESHOLD:
        return response
    
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(mode='wb', fileobj=gzip_buffer) as f:
        f.write(data)
    
    compressed_data = gzip_buffer.getvalue()
    
    if isinstance(response, Response):
        resp = Response(compressed_data)
        resp.headers = dict(response.headers)
    else:
        resp = Response(compressed_data)
    
    resp.headers['Content-Encoding'] = 'gzip'
    resp.headers['Content-Length'] = str(len(compressed_data))
    
    return resp

def cache_response(ttl_seconds=CACHE_TTL):

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not redis_client:
                return f(*args, **kwargs)
            
            if 'no_cache' in request.args:
                return f(*args, **kwargs)
            
            origin = request.headers.get('Origin')
            if origin and allowed_origins and origin in origins:
                logger.info(f"Bypassing cache for allowed origin: {origin}")
                return f(*args, **kwargs)
            
            cache_key = f"cat_api:{request.path}:{hash(frozenset(request.args.items()))}"
            
            cached_response = redis_client.get(cache_key)
            if cached_response:
                try:
                    cached_data = json.loads(cached_response)
                    if isinstance(cached_data, dict):
                        cached_data['from_cache'] = True
                    
                    start_time = getattr(g, 'start_time', time.time())
                    response_time = int((time.time() - start_time) * 1000)
                    
                    if isinstance(cached_data, dict):
                        cached_data['response_time_ms'] = response_time
                    
                    logger.info(f"Cache hit for {request.path}")
                    return jsonify(cached_data)
                except Exception as e:
                    logger.error(f"Error parsing cached response: {e}")
            
            response = f(*args, **kwargs)
            
            try:
                if response and hasattr(response, 'json'):
                    response_data = response.json
                    redis_client.setex(cache_key, ttl_seconds, json.dumps(response_data))
            except Exception as e:
                logger.error(f"Error caching response: {e}")
            
            return response
        
        return decorated_function
    
    return decorator

def log_request():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
            
            start_time = time.time()
            response = f(*args, **kwargs)
            duration = time.time() - start_time
            
            status_code = response.status_code if hasattr(response, 'status_code') else 200
            logger.info(f"Response: {status_code} in {duration:.2f}s")
            
            return response
        
        return decorated_function
    
    return decorator

def validate_request(schema):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            schema_instance = schema()
            
            try:
                validated_data = schema_instance.load(request.args)
                
                g.validated_data = validated_data
                
                return f(*args, **kwargs)
            
            except ValidationError as err:
                error_response = {
                    "error": "Invalid request parameters",
                    "details": err.messages,
                    "status": 400
                }
                return jsonify(error_response), 400
        
        return decorated_function
    
    return decorator

def is_safe_content(text):
    if not text or not isinstance(text, str):
        return False
    
    unsafe_patterns = [
        r'\b(nsfw|porn|xxx|sex|explicit|nude|naked|adult|obscene)\b',
        r'\b(violence|gore|blood|death|kill|murder|suicide)\b',
        r'\b(racist|racism|nazi|hitler|hate|offensive)\b'
    ]
    
    for pattern in unsafe_patterns:
        if re.search(pattern, text.lower()):
            return False
    
    return True

def fetch_safe_cat_images_from_subreddit(subreddit_name, limit=20):
    try:
        subreddit = reddit.subreddit(subreddit_name)
        image_posts = []
        
        for post in subreddit.hot(limit=limit):
            if post.url.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                if is_safe_content(post.title):
                    image_posts.append(post)
        
        logger.info(f"Fetched {len(image_posts)} safe cat images from r/{subreddit_name}")
        return image_posts
    
    except Exception as e:
        logger.error(f"Error fetching from r/{subreddit_name}: {e}")
        return []

def prefetch_cat_images_batch():
    global prefetched_images
    
    logger.info("Starting batch prefetch of cat images")
    start_time = time.time()
    
    selected_subreddits = random.sample(cat_subreddits, min(PREFETCH_BATCH_SIZE, len(cat_subreddits)))
    
    fetch_tasks = []
    for subreddit in selected_subreddits:
        fetch_tasks.append(thread_pool.submit(fetch_safe_cat_images_from_subreddit, subreddit))
    
    new_images = {}
    for subreddit, task in zip(selected_subreddits, fetch_tasks):
        try:
            images = task.result(timeout=REQUEST_TIMEOUT * 2)
            if images:
                new_images[subreddit] = images
        except Exception as e:
            logger.error(f"Error in prefetch task for {subreddit}: {e}")
    
    with prefetch_lock:
        prefetched_images.update(new_images)
    
    duration = time.time() - start_time
    logger.info(f"Batch prefetch completed in {duration:.2f}s, fetched from {len(new_images)} subreddits")
    
    return duration

def start_prefetching():
    def prefetch_worker():
        logger.info("Starting prefetch worker thread")
        
        while True:
            try:
                duration = prefetch_cat_images_batch()
                
                sleep_time = max(10, PREFETCH_INTERVAL - duration)
                logger.info(f"Prefetch worker sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in prefetch worker: {e}")
                time.sleep(60)
    
    prefetch_thread = threading.Thread(target=prefetch_worker, daemon=True)
    prefetch_thread.start()
    logger.info("Prefetch worker thread started")

start_prefetching()

@app.before_request
def block_ssl_requests():
    if request.path.startswith('/.well-known/acme-challenge/'):
        return '', 404
    
    if request.path.startswith('/.well-known/pki-validation/'):
        return '', 404
    
    if request.path.startswith('/apple-app-site-association'):
        return '', 404
    
    if request.path.startswith('/.well-known/assetlinks.json'):
        return '', 404

@app.before_request
def log_all_requests():
    g.start_time = time.time()
    logger.debug(f"Request: {request.method} {request.path} from {request.remote_addr}")

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Server'] = 'Cat API'
    
    return response

@app.after_request
def apply_compression(response):
    return compress_response(response)

@app.route('/')
@metrics.do_not_track()
@log_request()
def health_check():
    try:
        redis_status = "ok" if redis_client and redis_client.ping() else "error"
        
        reddit_status = "ok"
        try:
            future = thread_pool.submit(lambda: reddit.subreddit('cats').display_name)
            future.result(timeout=REQUEST_TIMEOUT)
        except Exception as e:
            reddit_status = "error"
            logger.warning(f"Reddit API check failed: {e}")
        
        with prefetch_lock:
            prefetch_count = sum(len(posts) for posts in prefetched_images.values())
            prefetch_subreddits = list(prefetched_images.keys())
        
        thread_stats = {
            "active": len([t for t in thread_pool._threads if t.is_alive()]),
            "total": thread_pool._max_workers,
            "queue_size": thread_pool._work_queue.qsize()
        }
        
        system_stats = {
            "hostname": socket.gethostname(),
            "uptime": int(time.time() - app.start_time),
            "memory_usage": f"{psutil.virtual_memory().percent}%",
            "cpu_usage": f"{psutil.cpu_percent(interval=0.1)}%"
        }
        
        start_time = getattr(g, 'start_time', time.time())
        response_time = int((time.time() - start_time) * 1000)
        
        response = {
            "status": "healthy" if all(s == "ok" for s in [redis_status, reddit_status]) else "degraded",
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "1.0.0",
            "services": {
                "redis": redis_status,
                "reddit": reddit_status
            },
            "prefetch": {
                "count": prefetch_count,
                "subreddits": prefetch_subreddits
            },
            "threads": thread_stats,
            "system": system_stats,
            "response_time_ms": response_time
        }
        
        status_code = 200 if response["status"] == "healthy" else 503
        return jsonify(response), status_code
    
    except Exception as e:
        logger.error(f"Health check error: {e}")
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

@app.route('/metrics')
@metrics.do_not_track()
def metrics_endpoint():
   if request.remote_addr != '127.0.0.1' and request.remote_addr != 'localhost':
        auth_token = request.headers.get('X-Metrics-Auth')
        expected_token = os.getenv('METRICS_AUTH_TOKEN')
        
        if not auth_token or not expected_token or auth_token != expected_token:
            return jsonify({
                "error": "Unauthorized access to metrics",
                "status": 403
            }), 403
    
    return metrics.generate_latest()

@app.route('/stats')
@metrics.do_not_track()
@log_request()
@cache_response(ttl_seconds=60) 

def api_stats():
    try:
        start_time = getattr(g, 'start_time', time.time())
        
        thread_stats = {
            "active": len([t for t in thread_pool._threads if t.is_alive()]),
            "total": thread_pool._max_workers,
            "utilization": round(len([t for t in thread_pool._threads if t.is_alive()]) / thread_pool._max_workers * 100, 1)
        }
        
        with prefetch_lock:
            prefetch_count = sum(len(posts) for posts in prefetched_images.values())
            prefetch_age = int(time.time() - getattr(app, 'last_prefetch_time', app.start_time))
        
        response_time = int((time.time() - start_time) * 1000)
        
        response = {
            "uptime": int(time.time() - app.start_time),
            "requests": {
                "total": getattr(app, 'request_count', 0),
                "random_cat": getattr(app, 'random_cat_count', 0)
            },
            "performance": {
                "threads": thread_stats
            },
            "cache": {
                "enabled": redis_client is not None,
                "prefetched_images": prefetch_count,
                "prefetch_age_seconds": prefetch_age
            },
            "timestamp": datetime.datetime.now().isoformat(),
            "response_time_ms": response_time
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({
            "error": "Error generating stats",
            "details": str(e)
        }), 500

@app.route('/random-cat')
@metrics.do_not_track()
@log_request()
@validate_request(CatRequestSchema)
@cache_response()
def get_random_cat():
    try:
        start_time = getattr(g, 'start_time', time.time())
        
        validated_data = getattr(g, 'validated_data', {})
        
        requested_subreddit = validated_data.get('subreddit')
        
        if requested_subreddit and requested_subreddit not in cat_subreddits:
            return jsonify({
                "error": f"Invalid subreddit. Must be one of: {', '.join(cat_subreddits)}",
                "status": 400
            }), 400
        
        subreddit_to_use = requested_subreddit if requested_subreddit else random.choice(cat_subreddits)
        
        origin = request.headers.get('Origin')
        is_allowed_origin = origin and allowed_origins and origin in origins
        
        image_posts = []
        with prefetch_lock:
            if subreddit_to_use in prefetched_images and prefetched_images[subreddit_to_use]:
                image_posts = prefetched_images[subreddit_to_use]
                
                if image_posts and (requested_subreddit or is_allowed_origin):
                    random_post = random.choice(image_posts)
                    prefetched_images[subreddit_to_use].remove(random_post)
                    return format_cat_response(random_post, start_time)
        
        if not image_posts:
            logger.info(f"No prefetched images for {subreddit_to_use}, fetching directly")
            image_posts = fetch_safe_cat_images_from_subreddit(subreddit_to_use)
        
        max_attempts = 3
        for attempt in range(max_attempts):
            if not image_posts:
                logger.warning(f"No images found in r/{subreddit_to_use}, trying another subreddit (attempt {attempt+1}/{max_attempts})")
                
                if not requested_subreddit:
                    subreddit_to_use = random.choice([s for s in cat_subreddits if s != subreddit_to_use])
                    image_posts = fetch_safe_cat_images_from_subreddit(subreddit_to_use)
                else:
                    break
            else:
                break
        
        if not image_posts:
            return jsonify({
                "error": "No safe cat images found after multiple attempts",
                "status": 404
            }), 404
        
        random_post = random.choice(image_posts)
        
        if is_allowed_origin and subreddit_to_use in prefetched_images and random_post in prefetched_images[subreddit_to_use]:
            with prefetch_lock:
                if random_post in prefetched_images[subreddit_to_use]:
                    prefetched_images[subreddit_to_use].remove(random_post)
        
        return format_cat_response(random_post, start_time)
    
    except Exception as e:
        logger.error(f"Error in get_random_cat: {e}")
        traceback.print_exc()
        return jsonify({
            "error": "Internal server error",
            "details": str(e),
            "status": 500
        }), 500

def format_cat_response(post, start_time):
    response_time = int((time.time() - start_time) * 1000)
    
    response = {
        "title": post.title,
        "url": post.url,
        "subreddit": post.subreddit.display_name,
        "upvotes": post.score,
        "source": "reddit",
        "response_time_ms": response_time
    }
    
    return jsonify(response)

@app.errorhandler(400)
def bad_request(e):
    return jsonify({
        "error": "Bad request",
        "details": str(e),
        "status": 400
    }), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": "Not found",
        "details": "The requested resource was not found",
        "status": 404
    }), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "details": str(e.description),
        "retry_after": e.retry_after if hasattr(e, 'retry_after') else None,
        "status": 429
    }), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({
        "error": "Internal server error",
        "details": str(e),
        "status": 500
    }), 500

@app.before_request
def record_request_start_time():
    g.start_time = time.time()
    app.request_count = getattr(app, 'request_count', 0) + 1
    if request.path == '/random-cat':
        app.random_cat_count = getattr(app, 'random_cat_count', 0) + 1

app.start_time = time.time()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False, threaded=True)
