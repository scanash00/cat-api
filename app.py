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

cat_subreddits = [
    'cats', 'Catloaf', 'CatsStandingUp', 'CatsInSinks', 'catpictures', 'kittens', 'IllegallySmolCats', 'cat', '316cats',
    'SupermodelCats', 'BlackCats', 'Floof', 'CatsWithJobs', 'TuxedoCats', 'CatSpotting', 'CatGifs', 'CatBellies',
    'TheCatTrapIsWorking', 'CatsInBusinessAttire', 'StartledCats', 'curledfeetsies', 'CatsAreAssholes',
    'CatsAreAliens', 'CatLoaf', 'CatsInHats', 'CatsOnGlass', 'Eyebleach', 'CatsWithDogs', 'CatsInBoxes', 'blep',
    'CatsPlayingDnd', 'CatSlaps', 'CatsWhoYell', 'CatsWithSocks', 'teefies', 'toebeans', 'airplaneears', 'bottlebrush',
    'CatsInWaterPackages', 'CatsWhoSqueak', 'CatsWhoChirp', 'CatsWhoTrill', 'gingercats', 'torties', 'mainecoons',
    'SiberianCats', 'ragdollcats', 'standardissuecat', 'WhiskerFireworks', 'scrungycats', 'CatsInSunlight', 'CatSmiles',
    'CatsEnjoyingPets', 'CatsHuggingThings', 'CatsSittingLikePeople', 'CatsStaringAtWalls', 'CatsWithMustaches',
    'PirateKitties', 'PetTheDamnCat', 'CatsWhoDidNotWantDads', 'CatsOnPizza', 'CatsWithHats',
    'CatsInCostumes', 'CatsInSnow', 'CatsOnKeyboards', 'ChonkyCats', 'Kitten', 'KittenGifs', 'CatPics'
]

cat_subreddits = list(dict.fromkeys(cat_subreddits))

prefetched_images = {}
prefetch_lock = Lock()
subreddit_access_count = {}  
subreddit_error_count = {}  
last_access_time = {}        
thread_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.getenv('THREAD_POOL_SIZE', '10'))
)

CACHE_TTL = int(os.getenv('CACHE_TTL', '3600')) 
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '5')) 
COMPRESSION_THRESHOLD = int(os.getenv('COMPRESSION_THRESHOLD', '1024')) 
PREFETCH_BATCH_SIZE = int(os.getenv('PREFETCH_BATCH_SIZE', '5'))  
PREFETCH_INTERVAL = int(os.getenv('PREFETCH_INTERVAL', '600'))    
MIN_IMAGES_PER_SUBREDDIT = int(os.getenv('MIN_IMAGES_PER_SUBREDDIT', '5'))
MAX_PREFETCH_ERRORS = int(os.getenv('MAX_PREFETCH_ERRORS', '3'))
PREFETCH_RETRY_DELAY = int(os.getenv('PREFETCH_RETRY_DELAY', '30'))

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
    global prefetched_images, subreddit_access_count, subreddit_error_count
    
    logger.info("Starting batch prefetch of cat images")
    start_time = time.time()
    
    candidate_subreddits = []
    
    with prefetch_lock:
        for subreddit in cat_subreddits:
            if subreddit not in prefetched_images or len(prefetched_images.get(subreddit, [])) < MIN_IMAGES_PER_SUBREDDIT:
                candidate_subreddits.append(subreddit)
    
    popular_subreddits = sorted(
        [s for s in subreddit_access_count.keys() if s not in candidate_subreddits],
        key=lambda s: subreddit_access_count.get(s, 0),
        reverse=True
    )[:PREFETCH_BATCH_SIZE]
    
    candidate_subreddits.extend(popular_subreddits)
    
    remaining_subreddits = [s for s in cat_subreddits if s not in candidate_subreddits]
    if remaining_subreddits:
        candidate_subreddits.extend(random.sample(
            remaining_subreddits, 
            min(PREFETCH_BATCH_SIZE // 4, len(remaining_subreddits))
        ))
    
    candidate_subreddits = [
        s for s in candidate_subreddits 
        if subreddit_error_count.get(s, 0) < MAX_PREFETCH_ERRORS
    ]
    
    if len(candidate_subreddits) < PREFETCH_BATCH_SIZE // 2:
        candidate_subreddits.extend(random.sample(
            cat_subreddits,
            min(PREFETCH_BATCH_SIZE - len(candidate_subreddits), len(cat_subreddits))
        ))
    
    selected_subreddits = candidate_subreddits[:PREFETCH_BATCH_SIZE]
    if len(selected_subreddits) < PREFETCH_BATCH_SIZE:
        remaining = [s for s in cat_subreddits if s not in selected_subreddits]
        if remaining:
            selected_subreddits.extend(random.sample(
                remaining,
                min(PREFETCH_BATCH_SIZE - len(selected_subreddits), len(remaining))
            ))
    
    logger.info(f"Selected {len(selected_subreddits)} subreddits for prefetching: {', '.join(selected_subreddits)}")
    
    fetch_tasks = {}
    for subreddit in selected_subreddits:
        fetch_tasks[subreddit] = thread_pool.submit(fetch_safe_cat_images_from_subreddit, subreddit)
    
    new_images = {}
    for subreddit, task in fetch_tasks.items():
        try:
            images = task.result(timeout=REQUEST_TIMEOUT * 3) 
            
            if images:
                new_images[subreddit] = images
                subreddit_error_count[subreddit] = 0
            else:
                subreddit_error_count[subreddit] = subreddit_error_count.get(subreddit, 0) + 1
                logger.warning(f"No images found for r/{subreddit}, error count: {subreddit_error_count[subreddit]}")
        except Exception as e:
            subreddit_error_count[subreddit] = subreddit_error_count.get(subreddit, 0) + 1
            logger.error(f"Error in prefetch task for {subreddit} (error count: {subreddit_error_count[subreddit]}): {e}")
    
    with prefetch_lock:
        for subreddit, images in new_images.items():
            if subreddit not in prefetched_images:
                prefetched_images[subreddit] = []
            
            existing_urls = {post.url for post in prefetched_images[subreddit]}
            for post in images:
                if post.url not in existing_urls:
                    prefetched_images[subreddit].append(post)
    
    duration = time.time() - start_time
    total_images = sum(len(images) for images in prefetched_images.values())
    
    logger.info(f"Batch prefetch completed in {duration:.2f}s, fetched {sum(len(images) for images in new_images.values())} new images")
    logger.info(f"Total prefetched images: {total_images} across {len(prefetched_images)} subreddits")
    
    return duration

def start_prefetching():
    def prefetch_worker():
        logger.info("Starting prefetch worker thread")
        
        consecutive_errors = 0
        last_prefetch_time = time.time()
        
        while True:
            try:
                current_time = time.time()
                time_since_last_prefetch = current_time - last_prefetch_time
                
                total_prefetched = 0
                with prefetch_lock:
                    total_prefetched = sum(len(images) for images in prefetched_images.values())
                
                need_prefetch = False
                
                if total_prefetched < MIN_IMAGES_PER_SUBREDDIT * PREFETCH_BATCH_SIZE:
                    need_prefetch = True
                    logger.info(f"Triggering prefetch due to low total image count ({total_prefetched})")
                
                elif time_since_last_prefetch >= PREFETCH_INTERVAL:
                    need_prefetch = True
                    logger.info(f"Triggering prefetch due to interval ({time_since_last_prefetch:.2f}s)")
                
                else:
                    with prefetch_lock:
                        popular_subs = sorted(
                            subreddit_access_count.keys(), 
                            key=lambda s: subreddit_access_count.get(s, 0),
                            reverse=True
                        )[:5]  
                        
                        for sub in popular_subs:
                            if sub not in prefetched_images or len(prefetched_images.get(sub, [])) < MIN_IMAGES_PER_SUBREDDIT:
                                need_prefetch = True
                                logger.info(f"Triggering prefetch due to popular subreddit {sub} being low on images")
                                break
                
                if need_prefetch:
                    last_prefetch_time = current_time
                    duration = prefetch_cat_images_batch()
                    consecutive_errors = 0
                    
                    sleep_time = max(10, min(PREFETCH_INTERVAL // 2, duration * 2))
                else:
                    sleep_time = 30
                
                logger.info(f"Prefetch worker sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
                
            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Error in prefetch worker (consecutive errors: {consecutive_errors}): {e}")
                
                sleep_time = min(PREFETCH_INTERVAL, PREFETCH_RETRY_DELAY * (2 ** (consecutive_errors - 1)))
                logger.info(f"Prefetch worker backing off for {sleep_time}s after error")
                time.sleep(sleep_time)
    
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

@app.route('/stats')
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
            
            popular_subreddits = sorted(
                subreddit_access_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            error_subreddits = {
                sub: count for sub, count in subreddit_error_count.items() 
                if count > 0
            }
            
            prefetch_distribution = {
                sub: len(posts) for sub, posts in prefetched_images.items()
                if posts
            }
        
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
                "prefetch_age_seconds": prefetch_age,
                "prefetch_distribution": prefetch_distribution,
                "prefetch_config": {
                    "batch_size": PREFETCH_BATCH_SIZE,
                    "interval": PREFETCH_INTERVAL,
                    "min_images_per_subreddit": MIN_IMAGES_PER_SUBREDDIT
                }
            },
            "subreddits": {
                "total": len(cat_subreddits),
                "popular": dict(popular_subreddits),
                "errors": error_subreddits
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
        
        subreddit_access_count[subreddit_to_use] = subreddit_access_count.get(subreddit_to_use, 0) + 1
        last_access_time[subreddit_to_use] = time.time()
        
        origin = request.headers.get('Origin')
        is_allowed_origin = origin and allowed_origins and origin in origins
        
        image_posts = []
        with prefetch_lock:
            if subreddit_to_use in prefetched_images and prefetched_images[subreddit_to_use]:
                image_posts = prefetched_images[subreddit_to_use]
                
                if image_posts and (requested_subreddit or is_allowed_origin):
                    random_post = random.choice(image_posts)
                    prefetched_images[subreddit_to_use].remove(random_post)
                    
                    if len(prefetched_images[subreddit_to_use]) < MIN_IMAGES_PER_SUBREDDIT:
                        logger.info(f"Running low on prefetched images for r/{subreddit_to_use}: {len(prefetched_images[subreddit_to_use])} remaining")
                    
                    return format_cat_response(random_post, start_time)
        
        if not image_posts:
            logger.info(f"No prefetched images for {subreddit_to_use}, fetching directly")
            image_posts = fetch_safe_cat_images_from_subreddit(subreddit_to_use)
        
        max_attempts = 3
        for attempt in range(max_attempts):
            if not image_posts:
                logger.warning(f"No images found in r/{subreddit_to_use}, trying another subreddit (attempt {attempt+1}/{max_attempts})")
                
                if not requested_subreddit:
                    with prefetch_lock:
                        available_subs = [s for s in prefetched_images.keys() 
                                         if prefetched_images[s] and s != subreddit_to_use]
                    
                    if available_subs:
                        subreddit_to_use = random.choice(available_subs)
                        logger.info(f"Selected alternative subreddit with prefetched images: r/{subreddit_to_use}")
                    else:
                        subreddit_to_use = random.choice([s for s in cat_subreddits if s != subreddit_to_use])
                    
                    subreddit_access_count[subreddit_to_use] = subreddit_access_count.get(subreddit_to_use, 0) + 1
                    last_access_time[subreddit_to_use] = time.time()
                    
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
        
        if subreddit_to_use not in prefetched_images:
            with prefetch_lock:
                prefetched_images[subreddit_to_use] = []
                
                other_posts = [p for p in image_posts if p.id != random_post.id]
                prefetched_images[subreddit_to_use].extend(other_posts[:MIN_IMAGES_PER_SUBREDDIT])
                
                if other_posts:
                    logger.info(f"Added {len(other_posts[:MIN_IMAGES_PER_SUBREDDIT])} directly fetched images to prefetch cache for r/{subreddit_to_use}")
        
        elif is_allowed_origin and random_post in prefetched_images[subreddit_to_use]:
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
