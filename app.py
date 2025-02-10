import os
import logging
import random
import traceback
import threading
import time
from typing import Dict, Optional

import praw
import openai
import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re

load_dotenv()

log_dir = os.path.join(os.getcwd(), 'logs')
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

openai.api_key = os.getenv('OPENAI_API_KEY')

app = Flask(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[
        "100 per day",  
        "30 per hour", 
        "10 per minute"  
    ],
    storage_uri="memory://",
    strategy="fixed-window"  
)

reddit = praw.Reddit(
    client_id=os.getenv('REDDIT_CLIENT_ID'),
    client_secret=os.getenv('REDDIT_CLIENT_SECRET'),
    user_agent=os.getenv('REDDIT_USER_AGENT')
)

moderation_cache = {}

image_cache = {
    'images': [],
    'last_updated': 0,
    'lock': threading.Lock()
}

CAT_SUBREDDITS = [
    'cats', 'catsstandingup', 'Chonkers', 
    'catpictures', 'blep', 
    'Kitten'
]

def cached_moderate_content(text):
    """
    Cached version of moderate_content to reduce API calls
    """
    if text in moderation_cache:
        return moderation_cache[text]
    
    result = moderate_content(text)
    moderation_cache[text] = result
    return result

def moderate_content(text):
    """
    Use OpenAI's moderation API to check if content is safe
    
    Args:
        text (str): Text to moderate
    
    Returns:
        bool: True if content is safe, False if flagged
    """
    try:
        if not text or not isinstance(text, str):
            return False
        
        response = openai.Moderation.create(input=text)
        moderation = response.results[0]
        
        unsafe_categories = [
            'hate', 'hate/threatening', 
            'harassment', 'harassment/threatening', 
            'violence', 'violence/graphic',
            'sexual', 'sexual/minors',
            'self-harm', 'self-harm/intent', 
            'self-harm/instructions'
        ]
        
        for category in unsafe_categories:
            if getattr(moderation.categories, category, False):
                return False
        
        return True
    
    except Exception as e:
        print(f"Moderation error: {e}")
        return True

def prefetch_cat_images():
    """
    Prefetch and cache one cat image from each subreddit
    """
    all_safe_images = []
    for subreddit_name in CAT_SUBREDDITS:
        try:
            subreddit_images = fetch_safe_cat_images(subreddit_name, limit=1)
            
            if subreddit_images:
                all_safe_images.append(subreddit_images[0])
        except Exception as e:
            print(f"Error fetching image from {subreddit_name}: {e}")
    
    with image_cache['lock']:
        image_cache['images'] = all_safe_images
        image_cache['last_updated'] = time.time()

def fetch_safe_cat_images(subreddit_name, limit=20):
    """
    Fetch safe cat images from a specific subreddit
    
    Args:
        subreddit_name (str): Name of the subreddit
        limit (int): Number of posts to fetch
    
    Returns:
        list: Safe cat image posts
    """
    try:
        subreddit = reddit.subreddit(subreddit_name)
        
        top_posts = list(subreddit.new(limit=limit))
        
        image_posts = [
            post for post in top_posts 
            if (post.url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')) and 
                cached_moderate_content(post.title))
        ]
        
        return image_posts
    
    except Exception as e:
        print(f"Error fetching images from {subreddit_name}: {e}")
        return []

def start_prefetching():
    """
    Start a background thread to periodically prefetch cat images
    """
    def prefetch_loop():
        while True:
            try:
                prefetch_cat_images()
                time.sleep(15 * 60)
            except Exception as e:
                print(f"Prefetch error: {e}")
                time.sleep(5 * 60)
    
    prefetch_thread = threading.Thread(target=prefetch_loop, daemon=True)
    prefetch_thread.start()

start_prefetching()

SSL_BLOCK_PATTERNS = [
    re.compile(rb'\x16\x03'),  
    re.compile(rb'CONNECT'),   
]

@app.before_request
def block_ssl_requests():
    try:
        raw_data = request.get_data(cache=True)
        
        for pattern in SSL_BLOCK_PATTERNS:
            if pattern.search(raw_data):
                logger.warning(f"Blocked potential SSL handshake attempt from {request.remote_addr}")
                abort(400, description="SSL handshake attempts are not allowed")
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        abort(500)

@app.route('/')
@limiter.limit("30 per minute")
def health_check():
    """
    Health check endpoint that returns basic system status.
    Used by Docker health check and monitoring systems.
    """
    try:
        return jsonify({
            "status": "healthy",
            "message": "Cat API is running smoothly!",
            "environment": os.getenv('ENV', 'development'),
            "domain": os.getenv('DOMAIN', 'localhost')
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

@app.route('/random-cat')
@limiter.limit("10 per minute")
def get_random_cat():
    """
    Fetch a random cat picture from a single random subreddit
    
    Returns:
        JSON with cat picture details
    """
    max_attempts = 5  
    
    for attempt in range(max_attempts):
        try:
            subreddit_name = random.choice(CAT_SUBREDDITS)
            
            subreddit = reddit.subreddit(subreddit_name)
            posts = list(subreddit.new(limit=50))
            
            image_posts = [
                post for post in posts 
                if post.url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif'))
            ]
            
            if not image_posts:
                continue
            
            random_post = random.choice(image_posts)
            
            try:
                title_safe = cached_moderate_content(random_post.title)
                
                if not title_safe:
                    continue
                
                response = openai.Moderation.create(
                    input=f"This is an image of a cat from {random_post.title}"
                )
                
                moderation = response.results[0]
                unsafe_categories = [
                    'hate', 'hate/threatening', 
                    'harassment', 'harassment/threatening', 
                    'violence', 'violence/graphic',
                    'sexual', 'sexual/minors',
                    'self-harm', 'self-harm/intent', 
                    'self-harm/instructions'
                ]
                
                is_safe = all(
                    not getattr(moderation.categories, category, False) 
                    for category in unsafe_categories
                )
                
                if is_safe:
                    return jsonify({
                        'title': random_post.title,
                        'url': random_post.url,
                        'subreddit': subreddit_name,
                        'upvotes': random_post.score
                    })
            
            except Exception as moderation_error:
                print(f"Moderation error on attempt {attempt + 1}: {moderation_error}")
                continue
        
        except Exception as e:
            print(f"Error fetching cat image on attempt {attempt + 1}: {e}")
            continue
    
    return jsonify({
        'error': 'No safe cat images found after multiple attempts',
        'status': 404
    }), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    """
    Custom handler for rate limit exceeded
    
    Args:
        e: Error object from rate limiting
    
    Returns:
        JSON response with detailed rate limit error
    """
    retry_after = e.description.split('Retry after ')[1] if 'Retry after' in e.description else 'unknown'
    
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'You have made too many requests. Please wait before trying again.',
        'retry_after': retry_after,
        'status': 429
    }), 429

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
