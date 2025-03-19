# 🐱 Cat API: Random Cat Image Generator

## Overview
Cat API is a fun, open-source Flask application that fetches and serves random cat images from Reddit, with built-in content filtering, security features, and high-performance optimizations.

## Features
- Fetch random cat images from multiple subreddits
- Simple text-based content filtering
- Enhanced security with proper headers and input validation
- Advanced rate limiting to prevent abuse
- Parallel background image prefetching
- Response caching for improved performance
- Response compression for faster delivery
- Connection pooling for optimized network performance
- Thread pool for concurrent operations
- Metrics and monitoring endpoints
- Simple, easy-to-use REST API

## Prerequisites
- Python 3.8+
- Reddit API Credentials
- Redis (optional, for enhanced caching)

## Installation

1. Clone the repository
```bash
git clone https://github.com/scanash00/cat-api.git
cd cat-api
```

2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with the following:
```
REDDIT_CLIENT_ID=your_reddit_client_id
REDDIT_CLIENT_SECRET=your_reddit_client_secret
REDDIT_USER_AGENT=your_user_agent
REDIS_URL=redis://localhost:6379/0  # Optional

# Performance Tuning
THREAD_POOL_SIZE=10  # Number of worker threads for concurrent operations
CACHE_TTL=3600  # Cache time-to-live in seconds
REQUEST_TIMEOUT=5  # Timeout for external requests in seconds
COMPRESSION_THRESHOLD=1024  # Minimum size in bytes for response compression

# Prefetching Configuration
PREFETCH_BATCH_SIZE=5  # Number of subreddits to prefetch in parallel
PREFETCH_INTERVAL=600  # Base interval between prefetch operations in seconds
MIN_IMAGES_PER_SUBREDDIT=5  # Minimum number of images to maintain per subreddit
MAX_PREFETCH_ERRORS=3  # Maximum number of consecutive errors before temporary blacklisting
PREFETCH_RETRY_DELAY=30  # Base delay for retry after prefetch errors

# Security
ALLOWED_ORIGINS=https://example.com,https://anotherdomain.com  # Optional, comma-separated
RATE_LIMIT=60  # Rate limit in requests per minute
LOG_LEVEL=INFO  # Logging level
```

## Running the Application

### Development Mode
```bash
python app.py
```

### Production Mode
```bash
gunicorn -c gunicorn_config.py app:app
```

## API Endpoints

### GET /random-cat
Fetches a random cat image from Reddit.

#### Query Parameters
- `subreddit` (optional): Specify a particular subreddit to fetch from. Must be one of the supported subreddits.

#### Response Example
```json
{
    "title": "Cute kitten sitting on a windowsill",
    "url": "https://i.redd.it/cute-kitten-image.jpg",
    "subreddit": "cats",
    "upvotes": 1245,
    "source": "reddit",
    "response_time_ms": 120
}
```

#### Possible Error Responses
```json
{
    "error": "No safe cat images found after multiple attempts",
    "status": 404
}
```

```json
{
    "error": "Invalid request parameters",
    "details": {"subreddit": ["Invalid value"]},
    "status": 400
}
```

### GET /
Health check endpoint. Returns application status and service health information.

### GET /stats
Public statistics endpoint that provides basic usage metrics and performance information.

#### Response Example
```json
{
    "uptime": 3600,
    "requests": {
        "total": 1500,
        "random_cat": 1200
    },
    "performance": {
        "threads": {
            "active": 3,
            "total": 10,
            "utilization": 30.0
        }
    },
    "cache": {
        "enabled": true,
        "prefetched_images": 45,
        "prefetch_age_seconds": 300,
        "prefetch_distribution": {
            "cats": 12,
            "kittens": 15,
            "CatsStandingUp": 8,
            "catpics": 10
        },
        "prefetch_config": {
            "batch_size": 5,
            "interval": 600,
            "min_images_per_subreddit": 5
        }
    },
    "subreddits": {
        "total": 20,
        "popular": {
            "cats": 156,
            "kittens": 98,
            "catpics": 67,
            "CatsStandingUp": 45,
            "SupermodelCats": 32
        },
        "errors": {
            "CatsBeingCats": 1
        }
    },
    "timestamp": "2025-03-18T20:35:22.123456",
    "response_time_ms": 15
}
```

### GET /metrics
Protected metrics endpoint for monitoring systems (only accessible from localhost or private networks).

## Performance Optimizations

### Connection Pooling
The API uses connection pooling for HTTP requests to improve network performance and reduce connection overhead.

### Parallel Processing
- Thread pool for concurrent operations
- Parallel prefetching of images from multiple subreddits
- Asynchronous health checks

### Caching
The API implements multiple levels of caching:
1. In-memory caching for prefetched images
2. Redis-based response caching (when configured) for API responses
3. Optimized cache key generation for faster lookups

### Response Compression
Responses are automatically compressed using gzip when they exceed a configurable threshold and the client supports compression.

### Adaptive Prefetching
The API implements a smart, adaptive prefetching system:

1. **Smart Subreddit Selection**
   - Prioritizes subreddits with low image counts
   - Favors popular subreddits based on request frequency
   - Includes random subreddits for exploration
   - Temporarily avoids subreddits with repeated errors

2. **Dynamic Scheduling**
   - Adjusts prefetch intervals based on demand and performance
   - Triggers immediate prefetching when popular subreddits run low on images
   - Implements exponential backoff for error recovery

3. **Efficient Image Management**
   - Maintains minimum thresholds of images per subreddit
   - Avoids duplicate images in the prefetch cache
   - Tracks image usage patterns to optimize prefetching

4. **Error Resilience**
   - Tracks error rates by subreddit
   - Implements retry logic with exponential backoff
   - Automatically recovers from temporary API failures

5. **Performance Monitoring**
   - Detailed metrics on prefetch operations
   - Subreddit popularity tracking
   - Error rate monitoring by subreddit

### Request Timeout Management
All external API calls have configurable timeouts to prevent slow operations from blocking the API.

## Content Filtering

The API implements a simple text-based content filtering system to ensure that only appropriate cat images are served:

1. Pattern-based filtering that checks for potentially unsafe words or phrases
2. Filtering applied to post titles to screen out inappropriate content
3. Configurable patterns that can be easily updated or extended

## Security Features

### Input Validation
All API endpoints validate input parameters to prevent injection attacks and ensure proper data formatting.

### Rate Limiting
- 100 requests per day per IP address
- 30 requests per hour per IP address
- 10 requests per minute per IP address

### Security Headers
The API implements the following security headers:
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy

### CORS Support
The API supports Cross-Origin Resource Sharing (CORS) with configurable origins.

#### CORS Configuration
- By default, requests from any origin are allowed
- For production, configure the `ALLOWED_ORIGINS` environment variable to restrict access
- Preflight requests are automatically handled

**Note for Production**: Always restrict CORS origins in a production environment for enhanced security.

## Contributing
Contributions are welcome! Make sure to follow common sense when contributing, and keeping the code clean.

## License
MIT License

## Disclaimer
Images are sourced from Reddit and filtered for safety. However, content may occasionally slip through filtering.
