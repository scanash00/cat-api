# 🐱 Cat API: Random Cat Image Generator

## Overview
Cat API is a fun, open-source Flask application that fetches and serves random cat images from Reddit, with built-in content moderation.

## Features
- Fetch random cat images from multiple subreddits
- Content moderation using OpenAI's Moderation API
- Rate limiting to prevent abuse
- Background image prefetching
- Simple, easy-to-use REST API

## Prerequisites
- Python 3.8+
- Reddit API Credentials
- OpenAI API Key

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
OPENAI_API_KEY=your_openai_api_key
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

#### Response Example
```json
{
    "title": "Cute kitten sitting on a windowsill",
    "url": "https://i.redd.it/cute-kitten-image.jpg",
    "subreddit": "cats",
    "upvotes": 1245
}
```

#### Possible Error Responses
```json
{
    "error": "No safe cat images found after multiple attempts",
    "status": 404
}
```

### GET /
Health check endpoint. Returns application status.

## CORS Support
The API supports Cross-Origin Resource Sharing (CORS) for all routes. By default, requests from any origin are allowed. 

### CORS Configuration
- All routes support cross-origin requests
- Wildcard `*` is used to allow requests from any domain
- Preflight requests are automatically handled

**Note for Production**: Consider restricting CORS origins in a production environment for enhanced security.

## Contributing
Contributions are welcome! Make sure to follow common sense when contributing, and keeping the code clean.

## License
MIT License

## Disclaimer
Images are sourced from Reddit and moderated for safety. However, content may occasionally slip through moderation.
