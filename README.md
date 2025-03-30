# Phishing Detector Backend

## Overview
The **Phishing Detector Backend** is a Flask-based API that powers the **Cybersecurity Awareness & Phishing Detection Platform**. It enables users to analyze URLs for phishing threats, store scan history, and manage user authentication securely.

## Features
 **Phishing Link Scanner** – Detects phishing URLs using the Google Safe Browsing API.  
 **Scan History Storage** – Saves analyzed URLs and their results in the database.  
 **User Authentication** – Implements JWT-based secure login and signup.  
 **RESTful API** – Provides endpoints for seamless frontend integration.  

## Tech Stack
- **Backend Framework:** Flask (Python)
- **Database:** MySQL
- **Authentication:** JWT (JSON Web Token)
- **APIs Used:** Google Safe Browsing API
- **Deployment:** Flask server (Local & Cloud hosting supported)

## Setup Instructions
### Prerequisites
- Python 3.x installed
- MySQL Database setup
- API Key for Google Safe Browsing

### Installation
```bash
# Clone the repository
git clone https://github.com/your-username/phishing-detector-backend.git

# Navigate to the backend directory
cd phishing-detector-backend

# Create a virtual environment
python -m venv venv
source venv/bin/activate   # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export FLASK_APP=app.py
export GOOGLE_API_KEY=your-google-api-key
export DATABASE_URL=mysql://user:password@localhost/phishing_db

# Run the Flask server
flask run
```

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan-url` | Submits a URL for phishing detection |
| GET | `/scan-history` | Retrieves user's past scan history |
| POST | `/signup` | Registers a new user |
| POST | `/login` | Authenticates user and returns JWT |

## Deployment
- Can be deployed on **Heroku, AWS, or any cloud provider**.
- Ensure **CORS is enabled** for frontend communication.

## Contributing
We welcome contributions! Feel free to submit issues or pull requests.

## License
This project is licensed under the **MIT License**.

## Contact
For any queries, reach out to [omvashishtha3@gmail.com](mailto:omvashishtha3@gmail.com).
