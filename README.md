# Kendra Backend

The backend service for Kendra, providing API endpoints for authentication, repository management, and AI-powered code analysis using Google Gemini and Cerebras.

## Features

- **Authentication**: GitHub OAuth integration and JWT-based session management.
- **Repository Management**: API for fetching and managing GitHub repositories, issues, and pull requests.
- **AI Analysis**:
  - **Gemini**: Used for high-level code analysis and summaries. Supports multiple API keys for rotation.
  - **Cerebras**: Integrated via Python script for specialized code analysis tasks.
- **Webhooks**: Handling GitHub webhooks for real-time updates.
- **Audit & Stats**: Tracking user activities and system statistics.

## Prerequisites

- **Node.js**: v16 or higher
- **MongoDB**: A running MongoDB instance/cluster
- **Python**: v3.8 or higher (required for Cerebras integration)
- **pip**: Python package installer

## Installation

1.  **Install Node.js dependencies:**
    ```bash
    npm install
    ```

2.  **Install Python dependencies:**
    ```bash
    npm run setup:python
    ```

## Configuration

Create a `.env` file in the root of the `backend` directory with the following variables:

### Server & Database
```env
PORT=4000
NODE_ENV=development
FRONTEND_URL=http://localhost:5173
MONGODB_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/kendra
```

### Authentication (JWT)
```env
JWT_SECRET=your_jwt_strong_secret
```

### GitHub OAuth App
Create a generic OAuth App on GitHub to get these credentials.
```env
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_CALLBACK_URL=/api/auth/github/callback
GITHUB_WEBHOOK_SECRET=your_github_webhook_secret
```

### AI Configuration (Gemini)
You must provide at least one Gemini API key. You can add more for key rotation.
```env
GEMINI_API_KEY=AI...
# Optional additional keys
GEMINI_API_KEY_1=AI...
GEMINI_API_KEY_2=AI...
```

## Running the Server

### Development Mode
Runs the server with `nodemon` for hot-reloading.
```bash
npm run dev
```

### Production Mode
Runs the server in production mode.
```bash
npm start
```

## API Endpoints

-   `/health`: Health check endpoint.
-   `/api/auth`: Authentication routes (GitHub login, logout, user info).
-   `/api/repositories`: Manage and fetch synced repositories.
-   `/api/issues`: Fetch and manage repository issues.
-   `/api/pull-requests`: Fetch and analyze pull requests.
-   `/api/webhooks`: GitHub webhook receiver.
-   `/api/audit`: Retrieve audit logs.
-   `/api/stats`: System and usage statistics.

## Project Structure

-   `src/config`: Configuration and environment variable validation.
-   `src/controllers`: Request handlers for API routes.
-   `src/middleware`: Express middleware (auth, rate limiting, etc.).
-   `src/models`: Mongoose schemas for MongoDB.
-   `src/routes`: API route definitions.
-   `src/services`: Business logic and external API integrations.
-   `src/python`: Python scripts for AI analysis (Cerebras).
