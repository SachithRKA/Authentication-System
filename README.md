# Authentication-System

This project provides a comprehensive User Authentication System with support for both traditional login/register and OAuth login/registration. It's designed to ensure secure and seamless user experiences.

## Key Features

* **Traditional Login/Register**: Users can easily create an account and log in using their email and password.
* **OAuth Login/Registration**: Supports third-party OAuth providers for a quicker and easier login/registration process.
* **Session Management**: After successful login or registration, a secure cookie is stored in the user's browser, enabling the system to recognize the user across sessions. This allows them to navigate to the main page without needing to log in again for up to 7 days. The cookie is secure and httpOnly, protecting against cross-site scripting (XSS) attacks. It also includes a 'SameSite' attribute to prevent cross-site request forgery (CSRF) attacks.
* **Database Integration**: User data, including emails and passwords, is securely stored in a PostgreSQL database.
* **Data Security**: Uses bcrypt for password hashing, ensuring secure storage and comparison of user passwords. Bcrypt uses multiple salt rounds to further enhance data security.

## Getting Started

To start using this Authentication System, follow these steps:

### Prerequisites

Before you begin, make sure you have Node.js installed on your machine.

### Installation

1. Clone the repository: `git clone git@github.com:SachithRKA/Authentication-System.git`
2. Navigate to the project directory: `cd Weather-API`
3. Install dependencies: `npm install`

### Running the Application

Start the server:

* If you have nodemon installed, run: `nodemon index.js`
* Otherwise, run: `node index.js`

After starting the server, access the application by opening your web browser and visiting: `http://localhost:3000`.
