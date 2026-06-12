# Secure Hotel and Travel Booking Payment System

## Project Overview

This application demonstrates secure payment processing for a hotel and travel
booking system. It protects against two major security threats:
  1. SQL Injection using parameterized queries
  2. Cross-Site Scripting (XSS) using input sanitization and security headers

## Setup Instructions

### Step 1: Install Python
Make sure Python 3.8 or higher is installed on your computer.
Download from https://www.python.org

### Step 2: Install Dependencies
Open a terminal (Command Prompt or PowerShell on Windows) in this folder and run:

    pip install -r requirements.txt

### Step 3: Run the Application

    python app.py

### Step 4: Open in Browser
Visit http://127.0.0.1:5000 in your web browser.

## File Structure

    hotel_payment_security/
    |-- app.py               (Main application with all security code)
    |-- requirements.txt     (Python dependencies)
    |-- README.md            (This file)
    |-- templates/
        |-- base.html        (Base layout with security meta tags)
        |-- index.html       (Home page)
        |-- booking.html     (Booking form with CSRF protection)
        |-- payment.html     (Secure payment form)
        |-- success.html     (Booking confirmation page)
        |-- search.html      (Destination search with safe queries)



## How to Test SQL Injection Prevention

In the search box, try typing:
    ' OR '1'='1
    '; DROP TABLE bookings; --

The application will treat these as literal text, not SQL commands.

## How to Test XSS Prevention

In any text input field, try typing:
    <script>alert('XSS Attack')</script>

The application will display these as harmless text strings.
