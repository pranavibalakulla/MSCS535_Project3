"""
Secure Hotel and Travel Booking Payment System
Demonstrates protection against SQL Injection and Cross-Site Scripting (XSS)

Course Project: Secure Software Design (Chapters 9-12)
"""

import sqlite3
import html
import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, abort

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATABASE = 'hotel_booking.db'


# ============================================================
# DATABASE SETUP
# ============================================================

def get_db_connection():
    """Create and return a database connection with Row factory"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS guests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guest_id INTEGER NOT NULL,
            hotel_name TEXT NOT NULL,
            destination TEXT NOT NULL,
            check_in DATE NOT NULL,
            check_out DATE NOT NULL,
            room_type TEXT NOT NULL,
            num_guests INTEGER NOT NULL,
            total_amount REAL NOT NULL,
            payment_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guest_id) REFERENCES guests (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            booking_id INTEGER NOT NULL,
            cardholder_name TEXT NOT NULL,
            card_last4 TEXT NOT NULL,
            amount REAL NOT NULL,
            transaction_status TEXT DEFAULT 'pending',
            transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (booking_id) REFERENCES bookings (id)
        )
    ''')

    conn.commit()
    conn.close()


# ============================================================
# SQL INJECTION PREVENTION: PARAMETERIZED QUERIES
# ============================================================

def save_guest(name, email, phone):
    """
    Save guest information using parameterized queries.

    SECURITY NOTE:
      VULNERABLE (DO NOT USE):
        query = "INSERT INTO guests VALUES ('" + name + "', '" + email + "')"
        If name = "'; DROP TABLE guests; --", the table would be deleted.

      SECURE (THIS IMPLEMENTATION):
        cursor.execute("INSERT INTO guests VALUES (?, ?, ?)", (name, email, phone))
        The ? placeholder tells the database driver to treat all values as DATA,
        never as SQL code, regardless of what characters they contain.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # SECURE: Each ? is a parameter placeholder bound to its corresponding value
    cursor.execute(
        "INSERT INTO guests (name, email, phone) VALUES (?, ?, ?)",
        (name, email, phone)
    )
    guest_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return guest_id


def save_booking(guest_id, hotel_name, destination, check_in,
                 check_out, room_type, num_guests, amount):
    """
    Save a hotel booking using parameterized queries.
    All eight values are bound as parameters; none are concatenated into the SQL string.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # SECURE: Multi-value parameterized INSERT
    cursor.execute(
        """INSERT INTO bookings
           (guest_id, hotel_name, destination, check_in,
            check_out, room_type, num_guests, total_amount)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (guest_id, hotel_name, destination, check_in,
         check_out, room_type, num_guests, amount)
    )
    booking_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return booking_id


def get_booking(booking_id):
    """
    Retrieve booking by ID using a parameterized query.

    SECURITY NOTE:
      Even if booking_id = "1 OR 1=1" (a classic injection attempt),
      the database driver treats it as a literal string value, not SQL syntax.
      The query will simply find no matching record rather than returning all records.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # SECURE: booking_id treated as data, never as SQL
    cursor.execute("SELECT * FROM bookings WHERE id = ?", (booking_id,))
    booking = cursor.fetchone()
    conn.close()
    return booking


def search_bookings(search_term):
    """
    Search bookings using a parameterized LIKE query.

    SECURITY NOTE:
      VULNERABLE (DO NOT USE):
        query = "SELECT * FROM bookings WHERE destination LIKE '%" + search_term + "%'"

      SECURE (THIS IMPLEMENTATION):
        The % wildcards are added to the Python string BEFORE parameterization.
        The full pattern is then bound as a single parameter value.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Build the LIKE pattern in Python, then pass it as a parameter
    safe_pattern = f"%{search_term}%"
    # SECURE: Parameterized LIKE query
    cursor.execute(
        "SELECT * FROM bookings WHERE destination LIKE ? ORDER BY created_at DESC",
        (safe_pattern,)
    )
    results = cursor.fetchall()
    conn.close()
    return results


def process_payment(booking_id, cardholder_name, card_last4, amount):
    """
    Record payment using parameterized queries.
    Only the last 4 card digits are stored (PCI DSS best practice).
    Both the INSERT and UPDATE use separate parameterized statements.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # SECURE: Parameterized INSERT for payment record
    cursor.execute(
        """INSERT INTO payments
           (booking_id, cardholder_name, card_last4, amount, transaction_status)
           VALUES (?, ?, ?, ?, ?)""",
        (booking_id, cardholder_name, card_last4, amount, 'completed')
    )
    # SECURE: Parameterized UPDATE for booking status
    cursor.execute(
        "UPDATE bookings SET payment_status = ? WHERE id = ?",
        ('paid', booking_id)
    )
    conn.commit()
    conn.close()


# ============================================================
# XSS PREVENTION: INPUT SANITIZATION AND OUTPUT ENCODING
# ============================================================

def sanitize_input(value):
    """
    Sanitize user input by HTML-encoding all special characters.

    Python's html.escape() converts dangerous characters into safe HTML entities:
      <  becomes  &lt;
      >  becomes  &gt;
      &  becomes  &amp;
      "  becomes  &quot;
      '  becomes  &#x27;

    Example attack that is neutralized:
      Input:  <script>document.cookie='stolen='+document.cookie</script>
      Output: &lt;script&gt;document.cookie=&#x27;stolen=&#x27;+document.cookie&lt;/script&gt;

    The browser displays the encoded text as literal characters rather than
    executing it as HTML or JavaScript code.
    """
    if value is None:
        return ""
    # html.escape with quote=True also encodes quote characters
    return html.escape(str(value).strip(), quote=True)


def validate_card_number(card_number):
    """Validate card number: must contain exactly 16 digits after removing spaces"""
    digits_only = card_number.replace(" ", "")
    return digits_only.isdigit() and len(digits_only) == 16


def validate_expiry(expiry):
    """Validate expiry date: must be in MM/YY format with a valid month"""
    if len(expiry) != 5 or expiry[2] != '/':
        return False
    month, year = expiry[:2], expiry[3:]
    return month.isdigit() and year.isdigit() and 1 <= int(month) <= 12


def validate_cvv(cvv):
    """Validate CVV: must be 3 or 4 digits only"""
    return cvv.isdigit() and len(cvv) in [3, 4]


def validate_email(email):
    """Validate email: must contain @ and a domain with a dot"""
    return '@' in email and '.' in email.split('@')[-1]


def validate_payment_form(data):
    """
    Validate all payment form fields.
    Returns a list of error messages; an empty list indicates all fields are valid.
    """
    errors = []
    if not data.get('cardholder_name', '').strip():
        errors.append("Cardholder name is required")
    if not validate_card_number(data.get('card_number', '')):
        errors.append("Card number must be 16 digits")
    if not validate_expiry(data.get('expiry', '')):
        errors.append("Expiry date must be in MM/YY format")
    if not validate_cvv(data.get('cvv', '')):
        errors.append("CVV must be 3 or 4 digits")
    return errors


# ============================================================
# CSRF TOKEN MANAGEMENT
# ============================================================

def generate_csrf_token():
    """Generate a cryptographically secure CSRF token and store it in the session"""
    token = secrets.token_hex(32)
    session['csrf_token'] = token
    return token


def validate_csrf_token(form_token):
    """
    Validate the CSRF token submitted in the form against the session token.
    Uses secrets.compare_digest to prevent timing-based attacks.
    """
    session_token = session.get('csrf_token')
    if not session_token or not form_token:
        return False
    return secrets.compare_digest(session_token, form_token)


# ============================================================
# XSS PREVENTION: SECURITY HEADERS (applied to every response)
# ============================================================

@app.after_request
def set_security_headers(response):
    """
    Attach HTTP security headers to every response.

    Content-Security-Policy (CSP):
      Restricts which origins can serve scripts, styles, and other resources.
      This is the primary defense against XSS because even if an attacker
      injects a <script> tag, CSP blocks the browser from executing it
      unless the source is explicitly whitelisted.

      default-src 'self'   Only allow resources from the same origin
      script-src 'self'    Block all inline scripts and external script sources
      frame-ancestors 'none'  Prevent the page from being embedded (clickjacking)

    X-XSS-Protection:
      Activates the built-in XSS filter in older browsers.

    X-Content-Type-Options:
      Prevents MIME type sniffing, which attackers use to treat non-script
      files as executable scripts.

    X-Frame-Options:
      Prevents the application from being embedded in an iframe.
    """
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    """Home page with CSRF token initialization"""
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)


@app.route('/booking', methods=['GET', 'POST'])
def booking():
    """
    Booking form route.
    Demonstrates XSS prevention on form submission and SQL injection
    prevention when saving to the database.
    """
    if request.method == 'POST':
        # Step 1: Validate CSRF token to prevent cross-site request forgery
        if not validate_csrf_token(request.form.get('csrf_token')):
            abort(403)

        # Step 2: XSS Prevention - sanitize ALL form inputs before use
        name = sanitize_input(request.form.get('name', ''))
        email = sanitize_input(request.form.get('email', ''))
        phone = sanitize_input(request.form.get('phone', ''))
        hotel_name = sanitize_input(request.form.get('hotel_name', ''))
        destination = sanitize_input(request.form.get('destination', ''))
        check_in = sanitize_input(request.form.get('check_in', ''))
        check_out = sanitize_input(request.form.get('check_out', ''))
        room_type = sanitize_input(request.form.get('room_type', ''))
        num_guests_raw = sanitize_input(request.form.get('num_guests', '1'))

        # Step 3: Validate business logic
        if not validate_email(email):
            return render_template('booking.html',
                                   error="Please enter a valid email address",
                                   csrf_token=generate_csrf_token())
        try:
            num_guests = int(num_guests_raw)
            if num_guests < 1 or num_guests > 10:
                raise ValueError
        except ValueError:
            return render_template('booking.html',
                                   error="Number of guests must be between 1 and 10",
                                   csrf_token=generate_csrf_token())

        room_prices = {
            'standard': 150, 'deluxe': 250,
            'suite': 450, 'presidential': 800
        }
        price_per_night = room_prices.get(room_type, 150)

        # Step 4: SQL Injection Prevention - save using parameterized queries
        guest_id = save_guest(name, email, phone)
        booking_id = save_booking(
            guest_id, hotel_name, destination,
            check_in, check_out, room_type, num_guests, price_per_night
        )

        session['booking_id'] = booking_id
        session['booking_amount'] = price_per_night
        return redirect(url_for('payment'))

    return render_template('booking.html', csrf_token=generate_csrf_token())


@app.route('/payment', methods=['GET', 'POST'])
def payment():
    """
    Payment form route.
    Core demonstration of both SQL injection and XSS prevention techniques.
    """
    booking_id = session.get('booking_id')
    if not booking_id:
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Step 1: Validate CSRF token
        if not validate_csrf_token(request.form.get('csrf_token')):
            abort(403)

        # Step 2: XSS Prevention - sanitize all payment inputs
        cardholder_name = sanitize_input(request.form.get('cardholder_name', ''))
        card_number = sanitize_input(request.form.get('card_number', ''))
        expiry = sanitize_input(request.form.get('expiry', ''))
        cvv = sanitize_input(request.form.get('cvv', ''))

        # Step 3: Validate sanitized inputs
        errors = validate_payment_form({
            'cardholder_name': cardholder_name,
            'card_number': card_number,
            'expiry': expiry,
            'cvv': cvv
        })

        if errors:
            booking = get_booking(booking_id)
            return render_template('payment.html',
                                   booking=booking,
                                   errors=errors,
                                   csrf_token=generate_csrf_token())

        # Step 4: PCI DSS - store only the last 4 digits of the card number
        card_digits = card_number.replace(" ", "")
        card_last4 = card_digits[-4:]

        amount = session.get('booking_amount', 0)

        # Step 5: SQL Injection Prevention - process payment with parameterized queries
        process_payment(booking_id, cardholder_name, card_last4, amount)

        return redirect(url_for('success'))

    # SQL Injection Prevention - retrieve booking with parameterized query
    booking = get_booking(booking_id)
    return render_template('payment.html',
                           booking=booking,
                           csrf_token=generate_csrf_token())


@app.route('/success')
def success():
    """Confirmation page after successful payment"""
    booking_id = session.get('booking_id')
    if not booking_id:
        return redirect(url_for('index'))
    booking = get_booking(booking_id)
    return render_template('success.html', booking=booking, booking_id=booking_id)


@app.route('/search')
def search():
    """
    Destination search route.
    Demonstrates SQL injection prevention in search queries and
    XSS prevention when rendering the search term back to the user.
    """
    search_term = request.args.get('q', '')

    # XSS Prevention - sanitize the search term before any use
    safe_term = sanitize_input(search_term)

    # SQL Injection Prevention - parameterized LIKE query
    results = search_bookings(safe_term) if safe_term else []

    return render_template('search.html', results=results, search_term=safe_term)


if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("Hotel Payment Security Demo")
    print("Running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True)
