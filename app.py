import os
import boto3
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import uuid
from textblob import TextBlob
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cinemapulse_secret_key_2024')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# Table Names from .env
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME')
MOVIES_TABLE_NAME = os.environ.get('MOVIES_TABLE_NAME')
REVIEWS_TABLE_NAME = os.environ.get('REVIEWS_TABLE_NAME')
FEEDBACK_TABLE_NAME = os.environ.get('FEEDBACK_TABLE_NAME')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
movies_table = dynamodb.Table(MOVIES_TABLE_NAME)
reviews_table = dynamodb.Table(REVIEWS_TABLE_NAME)
feedback_table = dynamodb.Table(FEEDBACK_TABLE_NAME)

# ---------------------------------------
# Utility Functions
# ---------------------------------------
def analyze_sentiment(text):
    """Analyze sentiment of text using TextBlob"""
    blob = TextBlob(text)
    polarity = blob.sentiment.polarity
    
    if polarity > 0.1:
        return 'positive', polarity
    elif polarity < -0.1:
        return 'negative', polarity
    else:
        return 'neutral', polarity

def send_sns_alert(message, subject):
    """Send SNS alert for negative feedback"""
    if ENABLE_SNS and SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=message,
                Subject=subject
            )
            return True
        except Exception as e:
            print(f"SNS Error: {e}")
            return False
    return False

def send_email_notification(to_email, subject, body):
    """Send email notification"""
    if not ENABLE_EMAIL or not SENDER_EMAIL or not SENDER_PASSWORD:
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False

def login_required(f):
    """Decorator for routes that require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator for admin-only routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'admin':
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ---------------------------------------
# Authentication Routes
# ---------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'customer')
        
        if not all([username, email, password]):
            flash('All fields are required')
            return render_template('register.html') if request.form else jsonify({'error': 'All fields required'}), 400
        
        # Check if user already exists
        try:
            response = users_table.get_item(Key={'email': email})
            if 'Item' in response:
                flash('User already exists')
                return render_template('register.html') if request.form else jsonify({'error': 'User exists'}), 409
        except Exception as e:
            flash('Database error')
            return render_template('register.html') if request.form else jsonify({'error': str(e)}), 500
        
        # Create new user
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        
        try:
            users_table.put_item(Item={
                'user_id': user_id,
                'email': email,
                'username': username,
                'password': hashed_password,
                'role': role,
                'created_at': datetime.now().isoformat(),
                'is_active': True
            })
            
            flash('Registration successful')
            if request.form:
                return redirect(url_for('login'))
            else:
                return jsonify({'message': 'User created successfully', 'user_id': user_id}), 201
                
        except Exception as e:
            flash('Registration failed')
            return render_template('register.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            flash('Email and password required')
            return render_template('login.html') if request.form else jsonify({'error': 'Missing credentials'}), 400
        
        try:
            response = users_table.get_item(Key={'email': email})
            if 'Item' not in response:
                flash('Invalid credentials')
                return render_template('login.html') if request.form else jsonify({'error': 'Invalid credentials'}), 401
            
            user = response['Item']
            
            if not user.get('is_active', True):
                flash('Account deactivated')
                return render_template('login.html') if request.form else jsonify({'error': 'Account deactivated'}), 401
            
            if check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['user_role'] = user.get('role', 'customer')
                
                if request.form:
                    return redirect(url_for('dashboard'))
                else:
                    return jsonify({
                        'message': 'Login successful',
                        'user': {
                            'user_id': user['user_id'],
                            'username': user['username'],
                            'email': user['email'],
                            'role': user.get('role', 'customer')
                        }
                    }), 200
            else:
                flash('Invalid credentials')
                return render_template('login.html') if request.form else jsonify({'error': 'Invalid credentials'}), 401
                
        except Exception as e:
            flash('Login failed')
            return render_template('login.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully')
    return redirect(url_for('index'))

# ---------------------------------------
# Dashboard Routes
# ---------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_role = session.get('user_role', 'customer')
    
    if user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('customer_dashboard'))

@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    try:
        # Get recent movies
        movies_response = movies_table.scan(Limit=10)
        movies = movies_response.get('Items', [])
        
        # Get user's recent reviews
        user_reviews_response = reviews_table.query(
            IndexName='UserIndex',
            KeyConditionExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']},
            Limit=5,
            ScanIndexForward=False
        )
        user_reviews = user_reviews_response.get('Items', [])
        
        return render_template('customer_dashboard.html', 
                             movies=movies, 
                             user_reviews=user_reviews)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}')
        return render_template('customer_dashboard.html', movies=[], user_reviews=[])

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        # Get recent reviews with sentiment analysis
        reviews_response = reviews_table.scan(Limit=20)
        reviews = reviews_response.get('Items', [])
        
        # Get feedback stats
        feedback_response = feedback_table.scan()
        feedback_items = feedback_response.get('Items', [])
        
        # Calculate sentiment statistics
        sentiment_stats = {'positive': 0, 'negative': 0, 'neutral': 0}
        for review in reviews:
            sentiment = review.get('sentiment', 'neutral')
            sentiment_stats[sentiment] += 1
        
        # Get negative feedback count
        negative_feedback = [f for f in feedback_items if f.get('sentiment') == 'negative']
        
        return render_template('admin_dashboard.html', 
                             reviews=reviews,
                             sentiment_stats=sentiment_stats,
                             negative_feedback=negative_feedback,
                             total_reviews=len(reviews))
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}')
        return render_template('admin_dashboard.html', 
                             reviews=[], 
                             sentiment_stats={'positive': 0, 'negative': 0, 'neutral': 0},
                             negative_feedback=[],
                             total_reviews=0)

# ---------------------------------------
# Movie Routes
# ---------------------------------------
@app.route('/movies')
@login_required
def movies():
    try:
        response = movies_table.scan()
        movies_list = response.get('Items', [])
        return render_template('movies.html', movies=movies_list)
    except Exception as e:
        flash(f'Error loading movies: {str(e)}')
        return render_template('movies.html', movies=[])

@app.route('/admin/movies/add', methods=['GET', 'POST'])
@admin_required
def add_movie():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        title = data.get('title')
        genre = data.get('genre')
        director = data.get('director')
        release_date = data.get('release_date')
        description = data.get('description', '')
        
        if not all([title, genre, director, release_date]):
            flash('All required fields must be filled')
            return render_template('add_movie.html') if request.form else jsonify({'error': 'Missing required fields'}), 400
        
        movie_id = str(uuid.uuid4())
        
        try:
            movies_table.put_item(Item={
                'movie_id': movie_id,
                'title': title,
                'genre': genre,
                'director': director,
                'release_date': release_date,
                'description': description,
                'created_at': datetime.now().isoformat(),
                'created_by': session['user_id']
            })
            
            flash('Movie added successfully')
            if request.form:
                return redirect(url_for('movies'))
            else:
                return jsonify({'message': 'Movie added successfully', 'movie_id': movie_id}), 201
                
        except Exception as e:
            flash('Failed to add movie')
            return render_template('add_movie.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('add_movie.html')

# ---------------------------------------
# Review Routes
# ---------------------------------------
@app.route('/movie/<movie_id>/review', methods=['GET', 'POST'])
@login_required
def add_review(movie_id):
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        rating = data.get('rating')
        comment = data.get('comment', '')
        
        if not rating:
            flash('Rating is required')
            return render_template('add_review.html', movie_id=movie_id) if request.form else jsonify({'error': 'Rating required'}), 400
        
        # Analyze sentiment
        sentiment, sentiment_score = analyze_sentiment(comment) if comment else ('neutral', 0)
        
        review_id = str(uuid.uuid4())
        
        try:
            # Add review to database
            reviews_table.put_item(Item={
                'review_id': review_id,
                'movie_id': movie_id,
                'user_id': session['user_id'],
                'username': session['username'],
                'rating': int(rating),
                'comment': comment,
                'sentiment': sentiment,
                'sentiment_score': float(sentiment_score),
                'created_at': datetime.now().isoformat()
            })
            
            # Send alert for negative reviews
            if sentiment == 'negative' and sentiment_score < -0.5:
                alert_message = f"Negative review detected!\nMovie ID: {movie_id}\nUser: {session['username']}\nRating: {rating}/5\nComment: {comment[:100]}..."
                send_sns_alert(alert_message, "Negative Movie Review Alert")
            
            flash('Review added successfully')
            if request.form:
                return redirect(url_for('movies'))
            else:
                return jsonify({'message': 'Review added successfully', 'review_id': review_id}), 201
                
        except Exception as e:
            flash('Failed to add review')
            return render_template('add_review.html', movie_id=movie_id) if request.form else jsonify({'error': str(e)}), 500
    
    # Get movie details
    try:
        movie_response = movies_table.get_item(Key={'movie_id': movie_id})
        movie = movie_response.get('Item')
        if not movie:
            flash('Movie not found')
            return redirect(url_for('movies'))
    except Exception as e:
        flash('Error loading movie')
        return redirect(url_for('movies'))
    
    return render_template('add_review.html', movie=movie)

@app.route('/movie/<movie_id>/reviews')
@login_required
def movie_reviews(movie_id):
    try:
        # Get movie details
        movie_response = movies_table.get_item(Key={'movie_id': movie_id})
        movie = movie_response.get('Item')
        
        # Get reviews for this movie
        reviews_response = reviews_table.query(
            IndexName='MovieIndex',
            KeyConditionExpression='movie_id = :movie_id',
            ExpressionAttributeValues={':movie_id': movie_id},
            ScanIndexForward=False
        )
        reviews = reviews_response.get('Items', [])
        
        return render_template('movie_reviews.html', movie=movie, reviews=reviews)
    except Exception as e:
        flash(f'Error loading reviews: {str(e)}')
        return redirect(url_for('movies'))

# ---------------------------------------
# Feedback Routes
# ---------------------------------------
@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        feedback_type = data.get('feedback_type', 'general')
        subject = data.get('subject')
        message = data.get('message')
        
        if not all([subject, message]):
            flash('Subject and message are required')
            return render_template('feedback.html') if request.form else jsonify({'error': 'Missing required fields'}), 400
        
        # Analyze sentiment
        sentiment, sentiment_score = analyze_sentiment(message)
        
        feedback_id = str(uuid.uuid4())
        
        try:
            # Add feedback to database
            feedback_table.put_item(Item={
                'feedback_id': feedback_id,
                'user_id': session['user_id'],
                'username': session['username'],
                'feedback_type': feedback_type,
                'subject': subject,
                'message': message,
                'sentiment': sentiment,
                'sentiment_score': float(sentiment_score),
                'status': 'open',
                'created_at': datetime.now().isoformat()
            })
            
            # Send alert for negative feedback
            if sentiment == 'negative':
                alert_message = f"Negative feedback received!\nType: {feedback_type}\nUser: {session['username']}\nSubject: {subject}\nMessage: {message[:100]}..."
                send_sns_alert(alert_message, "Negative Customer Feedback Alert")
            
            flash('Feedback submitted successfully')
            if request.form:
                return redirect(url_for('dashboard'))
            else:
                return jsonify({'message': 'Feedback submitted successfully', 'feedback_id': feedback_id}), 201
                
        except Exception as e:
            flash('Failed to submit feedback')
            return render_template('feedback.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('feedback.html')

# ---------------------------------------
# API Routes for Real-time Data
# ---------------------------------------
@app.route('/api/sentiment-stats')
@admin_required
def api_sentiment_stats():
    try:
        # Get recent reviews (last 30 days)
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        
        response = reviews_table.scan(
            FilterExpression='created_at > :date',
            ExpressionAttributeValues={':date': thirty_days_ago}
        )
        reviews = response.get('Items', [])
        
        sentiment_stats = {'positive': 0, 'negative': 0, 'neutral': 0}
        for review in reviews:
            sentiment = review.get('sentiment', 'neutral')
            sentiment_stats[sentiment] += 1
        
        return jsonify(sentiment_stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-feedback')
@admin_required
def api_recent_feedback():
    try:
        response = feedback_table.scan(Limit=10)
        feedback_items = response.get('Items', [])
        
        # Sort by created_at descending
        feedback_items.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify(feedback_items)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reviews/recent')
@login_required
def api_recent_reviews():
    try:
        response = reviews_table.scan(Limit=20)
        reviews = response.get('Items', [])
        
        # Sort by created_at descending
        reviews.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify(reviews)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

# ---------------------------------------
# Main
# ---------------------------------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)