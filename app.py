from functools import wraps
import os
import re
import fitz  # PyMuPDF for working with PDFs
from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from google.cloud import translate_v2 as translate
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from textwrap import wrap
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['TRANSLATED_FOLDER'] = 'translated/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = '5f412b31c89bcacd5112c2a50b1e9f67'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
load_dotenv()

# Set the admin email for login (or use an environment variable)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH") 

# User model for database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

with app.app_context():
    db.create_all()
    
# Admin-only access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session or session['email'] != ADMIN_EMAIL:
            flash("Access restricted to admin users only.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
    
# Helper function to validate password strength
def validate_password(password):
    if (len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[\W_]', password)):  # \W for special characters, _ for underscores
        return True
    return False

# Set up Google Cloud credentials
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.environ.get("GOOGLE_CREDENTIALS_PATH")

# Initialize the Google Translate client
def create_translate_client():
    return translate.Client()

# Clean text to remove unwanted artifacts
def clean_text(text):
    return text.replace('\n', ' ').replace('\r', ' ').strip()

# Extract text with positions to retain original formatting and layout
def extract_text_with_positions(pdf_path):
    doc = fitz.open(pdf_path)
    text_blocks = []
    for page_num in range(doc.page_count):
        page = doc.load_page(page_num)
        blocks = page.get_text("blocks")  # Extract text blocks with position info
        page_blocks = []
        for block in blocks:
            bbox = block[:4]  # Extract bounding box coordinates
            block_text = clean_text(block[4])
            if block_text:  # Avoid empty blocks
                page_blocks.append((bbox, block_text))
        text_blocks.append(page_blocks)
    doc.close()
    return text_blocks

# Translate text using Google Translate API
def translate_text_google(translate_client, text, target_lang):
    try:
        translation = translate_client.translate(text, target_language=target_lang)
        return translation['translatedText']
    except Exception as e:
        print(f"Error during translation: {e}")
        return text  # Fallback to original text if translation fails

# Register a Devanagari font for proper rendering of Marathi/Hindi text
pdfmetrics.registerFont(TTFont('NotoSansDevanagari', 'E:/project/OneDrive/Documents/Noto_Sans_Devanagari/NotoSansDevanagari-VariableFont_wdth,wght.ttf'))

# Create a new PDF with translated text while preserving original layout
def create_translated_pdf_with_layout(translate_client, text_blocks, output_path, target_lang):
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    for page_num, blocks in enumerate(text_blocks):
        for bbox, block_text in blocks:
            x0, y0, x1, y1 = bbox  # Extract block's coordinates
            block_width = max(x1 - x0, 50)
            y0_adjusted = height - y0  # Adjust to canvas coordinates
            
            # Translate block text
            translated_text = translate_text_google(translate_client, block_text, target_lang)
            
            # Dynamic font and line adjustments based on block dimensions
            font_size = 8
            line_height = 12
            wrap_width = max(10, int(block_width / (font_size * 0.4)))
            translated_lines = wrap(translated_text, width=wrap_width)
            
            # Start drawing translated text at the top-left corner of the block
            text_obj = c.beginText(x0, y0_adjusted)
            text_obj.setFont("NotoSansDevanagari", font_size)
            for line in translated_lines:
                text_obj.textLine(line)
                y0_adjusted -= line_height
                if y0_adjusted < 0:  # Move to next page if out of space
                    c.drawText(text_obj)
                    c.showPage()
                    text_obj = c.beginText(x0, height - y0)  # Reset to top of new page
            c.drawText(text_obj)
        c.showPage()
    c.save()

# Authentication routes
# Admin panel route
@app.route('/admin')
@admin_required
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users)

# Delete user route
@app.route('/admin/delete/<int:user_id>', methods=['GET'])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User has been deleted successfully.", "success")
    else:
        flash("User not found.", "danger")
    
    return redirect(url_for('admin'))


# Edit user route
@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get(user_id)
    
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        # Update user details
        user.username = request.form['username']
        user.email = request.form['email']
        
        # Optionally, update password if provided
        password = request.form['password']
        if password:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db.session.commit()
        flash("User has been updated successfully.", "success")
        return redirect(url_for('admin'))
    
    return render_template('edit_user.html', user=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = email.split('@')[0]  # Automatically use email's first part as username

        # Check if email or username already exists
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash("User already exists. Please log in or use a different email.", "danger")
            return redirect(url_for('signup'))

        # Validate password strength
        if not validate_password(password):
            flash("Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.", "danger")
            return redirect(url_for('signup'))

        # Hash the password and add user to the database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash("An error occurred during signup. Please try again.", "danger")
            return redirect(url_for('signup'))
        
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Check for admin credentials
        if email == ADMIN_EMAIL and bcrypt.check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['username'] = 'admin'
            session['email'] = ADMIN_EMAIL
            flash("Admin login successful!", "success")
            return redirect(url_for('admin'))  # Redirect to admin panel

        # Check for regular user credentials
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = user.username
            session['email'] = user.email
            flash("Login successful!", "success")
            return redirect(url_for('index'))  # Regular users redirected to index
    
        flash("Invalid email or password. Please try again.", "danger")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' in session:
        return render_template('pdf-translate.html', username=session['username'])
    return redirect(url_for('login'))

# PDF translation route
@app.route('/pdf-translate', methods=['POST'])
def handle_pdf_translation():
    if request.method == 'POST':
        if 'username' not in session:
            return redirect(url_for('login'))
        
        pdf_file = request.files['pdf_file']
        target_lang = request.form['target_lang']
        if not pdf_file or not pdf_file.filename.endswith('.pdf'):
            return "Invalid file type. Please upload a PDF."
        
        input_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename)
        pdf_file.save(input_pdf_path)
        translate_client = create_translate_client()
        
        # Extract text with positions from the uploaded PDF
        text_blocks = extract_text_with_positions(input_pdf_path)
        
        # Create the translated PDF while preserving layout
        output_pdf_path = os.path.join(app.config['TRANSLATED_FOLDER'], f"translated_{pdf_file.filename}")
        create_translated_pdf_with_layout(translate_client, text_blocks, output_pdf_path, target_lang)
        
        # Send the translated PDF as a download to the user
        return send_file(output_pdf_path, as_attachment=True)
    
    return render_template('pdf-translate.html')

if __name__ == '__main__':
    app.run(debug=True)
