from flask import Flask, request, render_template

app = Flask(__name__)

comments = []  # simulate stored XSS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search')
def search():
    q = request.args.get('q', '')
    return render_template('search.html', query=q)

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/comments', methods=['GET', 'POST'])
def comment_page():
    global comments
    if request.method == 'POST':
        user_comment = request.form.get('comment')
        comments.append(user_comment)  # simulate storing input (stored XSS)
    return render_template('comments.html', comments=comments)

if __name__ == '__main__':
    app.run(debug=True)
