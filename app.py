from flask import Flask, request, session, render_template_string




app = Flask(__name__)
app.secret_key = "your-secret-key"




def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

@app.before_request
def assign_ip_as_username():
    if "username" not in session:
        session["username"] = get_client_ip()
   




#navigation 
@app.route("/")
def home():
    username = session.get("username", "Unknown")
    return render_template_string("""
        <h1>Welcome!</h1>
        <p>Your login name (IP): {{ username }}</p>
    """, username=username)





#is this needed?
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message":"Hello from Flask API!"})





#Deploy
if __name__ == "__main__":
    #Listen on all interfaces, port 5000
    app.run(host="0.0.0.0", port=5000)

