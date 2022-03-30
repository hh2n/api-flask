from flask import Flask, jsonify, render_template, request, make_response
from flask_mysqldb import MySQL
from flask_cors import CORS, cross_origin
from bcrypt import checkpw
import uuid 
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
cors =CORS(app)
#bcrypt = Bcrypt(app)
app.config['SECRET_KEY']='1w4une&ww7cppb1-d7hhd^liw5_965hsi8fs4ebzw+6=g'
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'ISSTECH_Portal'

mysql = MySQL(app)
   
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            current_user = getUserId(data['public_id'])
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated


def getUser(params):
    password = params.password
    cur = mysql.connection.cursor()
    cur.execute("SELECT Pk_User, Fk_PadronMaestro, Rfc_User, Num_Cel, Email, Activo, Password_User FROM Tbl_Users WHERE Email = '" + str(params.username)+"'")
    user = cur.fetchone()
    padron = user[1]
    hashPassword = user[6]
    if checkpw(password.encode('utf-8'), hashPassword.encode('utf-8')):
        token = jwt.encode({'public_id': padron, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
        return jsonify({'token' : token}) 
    return "fail login"

def getUserId(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT Pk_User, Fk_PadronMaestro, Rfc_User, Num_Cel, Email, Activo FROM Tbl_Users WHERE Fk_PadronMaestro = '" + str(id)+"'")
    data = cur.fetchall()
    content = {}
    for row in data:
        content = {
            'ID': row[0],
            'PadronMaestro': row[1],
            'RFC': row[2],
            'Celular': row[3],
            'Email': row[4],
            'Activo': row[5]
        }
    print(content)
    return jsonify(content)


@app.route('/api/login', methods=['POST'])
def login_user(): 
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(
            'could not verify', 401, { 'WWW.Authentication': 'Basic realm: "login required"' }
        )
    return getUser(auth)


@app.route('/api/authors', methods=['POST', 'GET'])
@token_required
def get_authors(current_user):
    print('OK')
    print(type(current_user))
    print(current_user)
    
    """ authors = Authors.query.filter_by(user_id=current_user.id).all()
    output = []
    for author in authors:
        author_data = {}
        author_data['name'] = author.name
        author_data['book'] = author.book
        author_data['country'] = author.country
        author_data['booker_prize'] = author.booker_prize
        output.append(author_data) """
    return jsonify({'list_of_authors' : "Mensaje"})

@app.route('/')
def index():
    return render_template('notFound.html')


if  __name__ == '__main__':  
     app.run(None,3000,debug=True)
