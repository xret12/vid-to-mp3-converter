import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL
from dotenv import load_dotenv

load_dotenv()
server = Flask(__name__)
mysql = MySQL(server)

# config
server.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
server.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
server.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
server.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')
server.config['MYSQL_PORT'] = os.environ.get('MYSQL_PORT')


@server.route('/login', methods=['POST'])
def login():
    """
    Handles user login via HTTP POST request.

    Checks for user authorization credentials, verifies them against the database,
    and returns a JWT token upon successful authentication.

    Returns:
        str: A success or error message with a corresponding HTTP status code.
    """
    auth = request.authorization
    if not auth:
        return 'Missing credentials', 401

    # check db for user and password
    cur = mysql.connection.cursor()
    res = cur.execute("SELECT email, password FROM user WHERE email=%s;", (auth.username,))

    if res > 0: 
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return 'Invalid credentials', 401
        else:
            return create_jwt(auth.username, os.environ.get('JWT_SECRET'), True)

    else:
        return 'Invalid credentials', 401
    
@server.route('/validate', methods=['POST'])
def validate():
    """
    Validates a JSON Web Token (JWT) provided in the Authorization header of a POST request.

    This function checks if the Authorization header is present in the request. If it is not present,
    it returns a 'Missing credentials' message with a 401 status code.

    If the Authorization header is present, it extracts the encoded JWT from it and decodes it using
    the secret key stored in the environment variable 'JWT_SECRET'. The decoding is done using the
    'HS256' algorithm. If the decoding is successful, the function returns the decoded JWT and a 200
    status code.

    If the decoding fails, it returns a 'Not authorized' message with a 403 status code.

    Parameters:
        None

    Returns:
        - If the Authorization header is missing:
            - decoded (str): The decoded JWT.
            - status_code (int): 200.
        - If the Authorization header is present:
            - message (str): A message indicating the error.
            - status_code (int): 401 or 403.
    """
    # example: encoded_jwt: "Bearer <long.alphanumeric.string>"
    encoded_jwt = request.headers.get('Authorization')
    if not encoded_jwt:
        return 'Missing credentials', 401
    
    encoded_jwt = encoded_jwt.split(' ')[1]
    try:
        decoded = jwt.decode(encoded_jwt, os.environ.get('JWT_SECRET'), algorithm=['HS256'])
    except:
        return "Not authorized", 403
    
    return decoded, 200


def create_jwt(username, secret, authz):
    """
    Creates a JSON Web Token (JWT) with the provided username, secret, and authorization status.

    Args:
        username (str): The username to be encoded in the JWT.
        secret (str): The secret key used to sign the JWT.
        authz (bool): The authorization status of the user.

    Returns:
        str: The encoded JWT.
    """
    return jwt.encode(
        {
            'username': username,
            'exp': datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
            'iat': datetime.datetime.now(tz=datetime.timezone.utc),
            'admin': authz
        },
        secret,
        algorithm='HS256'
    )


if __name__ == '__main__':
    server.run(host='0.0.0.0', port=5000)